"""Security boundary shared by the case and fleet report renderers.

Report inputs contain attacker-controlled evidence text.  This module keeps that
text inert in Markdown, turns the generated HTML into a self-contained document,
and supplies a network-denied Chromium invocation.  It is deliberately stdlib
only so report rendering does not gain another parser or sanitizer dependency.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import stat
import tempfile
from contextlib import contextmanager
from html import escape
from pathlib import Path, PurePosixPath
from typing import Any, Iterator

MAX_FIGURE_BYTES = 16 * 1024 * 1024
MAX_AUDIT_EMBED_BYTES = 16 * 1024 * 1024
MAX_CASE_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_REPORT_MARKDOWN_BYTES = 64 * 1024 * 1024
MAX_REPORT_HTML_BYTES = 64 * 1024 * 1024
MAX_REPORT_PDF_BYTES = 512 * 1024 * 1024
PANDOC_RENDER_TIMEOUT_SECONDS = 120
CHROMIUM_RENDER_TIMEOUT_SECONDS = 120

REPORT_CSP = (
    "default-src 'none'; base-uri 'none'; connect-src 'none'; child-src 'none'; "
    "font-src data:; form-action 'none'; frame-ancestors 'none'; frame-src 'none'; "
    "img-src data:; manifest-src 'none'; media-src 'none'; object-src 'none'; "
    "script-src 'none'; style-src 'unsafe-inline'; worker-src 'none'; sandbox"
)

_FONT_FILES: tuple[tuple[str, str, int], ...] = (
    ("Inter", "inter-400.woff2", 400),
    ("Inter", "inter-600.woff2", 600),
    ("Archivo", "archivo-600.woff2", 600),
    ("Archivo Narrow", "archivonarrow-700.woff2", 700),
    ("JetBrains Mono", "jetbrainsmono-400.woff2", 400),
    ("JetBrains Mono", "jetbrainsmono-600.woff2", 600),
)

_REMOTE_CSS_RE = re.compile(r"@import\s+(?:url\()?[^;]+;", re.IGNORECASE)
_DANGEROUS_ELEMENT_RE = re.compile(
    r"<(?:base|embed|form|frame|frameset|iframe|link|meta\s+http-equiv\s*=\s*"
    r"[\"']?refresh|object)(?:\s[^>]*)?>.*?</(?:form|frameset|iframe|object)>|"
    r"<(?:base|embed|frame|link|meta\s+http-equiv\s*=\s*[\"']?refresh)(?:\s[^>]*)?/?>",
    re.IGNORECASE | re.DOTALL,
)
_META_TAG_RE = re.compile(r"<meta\b[^>]*>", re.IGNORECASE | re.DOTALL)
_SCRIPT_BLOCK_RE = re.compile(
    r"<script\b[^>]*>.*?</script\s*>", re.IGNORECASE | re.DOTALL
)
_SCRIPT_TAG_RE = re.compile(r"</?script\b[^>]*>", re.IGNORECASE | re.DOTALL)
_TRUSTED_AUDIT_SCRIPT_RE = re.compile(
    r'<script type="application/x-ndjson" id="verdict-embedded-audit-jsonl" '
    r'data-sha256="([0-9a-f]{64})">([A-Za-z0-9+/]*={0,2})</script>'
)
_RESOURCE_ATTR_RE = re.compile(
    r"\s+(?P<name>src|srcset|imagesrcset|href|xlink:href|ping|poster|data|"
    r"action|formaction|background|cite|longdesc|profile|usemap|manifest)\s*=\s*"
    r"(?:(?P<quote>[\"'])(?P<quoted>.*?)(?P=quote)|"
    r"(?P<unquoted>[^\s\"'`=<>]+))",
    re.IGNORECASE | re.DOTALL,
)
_EVENT_HANDLER_ATTR_RE = re.compile(
    r"\s+on[a-z0-9_-]+\s*=\s*(?:([\"']).*?\1|[^\s\"'`=<>]+)",
    re.IGNORECASE | re.DOTALL,
)
_CSS_URL_RE = re.compile(r"url\s*\(\s*([\"']?)(.*?)\1\s*\)", re.IGNORECASE | re.DOTALL)


def markdown_text(value: Any) -> str:
    """Flatten and escape one untrusted value for any Markdown text context.

    Newlines are collapsed before escaping so a value cannot terminate its
    current paragraph/table/code span.  Link, image, attribute, emphasis, math,
    and raw-HTML delimiters are escaped as well.  Callers still own the trusted
    Markdown surrounding the returned value.
    """

    if isinstance(value, (list, tuple, set, frozenset)):
        value = ", ".join(str(item) for item in value)
    text = str(value if value is not None else "")
    text = " ".join(text.replace("\x00", " ").splitlines())
    text = "".join(ch if ch >= " " else " " for ch in text)
    text = escape(text, quote=False)
    # Backslash must be escaped first so the escapes introduced below are not
    # themselves doubled.
    for old, new in (
        ("\\", "\\\\"),
        ("`", "'"),
        ("|", "\\|"),
        ("[", "\\["),
        ("]", "\\]"),
        ("(", "\\("),
        (")", "\\)"),
        ("!", "\\!"),
        ("*", "\\*"),
        ("_", "\\_"),
        ("~", "\\~"),
        ("#", "\\#"),
        ("{", "\\{"),
        ("}", "\\}"),
        ("$", "\\$"),
        ("^", "\\^"),
    ):
        text = text.replace(old, new)
    return re.sub(r"\s+", " ", text).strip()


def markdown_code(value: Any) -> str:
    """Flatten one untrusted value for a surrounding Markdown code span."""
    if isinstance(value, (set, frozenset)):
        value = sorted(str(item) for item in value)
    if isinstance(value, (list, tuple, set, frozenset)):
        value = ", ".join(str(item) for item in value)
    text = str(value if value is not None else "")
    text = " ".join(text.replace("\x00", " ").splitlines())
    text = "".join(ch if ch >= " " else " " for ch in text)
    # A backtick is the only delimiter that can end the surrounding code span.
    # Pipes can split a Pandoc table before inline parsing, so use a visible
    # lookalike rather than a backslash that would itself display in code.
    return re.sub(r"\s+", " ", text.replace("`", "'").replace("|", "¦")).strip()


def load_self_contained_css(style_path: Path) -> str:
    """Load fixed report CSS and inline the repository's vendored WOFF2 fonts."""

    css = _REMOTE_CSS_RE.sub("", style_path.read_text(encoding="utf-8"))
    font_dir = (
        Path(__file__).resolve().parent.parent
        / "services"
        / "agent"
        / "findevil_agent"
        / "attackflow"
        / "_fonts"
    )
    faces: list[str] = []
    for family, filename, weight in _FONT_FILES:
        data = (font_dir / filename).read_bytes()
        encoded = base64.b64encode(data).decode("ascii")
        faces.append(
            "@font-face{"
            f"font-family:'{family}';font-style:normal;font-weight:{weight};"
            "font-display:block;"
            f"src:url(data:font/woff2;base64,{encoded}) format('woff2');"
            "}"
        )
    return "\n".join(faces) + "\n" + css


def read_regular_file_no_follow(path: Path, *, max_bytes: int) -> bytes | None:
    """Read a bounded regular file while refusing a final-component symlink."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > max_bytes
        ):
            return None
        fd = os.open(path, flags | nofollow)
    except (FileNotFoundError, OSError):
        return None
    try:
        current = os.fstat(fd)
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_nlink != 1
            or current.st_size > max_bytes
            or _file_identity(current) != _file_identity(before)
        ):
            return None
        chunks: list[bytes] = []
        remaining = current.st_size
        while remaining:
            chunk = os.read(fd, min(remaining, 1024 * 1024))
            if not chunk:
                return None
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        after_descriptor = os.fstat(fd)
        try:
            after_path = path.lstat()
        except OSError:
            return None
        if (
            after_descriptor.st_nlink != 1
            or after_path.st_nlink != 1
            or _file_identity(after_descriptor) != _file_identity(before)
            or _file_identity(after_path) != _file_identity(before)
        ):
            return None
        return content
    finally:
        os.close(fd)


def _embed_figure_src(case_dir: Path, src: str) -> str | None:
    normalized = src.replace("\\", "/")
    path = PurePosixPath(normalized)
    if (
        path.is_absolute()
        or len(path.parts) != 2
        or path.parts[0] != "figures"
        or path.suffix.lower() != ".png"
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        return None
    data = read_regular_file_no_follow(
        case_dir / path.parts[0] / path.parts[1], max_bytes=MAX_FIGURE_BYTES
    )
    if data is None or not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return None
    return "data:image/png;base64," + base64.b64encode(data).decode("ascii")


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def read_text_regular_file_no_follow(
    path: Path, *, max_bytes: int = MAX_CASE_ARTIFACT_BYTES
) -> str | None:
    """Read one UTF-8 text snapshot through the bounded descriptor boundary."""

    data = read_regular_file_no_follow(path, max_bytes=max_bytes)
    if data is None:
        return None
    try:
        return data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None


def regular_file_size_no_follow(
    path: Path, *, max_bytes: int, min_bytes: int = 0
) -> int | None:
    """Validate a regular file through a descriptor without loading its content."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not min_bytes <= before.st_size <= max_bytes
        ):
            return None
        fd = os.open(path, flags | nofollow)
    except (FileNotFoundError, OSError):
        return None
    try:
        descriptor = os.fstat(fd)
        try:
            after_path = path.lstat()
        except OSError:
            return None
        if (
            not stat.S_ISREG(descriptor.st_mode)
            or descriptor.st_nlink != 1
            or after_path.st_nlink != 1
            or not min_bytes <= descriptor.st_size <= max_bytes
            or _file_identity(descriptor) != _file_identity(before)
            or _file_identity(after_path) != _file_identity(before)
        ):
            return None
        return descriptor.st_size
    finally:
        os.close(fd)


def require_text_regular_file_no_follow(
    path: Path, *, max_bytes: int = MAX_CASE_ARTIFACT_BYTES
) -> str:
    """Return a safe text snapshot or fail closed for a required artifact."""

    text = read_text_regular_file_no_follow(path, max_bytes=max_bytes)
    if text is None:
        raise ValueError(
            f"unsafe, unstable, invalid, or oversized report input: {path.name}"
        )
    return text


def ensure_safe_report_output(path: Path) -> None:
    """Refuse an existing linked or non-regular report output target."""

    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise ValueError(f"unsafe report output target: {path.name}") from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError(f"unsafe report output target: {path.name}")


def ensure_safe_output_directory(path: Path) -> None:
    """Create or validate a real output directory without following its leaf."""

    try:
        metadata = path.lstat()
    except FileNotFoundError:
        try:
            os.mkdir(path, mode=0o700)
            metadata = path.lstat()
        except OSError as exc:
            raise ValueError(f"unsafe report output directory: {path.name}") from exc
    except OSError as exc:
        raise ValueError(f"unsafe report output directory: {path.name}") from exc
    if not stat.S_ISDIR(metadata.st_mode) or path.is_symlink():
        raise ValueError(f"unsafe report output directory: {path.name}")


def publish_report_output(source: Path, target: Path) -> None:
    """Atomically publish a private render file without following target links."""

    try:
        metadata = source.lstat()
    except OSError as exc:
        raise ValueError(f"unsafe report output source: {source.name}") from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError(f"unsafe report output source: {source.name}")
    ensure_safe_output_directory(target.parent)
    ensure_safe_report_output(target)
    os.replace(source, target)


def write_report_text_no_follow(path: Path, text: str) -> None:
    """Atomically write UTF-8 report text while refusing linked targets."""

    ensure_safe_output_directory(path.parent)
    ensure_safe_report_output(path)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, 0o600)
        data = text.encode("utf-8")
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short write while creating report output")
            view = view[written:]
        os.fsync(fd)
        os.close(fd)
        fd = -1
        publish_report_output(temporary, path)
    finally:
        if fd >= 0:
            os.close(fd)
        temporary.unlink(missing_ok=True)


def save_matplotlib_figure(fig: Any, target: Path, **savefig_kwargs: Any) -> None:
    """Render a PNG privately, validate it, then atomically publish it."""

    ensure_safe_output_directory(target.parent)
    ensure_safe_report_output(target)
    with report_render_workspace(target.parent) as workspace:
        source = workspace / target.name
        fig.savefig(source, **savefig_kwargs)
        data = read_regular_file_no_follow(source, max_bytes=MAX_FIGURE_BYTES)
        if data is None or not data.startswith(b"\x89PNG\r\n\x1a\n"):
            raise ValueError(f"unsafe or invalid report figure: {target.name}")
        publish_report_output(source, target)


@contextmanager
def report_render_workspace(parent: Path) -> Iterator[Path]:
    """Create a private sibling workspace for untrusted renderer subprocess I/O."""

    ensure_safe_output_directory(parent)
    with tempfile.TemporaryDirectory(prefix=".report-render-", dir=parent) as tmp:
        path = Path(tmp)
        path.chmod(0o700)
        yield path


def _resource_value(match: re.Match[str]) -> str:
    return (match.group("quoted") or match.group("unquoted") or "").strip()


def _filter_resource_attributes(html_text: str, case_dir: Path) -> str:
    def replace(match: re.Match[str]) -> str:
        name = match.group("name").lower()
        value = _resource_value(match)
        if name == "src":
            if value.startswith("data:image/png;base64,"):
                return f' src="{value}"'
            embedded = _embed_figure_src(case_dir, value)
            if embedded is not None:
                return f' src="{embedded}"'
        elif name in {"href", "xlink:href"}:
            if re.fullmatch(r"#[A-Za-z0-9_.:-]+", value):
                return f' href="{value}"'
            if value.startswith("data:application/x-ndjson;base64,"):
                encoded = value.removeprefix("data:application/x-ndjson;base64,")
                try:
                    base64.b64decode(encoded, validate=True)
                except (binascii.Error, ValueError):
                    pass
                else:
                    return f' href="{value}"'
        return ' data-verdict-resource-blocked="true"'

    return _RESOURCE_ATTR_RE.sub(replace, html_text)


def _trusted_audit_script(script: str, expected_sha256: str | None) -> bool:
    match = _TRUSTED_AUDIT_SCRIPT_RE.fullmatch(script)
    if match is None or match.group(1) != expected_sha256:
        return False
    try:
        payload = base64.b64decode(match.group(2), validate=True)
    except (binascii.Error, ValueError):
        return False
    return hashlib.sha256(payload).hexdigest() == match.group(1)


def _filter_scripts(html_text: str, trusted_audit_sha256: str | None) -> str:
    """Remove every script except the renderer's exact authenticated data block."""

    output: list[str] = []
    cursor = 0
    for match in _SCRIPT_BLOCK_RE.finditer(html_text):
        output.append(_SCRIPT_TAG_RE.sub("", html_text[cursor : match.start()]))
        script = match.group(0)
        if _trusted_audit_script(script, trusted_audit_sha256):
            output.append(script)
        cursor = match.end()
    output.append(_SCRIPT_TAG_RE.sub("", html_text[cursor:]))
    return "".join(output)


def secure_report_html(
    html_text: str,
    *,
    case_dir: Path,
    css_text: str,
    trusted_audit_sha256: str | None = None,
) -> str:
    """Return self-contained HTML with no active external/local resource path."""

    text = _META_TAG_RE.sub("", html_text)
    text = _DANGEROUS_ELEMENT_RE.sub("", text)
    text = _filter_scripts(text, trusted_audit_sha256)
    text = _EVENT_HANDLER_ATTR_RE.sub("", text)
    text = _filter_resource_attributes(text, case_dir)

    # Only data: font/image URLs from fixed renderer CSS survive.  This also
    # catches a future accidental url(file://...) in the checked-in stylesheet.
    def safe_css_url(match: re.Match[str]) -> str:
        target = match.group(2).strip()
        if target.startswith(("data:font/woff2;base64,", "data:image/")):
            return match.group(0)
        return "url('')"

    css = _CSS_URL_RE.sub(safe_css_url, css_text)
    csp = escape(REPORT_CSP, quote=True)
    security_head = (
        '<meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<meta http-equiv="Content-Security-Policy" content="{csp}">'
        '<meta name="referrer" content="no-referrer">'
        f"<style>{css}</style>"
    )
    head = re.search(r"<head(?:\s[^>]*)?>", text, re.IGNORECASE)
    if head:
        return text[: head.end()] + security_head + text[head.end() :]
    return (
        "<!doctype html><html><head>"
        + security_head
        + "</head><body>"
        + text
        + "</body></html>"
    )


def chromium_pdf_args(
    chrome: str,
    *,
    html_path: Path,
    pdf_path: Path,
    user_data_dir: Path,
) -> list[str]:
    """Build a sandbox-preserving, network-denied headless Chromium command."""

    return [
        chrome,
        "--headless",
        "--disable-gpu",
        "--disable-background-networking",
        "--disable-client-side-phishing-detection",
        "--disable-component-update",
        "--disable-default-apps",
        "--disable-domain-reliability",
        "--disable-extensions",
        "--disable-sync",
        "--metrics-recording-only",
        "--no-first-run",
        "--no-default-browser-check",
        "--safebrowsing-disable-auto-update",
        "--host-resolver-rules=MAP * ~NOTFOUND",
        "--proxy-server=http://127.0.0.1:9",
        "--proxy-bypass-list=<-loopback>",
        f"--user-data-dir={user_data_dir}",
        "--print-to-pdf=" + str(pdf_path),
        "--print-to-pdf-no-header",
        "--virtual-time-budget=10000",
        html_path.resolve().as_uri(),
    ]


def secure_chromium_available() -> bool:
    """Chrome's setuid/user-namespace sandbox is not available when run as root."""

    geteuid = getattr(os, "geteuid", None)
    return not callable(geteuid) or geteuid() != 0


@contextmanager
def chromium_profile(parent: Path) -> Iterator[Path]:
    """Use an empty, ephemeral profile contained in the report output directory."""

    with tempfile.TemporaryDirectory(prefix=".report-chrome-", dir=parent) as tmp:
        path = Path(tmp)
        path.chmod(0o700)
        yield path
