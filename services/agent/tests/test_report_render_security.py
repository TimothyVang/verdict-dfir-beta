"""Hostile report text must remain inert and report rendering must stay offline."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import shlex
import shutil
import subprocess
import sys
import threading
import types
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = REPO_ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from report_entailment import entailment_evidence_lines  # noqa: E402
from report_render_security import (  # noqa: E402
    CHROMIUM_RENDER_TIMEOUT_SECONDS,
    MAX_CASE_ARTIFACT_BYTES,
    PANDOC_RENDER_TIMEOUT_SECONDS,
    chromium_pdf_args,
    load_self_contained_css,
    markdown_code,
    markdown_text,
    read_regular_file_no_follow,
    save_matplotlib_figure,
    secure_report_html,
)


def _load_render_report():
    spec = importlib.util.spec_from_file_location(
        "render_report_security_test", SCRIPTS / "render_report.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_render_fleet_report():
    try:
        matplotlib_available = importlib.util.find_spec("matplotlib") is not None
    except ValueError:
        matplotlib_available = False
    if not matplotlib_available:
        matplotlib = types.ModuleType("matplotlib")
        matplotlib.__path__ = []  # type: ignore[attr-defined]
        matplotlib.use = lambda *_args, **_kwargs: None  # type: ignore[attr-defined]
        patches = types.ModuleType("matplotlib.patches")
        pyplot = types.ModuleType("matplotlib.pyplot")
        pyplot.rcParams = {}  # type: ignore[attr-defined]
        font_manager = types.ModuleType("matplotlib.font_manager")
        font_manager.FontProperties = object  # type: ignore[attr-defined]
        sys.modules["matplotlib"] = matplotlib
        sys.modules["matplotlib.patches"] = patches
        sys.modules["matplotlib.pyplot"] = pyplot
        sys.modules["matplotlib.font_manager"] = font_manager
    spec = importlib.util.spec_from_file_location(
        "render_fleet_report_security_test", SCRIPTS / "render_fleet_report.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_hostile_entailment_markdown_cannot_open_a_resource() -> None:
    hostile = "`\n![steal](http://127.0.0.1:9999/token)\n<script src=file:///etc/passwd>"
    lines = entailment_evidence_lines(
        {
            "replay_artifact": {
                "entailment": {
                    "matched": [{"path": hostile, "actual": hostile}],
                }
            }
        }
    )

    assert len(lines) == 1
    assert lines[0].count("\n") == 0
    assert "`\n" not in lines[0]
    assert lines[0].count("`") == 4
    pandoc = shutil.which("pandoc")
    if pandoc:
        rendered = subprocess.run(
            [pandoc, "--from", "markdown-raw_html-raw_tex", "--to", "html5"],
            input=lines[0],
            capture_output=True,
            check=True,
            text=True,
        ).stdout
        assert "<img" not in rendered.lower()
        assert "<script" not in rendered.lower()
        assert rendered.count("<code>") == 2


def test_markdown_helpers_preserve_code_fidelity_without_delimiter_breakout() -> None:
    assert markdown_code(r"C:\Users\bob\evil.exe") == r"C:\Users\bob\evil.exe"
    assert "`" not in markdown_code("`\n![x](http://example.test)")
    escaped = markdown_text("<img src=file:///etc/passwd>\n![x](http://example.test)")
    assert "<img" not in escaped
    assert "![" not in escaped
    assert "\n" not in escaped


@pytest.mark.parametrize(
    "hostile",
    [
        "$(touch /tmp/verdict-report-pwn)",
        "tc-safe; touch /tmp/verdict-report-pwn",
        "tc-safe`touch /tmp/verdict-report-pwn`",
    ],
)
def test_reverify_affordance_omits_hostile_tool_call_id(hostile: str) -> None:
    renderer = _load_render_report()

    lines = renderer.confirmed_reverify_affordance(
        {"confidence": "CONFIRMED", "tool_call_id": hostile}
    )

    assert lines == []


@pytest.mark.parametrize(
    "tool_call_id",
    ["tc-confirmed-19", "tc-evtx_01", "8f5c2018-681c-49e0-bd92-933f063cec27"],
)
def test_reverify_affordance_accepts_canonical_safe_tool_call_id(
    tool_call_id: str,
) -> None:
    renderer = _load_render_report()

    lines = renderer.confirmed_reverify_affordance(
        {"confidence": "CONFIRMED", "tool_call_id": tool_call_id}
    )

    assert len(lines) == 1
    command = lines[0].split("`", 2)[1]
    assert shlex.split(command) == ["grep", "-F", "--", tool_call_id, "audit.jsonl"]


def test_manifest_verification_command_matches_signature_tier() -> None:
    renderer = _load_render_report()

    ed25519 = renderer.manifest_verification_command("ed25519", "PATH/TO/run.manifest.json")
    sigstore = renderer.manifest_verification_command("sigstore", "PATH/TO/run.manifest.json")

    assert "expected_ed25519_fingerprint" in ed25519
    assert "expected_sigstore_identity" not in ed25519
    assert "expected_sigstore_identity" in sigstore
    assert "expected_sigstore_issuer" in sigstore
    assert "expected_ed25519_fingerprint" not in sigstore


def test_report_tamper_recipe_uses_private_exclusive_output() -> None:
    source = (SCRIPTS / "render_report.py").read_text(encoding="utf-8")

    assert "TAMPER_DIR=" in source
    assert "os.O_EXCL" in source
    assert "O_NOFOLLOW" in source
    assert "shutil.copyfile('run.manifest.json','run.manifest.tamper.json')" not in source


def test_secure_html_removes_active_remote_and_local_resources(tmp_path: Path) -> None:
    hostile = """<!doctype html><html><head>
      <link rel="stylesheet" href="http://127.0.0.1:9999/leak">
      <script src="file:///etc/passwd">fetch('http://127.0.0.1')</script>
      </head><body><iframe src="http://127.0.0.1"></iframe>
      <img src="http://127.0.0.1:9999/secret"><a href="file:///etc/passwd">x</a>
      </body></html>"""
    secured = secure_report_html(
        hostile,
        case_dir=tmp_path,
        css_text="body{background:url(http://127.0.0.1:9999/css)}",
    )

    assert "http://127.0.0.1" not in secured
    assert "file:///etc/passwd" not in secured
    assert "<iframe" not in secured.lower()
    assert "<script" not in secured.lower()
    assert "Content-Security-Policy" in secured
    assert "default-src &#x27;none&#x27;" in secured
    assert "data-verdict-resource-blocked" in secured


@pytest.mark.parametrize(
    "meta",
    [
        '<meta content="0;url=file:///etc/passwd" http-equiv="refresh">',
        '<META HTTP-EQUIV=ReFrEsH CONTENT="0; URL=http://127.0.0.1/leak">',
        '<meta name="viewport" content="file:///etc/shadow">',
    ],
)
def test_secure_html_strips_every_untrusted_meta_tag(tmp_path: Path, meta: str) -> None:
    secured = secure_report_html(
        f"<html><head>{meta}</head><body>safe</body></html>",
        case_dir=tmp_path,
        css_text="",
    )

    assert "file:///" not in secured
    assert "127.0.0.1" not in secured
    assert secured.lower().count("http-equiv") == 1
    assert 'meta charset="utf-8"' in secured.lower()


def test_secure_html_keeps_only_exact_authenticated_audit_data_script(
    tmp_path: Path,
) -> None:
    audit = b'{"kind":"tool_call_output"}\n'
    payload = base64.b64encode(audit).decode("ascii")
    digest = hashlib.sha256(audit).hexdigest()
    trusted = (
        '<script type="application/x-ndjson" id="verdict-embedded-audit-jsonl" '
        f'data-sha256="{digest}">{payload}</script>'
    )
    hostile = (
        '<script type="application/x-ndjson" type="text/javascript">alert(1)</script>'
        '<script type="application/x-ndjson">alert(2)</script>'
        '<img src=http://127.0.0.1/a srcset="file:///etc/passwd 1x">'
        '<a href=file:///etc/shadow ping="//127.0.0.1/leak">bad</a>'
        "<object data=file:///etc/hosts></object>"
    )

    secured = secure_report_html(
        f"<html><head></head><body>{trusted}{hostile}</body></html>",
        case_dir=tmp_path,
        css_text="",
        trusted_audit_sha256=digest,
    )

    assert trusted in secured
    assert secured.lower().count("<script") == 1
    assert "alert(" not in secured
    assert "127.0.0.1" not in secured
    assert "file:///" not in secured
    assert "srcset=" not in secured.lower()
    assert " ping=" not in secured.lower()
    assert " data=file" not in secured.lower()


def test_secure_html_rejects_forged_audit_data_script(tmp_path: Path) -> None:
    payload = base64.b64encode(b"forged").decode("ascii")
    forged = (
        '<script type="application/x-ndjson" id="verdict-embedded-audit-jsonl" '
        f'data-sha256="{"0" * 64}">{payload}</script>'
    )

    secured = secure_report_html(
        f"<html><head></head><body>{forged}</body></html>",
        case_dir=tmp_path,
        css_text="",
    )

    assert "<script" not in secured.lower()


def test_vendored_css_has_no_remote_imports() -> None:
    css = load_self_contained_css(SCRIPTS / "_report_style.css")

    assert "fonts.googleapis.com" not in css
    assert "@import" not in css.lower()
    assert "data:font/woff2;base64," in css


def test_chromium_command_keeps_sandbox_and_denies_network(tmp_path: Path) -> None:
    args = chromium_pdf_args(
        "/usr/bin/chromium",
        html_path=tmp_path / "REPORT.html",
        pdf_path=tmp_path / "REPORT.pdf",
        user_data_dir=tmp_path / "profile",
    )

    assert "--no-sandbox" not in args
    assert "--disable-web-security" not in args
    assert "--host-resolver-rules=MAP * ~NOTFOUND" in args
    assert "--proxy-server=http://127.0.0.1:9" in args
    assert args[-1].startswith("file://")


def test_single_case_render_uses_sandboxed_pandoc_then_secures_html(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    renderer = _load_render_report()
    md = tmp_path / "REPORT.md"
    md.write_text("# Report\n\n![steal](http://127.0.0.1:9999/token)\n", encoding="utf-8")
    (tmp_path / "audit.jsonl").write_text(
        '{"kind":"tool_call_output","payload":{"tool_call_id":"tc-1"}}\n',
        encoding="utf-8",
    )
    calls: list[list[str]] = []
    timeouts: list[object] = []

    def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        timeouts.append(_kwargs.get("timeout"))
        output = Path(args[args.index("-o") + 1])
        output.write_text(
            '<html><head></head><body><img src="http://127.0.0.1:9999/token">'
            '<script>fetch("file:///etc/passwd")</script></body></html>',
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(renderer, "PANDOC", "/trusted/pandoc")
    monkeypatch.setattr(renderer, "CHROME", None)
    monkeypatch.setattr(renderer.subprocess, "run", fake_run)

    html, pdf = renderer.render_html_pdf(md)

    assert pdf is None
    assert calls
    assert "--sandbox" in calls[0]
    assert "markdown-raw_html-raw_tex" in calls[0]
    assert "--embed-resources" not in calls[0]
    rendered = html.read_text(encoding="utf-8")
    assert "http://127.0.0.1" not in rendered
    assert "file:///etc/passwd" not in rendered
    assert "Content-Security-Policy" in rendered
    assert rendered.count('id="verdict-embedded-audit-jsonl"') == 1
    assert timeouts == [PANDOC_RENDER_TIMEOUT_SECONDS]


@pytest.mark.parametrize("kind", ["case", "fleet"])
def test_pandoc_timeout_never_publishes_partial_html(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    renderer = _load_render_report() if kind == "case" else _load_render_fleet_report()
    stem = "REPORT" if kind == "case" else "FLEET_REPORT"
    md = tmp_path / f"{stem}.md"
    md.write_text("# Report\n", encoding="utf-8")
    html = tmp_path / f"{stem}.html"
    html.write_text("previous-safe-report", encoding="utf-8")

    def timeout_run(args: list[str], **kwargs: object) -> None:
        assert kwargs.get("timeout") == PANDOC_RENDER_TIMEOUT_SECONDS
        output = Path(args[args.index("-o") + 1])
        output.write_text("<html>partial-untrusted-output", encoding="utf-8")
        raise subprocess.TimeoutExpired(args, PANDOC_RENDER_TIMEOUT_SECONDS)

    monkeypatch.setattr(renderer, "PANDOC", "/trusted/pandoc")
    monkeypatch.setattr(renderer, "CHROME", None if kind == "case" else "/missing/chrome")
    monkeypatch.setattr(renderer.subprocess, "run", timeout_run)

    with pytest.raises(subprocess.TimeoutExpired):
        renderer.render_html_pdf(md)

    assert html.read_text(encoding="utf-8") == "previous-safe-report"
    assert not list(tmp_path.glob(".report-render-*"))


@pytest.mark.parametrize("kind", ["case", "fleet"])
def test_chromium_timeout_discards_partial_pdf_and_keeps_secured_html(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    renderer = _load_render_report() if kind == "case" else _load_render_fleet_report()
    stem = "REPORT" if kind == "case" else "FLEET_REPORT"
    md = tmp_path / f"{stem}.md"
    md.write_text("# Report\n", encoding="utf-8")
    chrome = tmp_path / "chrome"
    chrome.write_text("", encoding="utf-8")
    timeouts: list[object] = []

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        timeouts.append(kwargs.get("timeout"))
        if "-o" in args:
            output = Path(args[args.index("-o") + 1])
            output.write_text("<html><head></head><body>safe</body></html>", encoding="utf-8")
            return subprocess.CompletedProcess(args, 0, "", "")
        pdf_arg = next(arg for arg in args if arg.startswith("--print-to-pdf="))
        Path(pdf_arg.split("=", 1)[1]).write_bytes(b"partial" * 300)
        raise subprocess.TimeoutExpired(args, CHROMIUM_RENDER_TIMEOUT_SECONDS)

    monkeypatch.setattr(renderer, "PANDOC", "/trusted/pandoc")
    monkeypatch.setattr(renderer, "CHROME", str(chrome))
    monkeypatch.setattr(renderer, "secure_chromium_available", lambda: True)
    monkeypatch.setattr(renderer.subprocess, "run", fake_run)

    html, pdf = renderer.render_html_pdf(md)

    assert pdf is None
    assert "Content-Security-Policy" in html.read_text(encoding="utf-8")
    assert not (tmp_path / f"{stem}.pdf").exists()
    assert not (tmp_path / f"{stem}.new.pdf").exists()
    assert not list(tmp_path.glob(".report-render-*"))
    assert not list(tmp_path.glob(".report-chrome-*"))
    assert timeouts == [
        PANDOC_RENDER_TIMEOUT_SECONDS,
        CHROMIUM_RENDER_TIMEOUT_SECONDS,
    ]


@pytest.mark.parametrize("stem", ["REPORT", "REPORT-internal"])
@pytest.mark.parametrize("link_kind", ["symlink", "hardlink"])
def test_single_case_renderer_refuses_linked_html_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, link_kind: str, stem: str
) -> None:
    renderer = _load_render_report()
    md = tmp_path / f"{stem}.md"
    md.write_text("# Report\n", encoding="utf-8")
    victim = tmp_path / "victim.txt"
    victim.write_text("do-not-clobber", encoding="utf-8")
    html = tmp_path / f"{stem}.html"
    if link_kind == "symlink":
        try:
            html.symlink_to(victim.name)
        except (NotImplementedError, OSError):
            pytest.skip("symlinks are unavailable")
    else:
        html.hardlink_to(victim)

    calls: list[list[str]] = []
    monkeypatch.setattr(renderer, "PANDOC", "/trusted/pandoc")
    monkeypatch.setattr(renderer, "CHROME", None)
    monkeypatch.setattr(renderer.subprocess, "run", lambda args, **_kwargs: calls.append(args))

    with pytest.raises(ValueError, match="unsafe report output"):
        renderer.render_html_pdf(md)

    assert calls == []
    assert victim.read_text(encoding="utf-8") == "do-not-clobber"


@pytest.mark.parametrize("target_name", ["REPORT.md", "REPORT-internal.md"])
def test_single_case_markdown_writer_refuses_linked_packets(
    tmp_path: Path, target_name: str
) -> None:
    renderer = _load_render_report()
    victim = tmp_path / "victim.txt"
    victim.write_text("do-not-clobber", encoding="utf-8")
    target = tmp_path / target_name
    target.hardlink_to(victim)
    manifest = {
        "audit_log_final_hash": "a" * 64,
        "merkle_root_hex": "b" * 64,
        "signature": {
            "payload_sha256": "c" * 64,
            "cert_fingerprint": "d" * 64,
            "kind": "stub",
        },
        "case_id": "case-1",
        "run_id": "run-1",
        "started_at": "2026-01-01T00:00:00Z",
        "finalized_at": "2026-01-01T00:01:00Z",
    }

    with pytest.raises(ValueError, match="unsafe report output"):
        renderer.write_markdown(
            tmp_path,
            manifest,
            [],
            0,
            0,
            0,
            "evidence.evtx",
            "INDETERMINATE",
            False,
        )

    assert victim.read_text(encoding="utf-8") == "do-not-clobber"


@pytest.mark.parametrize("stem", ["REPORT", "REPORT-internal"])
def test_single_case_renderer_refuses_linked_pdf_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stem: str
) -> None:
    renderer = _load_render_report()
    md = tmp_path / f"{stem}.md"
    md.write_text("# Report\n", encoding="utf-8")
    victim = tmp_path / "victim.txt"
    victim.write_text("do-not-clobber", encoding="utf-8")
    (tmp_path / f"{stem}.pdf").hardlink_to(victim)
    calls: list[list[str]] = []
    monkeypatch.setattr(renderer, "PANDOC", "/trusted/pandoc")
    monkeypatch.setattr(renderer, "CHROME", "/trusted/chrome")
    monkeypatch.setattr(renderer.subprocess, "run", lambda args, **_kwargs: calls.append(args))

    with pytest.raises(ValueError, match="unsafe report output"):
        renderer.render_html_pdf(md)

    assert calls == []
    assert victim.read_text(encoding="utf-8") == "do-not-clobber"


def test_fleet_renderer_refuses_linked_outputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    renderer = _load_render_fleet_report()
    md = tmp_path / "FLEET_REPORT.md"
    md.write_text("# Fleet\n", encoding="utf-8")
    victim = tmp_path / "victim.txt"
    victim.write_text("do-not-clobber", encoding="utf-8")
    html = tmp_path / "FLEET_REPORT.html"
    html.hardlink_to(victim)
    calls: list[list[str]] = []
    monkeypatch.setattr(renderer, "PANDOC", "/trusted/pandoc")
    monkeypatch.setattr(renderer, "CHROME", "/missing/chrome")
    monkeypatch.setattr(renderer.subprocess, "run", lambda args, **_kwargs: calls.append(args))

    with pytest.raises(ValueError, match="unsafe report output"):
        renderer.render_html_pdf(md)

    assert calls == []
    assert victim.read_text(encoding="utf-8") == "do-not-clobber"


def test_fleet_markdown_writer_refuses_linked_output(tmp_path: Path) -> None:
    renderer = _load_render_fleet_report()
    victim = tmp_path / "victim.txt"
    victim.write_text("do-not-clobber", encoding="utf-8")
    (tmp_path / "FLEET_REPORT.md").hardlink_to(victim)

    with pytest.raises(ValueError, match="unsafe report output"):
        renderer.write_markdown(tmp_path, {}, False)

    assert victim.read_text(encoding="utf-8") == "do-not-clobber"


def test_fleet_renderer_refuses_linked_pdf_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    renderer = _load_render_fleet_report()
    md = tmp_path / "FLEET_REPORT.md"
    md.write_text("# Fleet\n", encoding="utf-8")
    victim = tmp_path / "victim.txt"
    victim.write_text("do-not-clobber", encoding="utf-8")
    (tmp_path / "FLEET_REPORT.pdf").hardlink_to(victim)
    chrome = tmp_path / "chrome"
    chrome.write_text("", encoding="utf-8")
    calls: list[list[str]] = []
    monkeypatch.setattr(renderer, "PANDOC", "/trusted/pandoc")
    monkeypatch.setattr(renderer, "CHROME", str(chrome))
    monkeypatch.setattr(renderer.subprocess, "run", lambda args, **_kwargs: calls.append(args))

    with pytest.raises(ValueError, match="unsafe report output"):
        renderer.render_html_pdf(md)

    assert calls == []
    assert victim.read_text(encoding="utf-8") == "do-not-clobber"


def test_standalone_case_main_does_not_use_path_read_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    renderer = _load_render_report()
    (tmp_path / "run.manifest.json").write_text('{"case_id":"case-1"}', encoding="utf-8")
    (tmp_path / "verdict.json").write_text(
        json.dumps({"findings": [], "findings_summary": {}}), encoding="utf-8"
    )
    monkeypatch.setattr(
        renderer.Path,
        "read_text",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("unsafe read_text")),
    )
    monkeypatch.setattr(
        renderer, "render_report", lambda *_args, **_kwargs: tmp_path / "REPORT.html"
    )
    monkeypatch.setattr(sys, "argv", ["render_report.py", str(tmp_path)])

    assert renderer.main() == 0


@pytest.mark.parametrize("mode", ["symlink", "hardlink", "oversized"])
def test_standalone_case_main_rejects_unsafe_required_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    renderer = _load_render_report()
    manifest = tmp_path / "run.manifest.json"
    if mode == "oversized":
        manifest.touch()
        manifest.chmod(0o600)
        with manifest.open("r+b") as stream:
            stream.truncate(MAX_CASE_ARTIFACT_BYTES + 1)
    else:
        original = tmp_path / "manifest-source.json"
        original.write_text('{"case_id":"case-1"}', encoding="utf-8")
        if mode == "symlink":
            try:
                manifest.symlink_to(original.name)
            except (NotImplementedError, OSError):
                pytest.skip("symlinks are unavailable")
        else:
            manifest.hardlink_to(original)
    (tmp_path / "verdict.json").write_text(
        json.dumps({"findings": [], "findings_summary": {}}), encoding="utf-8"
    )
    rendered: list[object] = []
    monkeypatch.setattr(
        renderer, "render_report", lambda *_args, **_kwargs: rendered.append(object())
    )
    monkeypatch.setattr(sys, "argv", ["render_report.py", str(tmp_path)])

    with pytest.raises(ValueError, match="unsafe, unstable, invalid, or oversized"):
        renderer.main()

    assert rendered == []


def test_standalone_fleet_main_does_not_use_path_read_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    renderer = _load_render_fleet_report()
    (tmp_path / "fleet_correlation.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        renderer.Path,
        "read_text",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("unsafe read_text")),
    )
    for name in (
        "fig_verdict_distribution",
        "fig_mitre_density",
        "fig_cross_host_processes",
    ):
        monkeypatch.setattr(renderer, name, lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        renderer, "write_markdown", lambda *_args, **_kwargs: tmp_path / "FLEET_REPORT.md"
    )
    monkeypatch.setattr(
        renderer,
        "render_html_pdf",
        lambda *_args, **_kwargs: (tmp_path / "FLEET_REPORT.html", None),
    )
    monkeypatch.setattr(sys, "argv", ["render_fleet_report.py", str(tmp_path)])

    assert renderer.main() == 0


def test_standalone_fleet_main_rejects_linked_correlation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    renderer = _load_render_fleet_report()
    original = tmp_path / "correlation-source.json"
    original.write_text("{}", encoding="utf-8")
    (tmp_path / "fleet_correlation.json").hardlink_to(original)
    rendered: list[object] = []
    monkeypatch.setattr(
        renderer, "write_markdown", lambda *_args, **_kwargs: rendered.append(object())
    )
    monkeypatch.setattr(sys, "argv", ["render_fleet_report.py", str(tmp_path)])

    assert renderer.main() == 1
    assert rendered == []


def test_bounded_resource_reader_rejects_links_and_oversize(tmp_path: Path) -> None:
    original = tmp_path / "figure.png"
    original.write_bytes(b"payload")
    assert read_regular_file_no_follow(original, max_bytes=7) == b"payload"
    assert read_regular_file_no_follow(original, max_bytes=6) is None

    hardlink = tmp_path / "hardlink.png"
    hardlink.hardlink_to(original)
    assert read_regular_file_no_follow(original, max_bytes=7) is None
    hardlink.unlink()

    symlink = tmp_path / "symlink.png"
    try:
        symlink.symlink_to(original.name)
    except (NotImplementedError, OSError):
        return
    assert read_regular_file_no_follow(symlink, max_bytes=7) is None


class _FakeFigure:
    def __init__(self) -> None:
        self.calls = 0

    def savefig(self, path: Path, **_kwargs: object) -> None:
        self.calls += 1
        Path(path).write_bytes(b"\x89PNG\r\n\x1a\nprivate-render")


@pytest.mark.parametrize("link_kind", ["symlink", "hardlink", "fifo"])
def test_figure_publisher_refuses_linked_or_special_targets(tmp_path: Path, link_kind: str) -> None:
    figures = tmp_path / "figures"
    figures.mkdir()
    target = figures / "chain_of_custody.png"
    victim = tmp_path / "victim.txt"
    victim.write_text("do-not-clobber", encoding="utf-8")
    if link_kind == "symlink":
        try:
            target.symlink_to(victim)
        except (NotImplementedError, OSError):
            pytest.skip("symlinks are unavailable")
    elif link_kind == "hardlink":
        target.hardlink_to(victim)
    else:
        try:
            os.mkfifo(target)
        except (AttributeError, NotImplementedError, OSError):
            pytest.skip("FIFOs are unavailable")
    figure = _FakeFigure()

    with pytest.raises(ValueError, match="unsafe report output"):
        save_matplotlib_figure(figure, target)

    assert figure.calls == 0
    assert victim.read_text(encoding="utf-8") == "do-not-clobber"


def test_figure_publisher_refuses_symlinked_figures_directory(tmp_path: Path) -> None:
    redirected = tmp_path / "redirected"
    redirected.mkdir()
    figures = tmp_path / "figures"
    try:
        figures.symlink_to(redirected, target_is_directory=True)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are unavailable")
    figure = _FakeFigure()

    with pytest.raises(ValueError, match="unsafe report output directory"):
        save_matplotlib_figure(figure, figures / "chain_of_custody.png")

    assert figure.calls == 0
    assert not (redirected / "chain_of_custody.png").exists()


def test_figure_publisher_privately_publishes_regular_png(tmp_path: Path) -> None:
    figures = tmp_path / "figures"
    figures.mkdir()
    target = figures / "chain_of_custody.png"
    figure = _FakeFigure()

    save_matplotlib_figure(figure, target, dpi=150)

    assert figure.calls == 1
    assert target.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
    assert not list(figures.glob(".report-render-*"))


@pytest.mark.skipif(shutil.which("pandoc") is None, reason="pandoc is unavailable")
def test_real_render_makes_zero_hostile_network_requests(tmp_path: Path) -> None:
    renderer = _load_render_report()
    if renderer.PANDOC is None:
        pytest.skip("pandoc is unavailable to the renderer")

    class ProbeHandler(BaseHTTPRequestHandler):
        hits = 0

        def do_GET(self) -> None:
            type(self).hits += 1
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"network-secret")

        def log_message(self, *_args: object) -> None:
            return

    try:
        server = ThreadingHTTPServer(("127.0.0.1", 0), ProbeHandler)
    except PermissionError:
        pytest.skip("sandbox forbids loopback sockets")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        secret = tmp_path / "local-secret.txt"
        secret.write_text("local-file-secret", encoding="utf-8")
        md = tmp_path / "REPORT.md"
        md.write_text(
            "# Hostile report\n\n"
            f"![remote](http://127.0.0.1:{port}/secret)\n\n"
            f"![local]({secret.as_uri()})\n",
            encoding="utf-8",
        )

        html, _pdf = renderer.render_html_pdf(md)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    rendered = html.read_text(encoding="utf-8")
    assert ProbeHandler.hits == 0
    assert f"127.0.0.1:{port}" not in rendered
    assert secret.as_uri() not in rendered
    assert "network-secret" not in rendered
    assert "local-file-secret" not in rendered
