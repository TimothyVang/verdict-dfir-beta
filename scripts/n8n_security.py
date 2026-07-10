#!/usr/bin/env python3
"""Shared security primitives for the optional local n8n grounding sidecar.

This module deliberately has no third-party dependencies.  It is imported by
the setup scripts and the post-verdict caller, all of which must also work from
an arbitrary current working directory.
"""

from __future__ import annotations

import ipaddress
import os
import secrets
import socket
import stat
from pathlib import Path
from urllib.parse import SplitResult, urlsplit, urlunsplit

MAX_URL_CHARS = 2048
MAX_SECRET_BYTES = 8192

_BLOCKED_HOSTS = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "metadata",
        "metadata.google.internal",
        "metadata.azure.internal",
        "instance-data.ec2.internal",
    }
)
_BLOCKED_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".home",
    ".lan",
    ".test",
    ".invalid",
    ".example",
)


def _parse_http_url(url: str) -> tuple[SplitResult, str, int]:
    if not isinstance(url, str) or not url or len(url) > MAX_URL_CHARS:
        raise ValueError("URL is empty or exceeds the 2048-character limit")
    if any(ord(char) < 0x21 or ord(char) == 0x7F for char in url):
        raise ValueError("URL contains whitespace or control characters")
    parsed = urlsplit(url)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("only http(s) URLs are allowed")
    if not parsed.netloc or not parsed.hostname:
        raise ValueError("URL must include a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URL credentials are forbidden")
    try:
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    except ValueError as exc:
        raise ValueError("URL contains an invalid port") from exc
    if not 1 <= port <= 65535:
        raise ValueError("URL port is outside 1..65535")
    host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    if not host:
        raise ValueError("URL hostname is empty")
    return parsed, host, port


def _normalized_url(parsed: SplitResult, host: str, port: int) -> str:
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    display_host = f"[{host}]" if ":" in host else host
    netloc = display_host if port == default_port else f"{display_host}:{port}"
    return urlunsplit(
        (parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, "")
    )


def validate_loopback_http_url(url: str) -> str:
    """Accept only a literal loopback http(s) URL with no credentials/query.

    Literal addresses avoid trusting host-file or DNS aliases at the boundary
    where verdict metadata is handed to the local automation sidecar.
    """

    parsed, host, port = _parse_http_url(url)
    if parsed.query or parsed.fragment:
        raise ValueError("local automation URL must not include query or fragment data")
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError(
            "local automation URL must use a literal loopback address"
        ) from exc
    if not address.is_loopback:
        raise ValueError("local automation URL must resolve only to loopback")
    return _normalized_url(parsed, address.compressed, port)


def _require_global_address(value: str) -> None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(f"DNS returned an invalid address: {value!r}") from exc
    if not address.is_global:
        raise ValueError(
            "URL resolves to a non-public address "
            f"({address.compressed}; private/link-local/reserved/multicast forbidden)"
        )


def validate_public_http_url(url: str, *, resolve: bool = True) -> str:
    """Validate a public outbound URL, including every DNS answer.

    Call this again for each redirect target before following it.  A caller
    should disable automatic redirects so no unvalidated hop can be reached.
    """

    parsed, host, port = _parse_http_url(url)
    if host in _BLOCKED_HOSTS or host.endswith(_BLOCKED_SUFFIXES):
        raise ValueError("localhost, metadata, and internal DNS names are forbidden")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        _require_global_address(literal.compressed)
    elif resolve:
        try:
            answers = socket.getaddrinfo(
                host,
                port,
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
            )
        except socket.gaierror as exc:
            raise ValueError(f"URL hostname did not resolve: {host}") from exc
        addresses = {answer[4][0] for answer in answers}
        if not addresses:
            raise ValueError(f"URL hostname did not resolve: {host}")
        for address in addresses:
            _require_global_address(address)
    return _normalized_url(parsed, host, port)


def _secure_file_flags(write: bool = False) -> int:
    flags = os.O_WRONLY if write else os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    return flags


def _reject_link_path(path: Path) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode):
        raise PermissionError(f"secret path must not be a symlink: {path}")


def _validate_open_secret(
    fd: int, path: Path, *, require_private: bool
) -> os.stat_result:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        raise PermissionError(f"secret path is not a regular file: {path}")
    if info.st_nlink != 1:
        raise PermissionError(f"secret path must not be hard-linked: {path}")
    if hasattr(os, "getuid") and info.st_uid != os.getuid():
        raise PermissionError(f"secret path is not owned by the current user: {path}")
    if require_private and stat.S_IMODE(info.st_mode) & 0o077:
        raise PermissionError(f"secret path must be mode 0600: {path}")
    return info


def read_private_secret(path: Path, *, minimum_bytes: int = 1) -> str:
    """Read one small, current-user-owned 0600 regular file without links."""

    path = Path(path)
    _reject_link_path(path)
    fd = os.open(path, _secure_file_flags())
    try:
        info = _validate_open_secret(fd, path, require_private=True)
        if info.st_size > MAX_SECRET_BYTES:
            raise ValueError(f"secret file exceeds {MAX_SECRET_BYTES} bytes: {path}")
        chunks = []
        remaining = MAX_SECRET_BYTES + 1
        while remaining:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    finally:
        os.close(fd)
    value = raw.decode("utf-8").strip()
    if len(value.encode("utf-8")) < minimum_bytes:
        raise ValueError(f"secret must contain at least {minimum_bytes} bytes: {path}")
    return value


def harden_private_file(path: Path) -> None:
    """Safely migrate an owned, unlinked regular file to mode 0600."""

    path = Path(path)
    _reject_link_path(path)
    fd = os.open(path, _secure_file_flags(write=True))
    try:
        _validate_open_secret(fd, path, require_private=False)
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        else:
            os.chmod(path, 0o600)
        os.fsync(fd)
    finally:
        os.close(fd)


def ensure_private_secret(path: Path, *, minimum_bytes: int = 32) -> str:
    """Create a high-entropy 0600 capability once, or verify the existing one."""

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    _reject_link_path(path)
    try:
        return read_private_secret(path, minimum_bytes=minimum_bytes)
    except FileNotFoundError:
        pass
    value = secrets.token_urlsafe(minimum_bytes)
    flags = _secure_file_flags(write=True) | os.O_CREAT | os.O_EXCL
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        return read_private_secret(path, minimum_bytes=minimum_bytes)
    try:
        _validate_open_secret(fd, path, require_private=False)
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        else:
            os.chmod(path, 0o600)
        raw = (value + "\n").encode("utf-8")
        offset = 0
        while offset < len(raw):
            written = os.write(fd, raw[offset:])
            if written <= 0:
                raise OSError("short write while creating secret")
            offset += written
        os.fsync(fd)
    finally:
        os.close(fd)
    return value


def write_private_text(path: Path, value: str) -> None:
    """Write a small secret file after fd-based link/type/owner validation."""

    path = Path(path)
    raw = value.encode("utf-8")
    if len(raw) > MAX_SECRET_BYTES:
        raise ValueError(f"secret exceeds {MAX_SECRET_BYTES} bytes")
    path.parent.mkdir(parents=True, exist_ok=True)
    _reject_link_path(path)
    flags = _secure_file_flags(write=True) | os.O_CREAT
    fd = os.open(path, flags, 0o600)
    try:
        _validate_open_secret(fd, path, require_private=False)
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        else:
            os.chmod(path, 0o600)
        os.ftruncate(fd, 0)
        offset = 0
        while offset < len(raw):
            written = os.write(fd, raw[offset:])
            if written <= 0:
                raise OSError("short write while writing secret")
            offset += written
        os.fsync(fd)
    finally:
        os.close(fd)
