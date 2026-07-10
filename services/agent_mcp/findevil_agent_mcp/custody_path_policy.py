"""Fail-closed host filesystem policy for every custody transport.

The Python MCP owns signing and therefore must not act as a general filesystem
deputy for its caller. When ``FINDEVIL_CUSTODY_BOUNDARY=reserved_case`` is set,
every path-bearing tool is bound to launcher-reserved locations before its
handler runs. Filesystem-capable tools fail closed if a launcher starts the MCP
without that reservation; pure in-memory reasoning tools remain available.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

_BOUNDARY_ENV = "FINDEVIL_CUSTODY_BOUNDARY"
_BOUNDARY_VALUE = "reserved_case"
_ACTIVE_CASE_ENV = "FINDEVIL_ACTIVE_CASE_DIR"
_ACTIVE_CASE_ID_ENV = "FINDEVIL_ACTIVE_CASE_ID"
_ACTIVE_RUN_ID_ENV = "FINDEVIL_ACTIVE_RUN_ID"
_ACTIVE_STARTED_AT_ENV = "FINDEVIL_ACTIVE_STARTED_AT"
_ACTIVE_SIGNER_ENV = "FINDEVIL_ACTIVE_SIGNER"
_CASE_MARKER = ".verdict-case-marker"
_FILESYSTEM_AUTHORITY_TOOLS = frozenset(
    {
        "accuracy_compare",
        "audit_append",
        "audit_verify",
        "expert_miss_capture",
        "find_ai_signatures",
        "manifest_finalize",
        "manifest_verify",
        "memory_recall",
        "memory_remember",
        "pool_handoff",
        "verify_finding",
    }
)


class CustodyPathPolicyError(ValueError):
    """A tool requested host filesystem authority outside its reservation."""


def _is_native_windows() -> bool:
    return os.name == "nt"


def _value(inp: object, name: str, default: Any = None) -> Any:
    return getattr(inp, name, default)


def _require_launcher_value(inp: object, *, field: str, environment: str, label: str) -> None:
    trusted = os.environ.get(environment, "").strip()
    if not trusted:
        raise CustodyPathPolicyError(f"{environment} is required")
    if _value(inp, field) != trusted:
        raise CustodyPathPolicyError(f"manifest {label} must equal launcher reservation")


def _absolute_lexical(path: str | os.PathLike[str], *, label: str) -> Path:
    raw = Path(path)
    if not raw.is_absolute():
        raise CustodyPathPolicyError(f"{label} must be absolute")
    if ".." in raw.parts:
        raise CustodyPathPolicyError(f"{label} contains parent traversal")
    return Path(os.path.abspath(raw))


def _reject_link_components(path: Path, *, label: str) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise CustodyPathPolicyError(f"cannot inspect {label}: {exc}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise CustodyPathPolicyError(f"{label} contains symlink component: {current}")


def _validate_file_target(
    provided: str,
    expected: Path,
    *,
    label: str,
    writable: bool,
    must_exist: bool = False,
) -> Path:
    candidate = _absolute_lexical(provided, label=label)
    expected_abs = _absolute_lexical(expected, label=f"reserved {label}")
    if candidate != expected_abs:
        raise CustodyPathPolicyError(f"{label} must equal reserved {label}: {expected_abs}")
    _reject_link_components(candidate, label=label)
    try:
        metadata = os.lstat(candidate)
    except FileNotFoundError:
        if must_exist:
            raise CustodyPathPolicyError(f"{label} does not exist: {candidate}") from None
        return candidate
    if not stat.S_ISREG(metadata.st_mode):
        raise CustodyPathPolicyError(f"{label} is not a regular file: {candidate}")
    if writable and metadata.st_nlink != 1:
        raise CustodyPathPolicyError(f"{label} is hard-linked: {candidate}")
    return candidate


def _reserved_case_dir() -> Path:
    value = os.environ.get(_ACTIVE_CASE_ENV, "").strip()
    if not value:
        raise CustodyPathPolicyError(f"{_ACTIVE_CASE_ENV} is required")
    case_dir = _absolute_lexical(value, label="reserved case directory")
    _reject_link_components(case_dir, label="reserved case directory")
    try:
        metadata = os.lstat(case_dir)
    except OSError as exc:
        raise CustodyPathPolicyError(f"reserved case directory unavailable: {exc}") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise CustodyPathPolicyError("reserved case path is not a directory")
    if os.name != "nt":
        if metadata.st_uid != os.geteuid():
            raise CustodyPathPolicyError("reserved case directory is not owned by this user")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise CustodyPathPolicyError("reserved case directory is not owner-private")
    marker = case_dir / _CASE_MARKER
    _validate_file_target(
        str(marker), marker, label="case ownership marker", writable=False, must_exist=True
    )
    if os.name != "nt":
        marker_metadata = os.lstat(marker)
        if marker_metadata.st_uid != os.geteuid():
            raise CustodyPathPolicyError("case ownership marker is not owned by this user")
        if stat.S_IMODE(marker_metadata.st_mode) & 0o077:
            raise CustodyPathPolicyError("case ownership marker is not owner-private")
    return case_dir


def _fixed_memory_store() -> Path:
    explicit = os.environ.get("FINDEVIL_MEMORY_STORE", "").strip()
    if explicit:
        return _absolute_lexical(explicit, label="reserved memory store")
    home = os.environ.get("FINDEVIL_HOME", "").strip()
    if not home:
        raise CustodyPathPolicyError(
            "FINDEVIL_MEMORY_STORE or FINDEVIL_HOME is required for reserved custody"
        )
    return _absolute_lexical(Path(home) / "memory" / "memory.sqlite", label="reserved memory store")


def _fixed_expert_ledger() -> Path:
    value = os.environ.get("FINDEVIL_EXPERT_MISS_LEDGER", "").strip()
    if not value:
        raise CustodyPathPolicyError("FINDEVIL_EXPERT_MISS_LEDGER is required for reserved custody")
    return _absolute_lexical(value, label="reserved expert miss ledger")


def _validate_case_read(path: str, case_dir: Path, *, label: str) -> None:
    candidate = _absolute_lexical(path, label=label)
    try:
        candidate.relative_to(case_dir)
    except ValueError as exc:
        raise CustodyPathPolicyError(f"{label} is outside reserved case") from exc
    _reject_link_components(candidate, label=label)
    try:
        metadata = os.lstat(candidate)
    except OSError as exc:
        raise CustodyPathPolicyError(f"{label} is unavailable: {exc}") from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise CustodyPathPolicyError(f"{label} must be one regular, unlinked case file")


def enforce_tool_path_policy(tool_name: str, inp: object) -> None:
    """Validate a tool's filesystem authority before its handler executes."""
    if os.environ.get(_BOUNDARY_ENV, "").strip() != _BOUNDARY_VALUE:
        if tool_name in _FILESYSTEM_AUTHORITY_TOOLS:
            raise CustodyPathPolicyError(
                f"{tool_name} requires a launcher reservation; "
                f"set {_BOUNDARY_ENV}={_BOUNDARY_VALUE} through scripts/verdict"
            )
        return
    if _is_native_windows():
        raise CustodyPathPolicyError(
            "native Windows custody is disabled until private DACLs and an "
            "interprocess audit lock can be verified; run VERDICT in WSL2 or Docker"
        )

    case_dir = _reserved_case_dir()
    audit = case_dir / "audit.jsonl"
    manifest = case_dir / "run.manifest.json"

    if tool_name in {"audit_append", "audit_verify"}:
        _validate_file_target(
            str(_value(inp, "path")),
            audit,
            label="audit path",
            writable=tool_name == "audit_append",
        )
    elif tool_name == "pool_handoff":
        _validate_file_target(
            str(_value(inp, "audit_path")),
            audit,
            label="audit path",
            writable=True,
        )
    elif tool_name == "manifest_finalize":
        _validate_file_target(
            str(_value(inp, "audit_log_path")),
            audit,
            label="audit path",
            writable=False,
            must_exist=True,
        )
        _validate_file_target(
            str(_value(inp, "output_path")),
            manifest,
            label="manifest output",
            writable=True,
        )
        _require_launcher_value(
            inp, field="case_id", environment=_ACTIVE_CASE_ID_ENV, label="case ID"
        )
        _require_launcher_value(inp, field="run_id", environment=_ACTIVE_RUN_ID_ENV, label="run ID")
        _require_launcher_value(
            inp,
            field="started_at",
            environment=_ACTIVE_STARTED_AT_ENV,
            label="start time",
        )
        _require_launcher_value(inp, field="signer", environment=_ACTIVE_SIGNER_ENV, label="signer")
    elif tool_name == "manifest_verify":
        _validate_file_target(
            str(_value(inp, "manifest_path")),
            manifest,
            label="manifest path",
            writable=False,
            must_exist=True,
        )
        audit_value = _value(inp, "audit_log_path")
        if audit_value is None:
            raise CustodyPathPolicyError("manifest verification requires reserved audit path")
        _validate_file_target(
            str(audit_value),
            audit,
            label="audit path",
            writable=False,
            must_exist=True,
        )
    elif tool_name == "memory_remember":
        _validate_file_target(
            str(_value(inp, "store_path")),
            _fixed_memory_store(),
            label="memory store",
            writable=True,
        )
        _require_launcher_value(
            inp, field="case_id", environment=_ACTIVE_CASE_ID_ENV, label="case ID"
        )
        audit_value = _value(inp, "audit_log_path")
        if audit_value is None:
            raise CustodyPathPolicyError("memory_remember requires the reserved audit path")
        _validate_file_target(str(audit_value), audit, label="audit path", writable=True)
        case_path = _value(inp, "case_path")
        if case_path is not None:
            requested_case = _absolute_lexical(str(case_path), label="case path")
            if requested_case != case_dir:
                raise CustodyPathPolicyError("case path must equal reserved case path")
            _reject_link_components(requested_case, label="case path")
    elif tool_name == "memory_recall":
        _validate_file_target(
            str(_value(inp, "store_path")),
            _fixed_memory_store(),
            label="memory store",
            writable=True,
        )
        audit_value = _value(inp, "audit_log_path")
        if audit_value is not None:
            _validate_file_target(str(audit_value), audit, label="audit path", writable=True)
    elif tool_name == "expert_miss_capture":
        _validate_file_target(
            str(_value(inp, "ledger_path")),
            _fixed_expert_ledger(),
            label="expert miss ledger",
            writable=True,
        )
        _require_launcher_value(
            inp, field="case_id", environment=_ACTIVE_CASE_ID_ENV, label="case ID"
        )
    elif tool_name == "accuracy_compare":
        requested_case = _absolute_lexical(
            str(_value(inp, "case_dir")), label="accuracy case directory"
        )
        if requested_case != case_dir:
            raise CustodyPathPolicyError("accuracy case directory is outside reserved case")
        golden = _value(inp, "golden_path")
        if golden is not None:
            repo_goldens = Path(__file__).resolve().parents[3] / "goldens"
            _validate_case_read(str(golden), repo_goldens, label="golden path")
        audit_value = _value(inp, "audit_log_path")
        if audit_value is not None:
            _validate_file_target(str(audit_value), audit, label="audit path", writable=True)
        coverage = _value(inp, "coverage_manifest_path")
        if coverage is not None:
            _validate_file_target(
                str(coverage),
                case_dir / "coverage_manifest.json",
                label="coverage manifest path",
                writable=False,
                must_exist=True,
            )
    elif tool_name == "find_ai_signatures":
        for index, path in enumerate(_value(inp, "paths", ())):
            _validate_case_read(str(path), case_dir, label=f"signature path[{index}]")


__all__ = [
    "CustodyPathPolicyError",
    "enforce_tool_path_policy",
]
