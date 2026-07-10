"""``verify_finding`` tool — re-run a Finding's cited tool call.

Wraps :func:`findevil_agent.verifier.reverify_finding`. The wrapper
spawns its own short-lived stdio connection to ``findevil-mcp`` (the
Rust DFIR tool server) so the re-execution path is byte-for-byte
identical to what the original agent saw — same binary, same args,
same SHA-256.

Returns the verifier action ('approved' / 'rejected' / 'downgraded')
plus a replay record describing the comparison.

The Rust binary is spawned as a child process for each call. That's
not the cheapest possible path, but it's the cleanest — the
verifier is intentionally a deliberation step (Spec #2 §8.1 budgets
30s/finding), not a hot loop, and a fresh subprocess avoids any
state leak between findings.
"""

from __future__ import annotations

import contextlib
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from findevil_agent.events import Finding
from findevil_agent.mcp_client import McpClient, StdioMcpClient
from findevil_agent.replay import ReplayArtifact
from findevil_agent.verifier import reverify_finding
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from findevil_agent_mcp.tools._base import ToolSpec
from findevil_agent_mcp.tools._input_limits import (
    MAX_TOOL_CALL_INDEX_ENTRIES,
    enforce_json_budget,
)


class VerifyFindingInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    finding: dict[str, Any] = Field(
        ...,
        description=(
            "The Finding to re-verify, as a dict matching the Finding "
            "AgentEvent schema (case_id, finding_id, tool_call_id, "
            "artifact_path, confidence, description, etc.). A CONFIRMED/"
            "INFERRED finding SHOULD carry asserted_values "
            "[{path, expected, match, count?}] — the structured fact(s) it "
            "claims; after the cited output reproduces, the verifier re-extracts "
            "each from that output (entailment check) and rejects a misread. A "
            "wrong hard IDENTITY anchor (hash/IP) is rejected outright; a count "
            "claim (set count>1) backed by fewer entailed lines is demoted."
        ),
    )
    tool_call_index: dict[str, dict[str, Any]] = Field(
        ...,
        max_length=MAX_TOOL_CALL_INDEX_ENTRIES,
        description=(
            "Map tool_call_id -> {tool_name, arguments, output_sha256} "
            "from the audit log. The verifier looks up the cited "
            "tool_call_id here, then re-runs that exact call."
        ),
    )
    force_fresh_replay: bool = Field(
        default=False,
        description="Bypass replay cache when a caller supplies pooled verifier execution.",
    )
    downgrade_on_drift: bool = Field(
        default=False,
        description=(
            "Terminal drift policy. False (first pass): sha256 drift on a "
            "CONFIRMED finding is rejected so the orchestrator re-dispatches "
            "once with a fresh replay. True (the re-dispatch attempt): "
            "persistent drift takes the terminal downgrade."
        ),
    )

    @model_validator(mode="before")
    @classmethod
    def _enforce_input_budget(cls, value: Any) -> Any:
        return enforce_json_budget(value, label="verify_finding")


class VerifyFindingOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    action: str = Field(..., description="'approved', 'rejected', or 'downgraded'.")
    finding_id: str
    reason: str
    replay_tool_name: str | None
    replay_expected_sha256: str | None
    replay_actual_sha256: str | None
    replay_matched: bool | None
    replay_error: str | None
    replay_artifact: ReplayArtifact | None = Field(
        default=None,
        description="Structured replay artifact. Legacy top-level replay_* fields are preserved.",
    )


# Replay re-runs the finding's cited tool, which may be a slow memory plugin
# (vol_malfind on a multi-GB image runs for many minutes — the main
# investigation budgets it 1800s). The StdioMcpClient default request timeout
# is 120s, which falsely rejected legitimate slow-tool findings with an "MCP
# request timed out after 120.0s" replay error. Match the main run's slowest
# budget so verification rejects on real drift, not on a too-short clock. The
# timeout is a ceiling, so fast tools still return immediately.
_REPLAY_TIMEOUT_S = 1800.0

# Explicit capability boundary for the verifier's Rust child. Replay is allowed
# only for parsers/enumerators whose contract is read-only and does not create
# mounts, cases, extracted output, or live collections. The caller-provided
# citation map selects within this set; it can never turn verify_finding into a
# deputy for lifecycle or state-changing tools.
_REPLAY_SAFE_TOOLS = frozenset(
    {
        "ausearch",
        "bits_parse",
        "browser_history",
        "bulk_extract",
        "cloud_audit",
        "email_parse",
        "evtx_query",
        "ez_parse",
        "exif_parse",
        "hashset_lookup",
        "hayabusa_scan",
        "indx_parse",
        "journalctl_query",
        "login_accounting",
        "mft_timeline",
        "nfdump_query",
        "oe_dbx_parse",
        "pcap_triage",
        "plaso_parse",
        "prefetch_parse",
        "pst_parse",
        "registry_query",
        "setupapi_parse",
        "srum_parse",
        "suricata_eve",
        "sysmon_network_query",
        "thumbcache_parse",
        "usnjrnl_query",
        "vol_malfind",
        "vol_pslist",
        "vol_psscan",
        "vol_psxview",
        "vol_run",
        "vss_list",
        "wmi_persist_parse",
        "yara_scan",
        "zeek_summary",
    }
)

_REPLAY_ENV_NAMES = (
    "HOME",
    "USER",
    "USERPROFILE",
    "PATH",
    "LANG",
    "LC_ALL",
    "TZ",
    "TMPDIR",
    "TMP",
    "TEMP",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    "XDG_CACHE_HOME",
    "CARGO_HOME",
    "RUSTUP_HOME",
    "FINDEVIL_HOME",
    "FINDEVIL_INJECTION_LEDGER",
    "FINDEVIL_OUTPUT_ROUTE",
    "FINDEVIL_ACKNOWLEDGE_PARSED_EVIDENCE_EGRESS",
    "FINDEVIL_CASE_OPEN_BINDING",
    "FINDEVIL_BROWSER_CASE_BINDING",
    "FINDEVIL_BROWSER_DB_MAX_BYTES",
    "FINDEVIL_BROWSER_FIELD_MAX_BYTES",
    "FINDEVIL_BROWSER_SQLITE_MAX_OPS",
    "FINDEVIL_BROWSER_OUTPUT_MAX_BYTES",
    "FINDEVIL_BROWSER_SQLITE_HEAP_MAX_BYTES",
    "FINDEVIL_BROWSER_SCHEMA_MAX_ENTRIES",
    "FINDEVIL_CLOUD_AUDIT_MAX_INPUT_BYTES",
    "FINDEVIL_CLOUD_AUDIT_MAX_OUTPUT_BYTES",
    "FINDEVIL_CLOUD_AUDIT_MAX_RECORD_BYTES",
    "FINDEVIL_PCAP_TIMEOUT_SECS",
    "FINDEVIL_PLASO_TIMEOUT_SECS",
    "FINDEVIL_SUBPROCESS_STDERR_MAX_BYTES",
    "FINDEVIL_SUBPROCESS_STDOUT_MAX_BYTES",
    "FINDEVIL_VOL_TIMEOUT_SECS",
    "FINDEVIL_AUSEARCH_TIMEOUT_SECS",
    "FINDEVIL_JOURNALCTL_TIMEOUT_SECS",
    "FINDEVIL_LOGIN_ACCOUNTING_TIMEOUT_SECS",
    "FINDEVIL_NFDUMP_TIMEOUT_SECS",
    "FINDEVIL_INDX_TIMEOUT_SECS",
    "FINDEVIL_EZ_PARSE_TIMEOUT_SECS",
    "FINDEVIL_SURICATA_TIMEOUT_SECS",
    "FINDEVIL_PST_TIMEOUT_SECS",
    "FINDEVIL_SRUM_TIMEOUT_SECS",
    "FINDEVIL_BULK_EXTRACT_TIMEOUT_SECS",
    "FINDEVIL_HAYABUSA_TIMEOUT_SECS",
    "FINDEVIL_HAYABUSA_OUTPUT_MAX_BYTES",
    "FINDEVIL_VSS_TIMEOUT_SECS",
    "FINDEVIL_MAC_TRIAGE_TIMEOUT_SECS",
    "FIND_EVIL_MEMORY_YARA_RULES",
    "FIND_EVIL_DISK_YARA_RULES",
    "FINDEVIL_YARA_RULES_ROOT",
    "AUSEARCH_BIN",
    "CHAINSAW_BIN",
    "EWF_MOUNT_BIN",
    "EZTOOLS_DIR",
    "HAYABUSA_BIN",
    "HAYABUSA_RULES_BASE",
    "FINDEVIL_HAYABUSA_RULE_SET",
    "INDXPARSE_BIN",
    "JOURNALCTL_BIN",
    "LAST_BIN",
    "MAC_APT",
    "NFDUMP_BIN",
    "PLASO_DIR",
    "SURICATA_BIN",
    "TSHARK_BIN",
    "VOLATILITY_BIN",
    "FINDEVIL_BULK_EXTRACTOR_BIN",
    "FINDEVIL_BULK_KEYWORD_FILE",
    "FINDEVIL_ESEDBEXPORT_BIN",
    "FINDEVIL_FLS_BIN",
    "FINDEVIL_FLS_TIMEOUT_SECONDS",
    "FINDEVIL_ICAT_TIMEOUT_SECONDS",
    "FINDEVIL_MMLS_TIMEOUT_SECONDS",
    "FINDEVIL_HASHSET_DIR",
    "FINDEVIL_HASHSET_MAX_SETS",
    "FINDEVIL_HASHSET_MAX_FILE_BYTES",
    "FINDEVIL_HASHSET_MAX_TOTAL_BYTES",
    "FINDEVIL_HASHSET_MAX_LINE_BYTES",
    "FINDEVIL_HASHSET_SQLITE_MAX_OPS",
    "FINDEVIL_HASHSET_SQLITE_MAX_FIELD_BYTES",
    "FINDEVIL_HASHSET_SQLITE_HEAP_MAX_BYTES",
    "FINDEVIL_ICAT_BIN",
    "FINDEVIL_MMLS_BIN",
    "FINDEVIL_MOUNT_BIN",
    "FINDEVIL_PFFEXPORT_BIN",
    "FINDEVIL_UMOUNT_BIN",
    "FINDEVIL_VSHADOWINFO_BIN",
    "FINDEVIL_VSHADOWMOUNT_BIN",
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_TLS_VERIFY",
    "DOCKER_CERT_PATH",
)


def _replay_env() -> dict[str, str]:
    """Return the reviewed parser environment, excluding ambient secrets."""
    selected = {
        name: value for name in _REPLAY_ENV_NAMES if (value := os.environ.get(name, "").strip())
    }
    selected.setdefault("PATH", os.environ.get("PATH") or os.defpath)
    selected.setdefault("HOME", os.environ.get("HOME") or str(Path.home()))
    selected.setdefault("LANG", os.environ.get("LANG") or "C.UTF-8")
    return selected


# Indirection to let tests monkeypatch the client factory.
def _make_mcp_client() -> McpClient:
    """Build the replay client from a fixed server-side launcher.

    Process argv, cwd, and environment are deliberately absent from the public
    tool schema. The child inherits the Python MCP server's trusted case binding
    and resource limits, while the executable is resolved only inside this
    repository checkout.
    """
    repo_root = Path(__file__).resolve().parents[4]
    transport = os.environ.get("FINDEVIL_REPLAY_TRANSPORT", "").strip()
    abort_callback = None
    if transport == "docker":
        container = os.environ.get("FINDEVIL_REPLAY_DOCKER_CONTAINER", "").strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", container):
            raise RuntimeError(f"unsafe Docker replay container name: {container!r}")
        docker = shutil.which("docker") or "docker"
        replay_env_options = [
            item
            for name in (
                "FINDEVIL_OUTPUT_ROUTE",
                "FINDEVIL_ACKNOWLEDGE_PARSED_EVIDENCE_EGRESS",
                "FINDEVIL_BROWSER_CASE_BINDING",
                "FINDEVIL_BROWSER_DB_MAX_BYTES",
                "FINDEVIL_BROWSER_FIELD_MAX_BYTES",
                "FINDEVIL_BROWSER_SQLITE_MAX_OPS",
                "FINDEVIL_BROWSER_OUTPUT_MAX_BYTES",
                "FINDEVIL_BROWSER_SQLITE_HEAP_MAX_BYTES",
                "FINDEVIL_BROWSER_SCHEMA_MAX_ENTRIES",
                "FINDEVIL_CLOUD_AUDIT_MAX_INPUT_BYTES",
                "FINDEVIL_CLOUD_AUDIT_MAX_OUTPUT_BYTES",
                "FINDEVIL_CLOUD_AUDIT_MAX_RECORD_BYTES",
                "FINDEVIL_FLS_TIMEOUT_SECONDS",
                "FINDEVIL_HASHSET_DIR",
                "FINDEVIL_HASHSET_MAX_SETS",
                "FINDEVIL_HASHSET_MAX_FILE_BYTES",
                "FINDEVIL_HASHSET_MAX_TOTAL_BYTES",
                "FINDEVIL_HASHSET_MAX_LINE_BYTES",
                "FINDEVIL_HASHSET_SQLITE_MAX_OPS",
                "FINDEVIL_HASHSET_SQLITE_MAX_FIELD_BYTES",
                "FINDEVIL_HASHSET_SQLITE_HEAP_MAX_BYTES",
                "FINDEVIL_ICAT_TIMEOUT_SECONDS",
                "FINDEVIL_MMLS_TIMEOUT_SECONDS",
                "FINDEVIL_PCAP_TIMEOUT_SECS",
                "FINDEVIL_PLASO_TIMEOUT_SECS",
                "FINDEVIL_SUBPROCESS_STDERR_MAX_BYTES",
                "FINDEVIL_SUBPROCESS_STDOUT_MAX_BYTES",
                "FINDEVIL_VOL_TIMEOUT_SECS",
                "FINDEVIL_AUSEARCH_TIMEOUT_SECS",
                "FINDEVIL_JOURNALCTL_TIMEOUT_SECS",
                "FINDEVIL_LOGIN_ACCOUNTING_TIMEOUT_SECS",
                "FINDEVIL_NFDUMP_TIMEOUT_SECS",
                "FINDEVIL_INDX_TIMEOUT_SECS",
                "FINDEVIL_EZ_PARSE_TIMEOUT_SECS",
                "FINDEVIL_SURICATA_TIMEOUT_SECS",
                "FINDEVIL_PST_TIMEOUT_SECS",
                "FINDEVIL_SRUM_TIMEOUT_SECS",
                "FINDEVIL_BULK_EXTRACT_TIMEOUT_SECS",
                "FINDEVIL_HAYABUSA_TIMEOUT_SECS",
                "FINDEVIL_HAYABUSA_OUTPUT_MAX_BYTES",
                "FINDEVIL_VSS_TIMEOUT_SECS",
                "FINDEVIL_MAC_TRIAGE_TIMEOUT_SECS",
            )
            if (value := os.environ.get(name, "").strip())
            for item in ("-e", f"{name}={value}")
        ]
        command = [
            docker,
            "exec",
            "-i",
            *replay_env_options,
            container,
            "/workspace/target/release/findevil-mcp",
        ]
        child_env = _replay_env()

        def abort_docker_replay() -> None:
            with contextlib.suppress(OSError, subprocess.TimeoutExpired):
                subprocess.run(
                    [docker, "rm", "-f", container],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env=child_env,
                    timeout=10,
                    check=False,
                )

        abort_callback = abort_docker_replay
    elif transport:
        raise RuntimeError(f"unsupported verifier replay transport: {transport!r}")
    else:
        release_binary = repo_root / "target" / "release" / "findevil-mcp"
        if release_binary.is_file():
            command = [str(release_binary)]
        else:
            cargo = shutil.which("cargo") or "cargo"
            command = [
                cargo,
                "run",
                "--release",
                "-p",
                "findevil-mcp",
                "--locked",
                "--quiet",
            ]
        child_env = _replay_env()
    return StdioMcpClient(
        command,
        cwd=repo_root,
        env=child_env,
        request_timeout_s=_REPLAY_TIMEOUT_S,
        abort_callback=abort_callback,
    )


async def _handle(inp: BaseModel) -> VerifyFindingOutput:
    assert isinstance(inp, VerifyFindingInput)
    # Untrusted-input boundary: the finding dict comes from the model. A schema
    # violation here (e.g. the evidence-anchor firewall in
    # Finding._require_tool_call_id_for_anchored rejecting a blank-cited
    # CONFIRMED/INFERRED finding) is a malformed claim, not a tool fault — turn it
    # into a structured 'rejected' action so it is logged to the audit chain as a
    # veto rather than crashing the run loop. This preserves the graceful veto the
    # verifier gave for blank citations before the schema firewall existed.
    try:
        finding = Finding.model_validate(inp.finding)
    except ValidationError as exc:
        finding_id = ""
        if isinstance(inp.finding, dict):
            finding_id = str(inp.finding.get("finding_id") or "")
        return VerifyFindingOutput(
            action="rejected",
            finding_id=finding_id,
            reason=f"schema rejected before replay: {exc.errors()[0].get('msg', str(exc))}",
            replay_tool_name=None,
            replay_expected_sha256=None,
            replay_actual_sha256=None,
            replay_matched=None,
            replay_error=None,
        )
    citation = inp.tool_call_index.get(finding.tool_call_id)
    if not isinstance(citation, dict):
        return VerifyFindingOutput(
            action="rejected",
            finding_id=finding.finding_id,
            reason=f"cited tool_call_id {finding.tool_call_id!r} missing from audit index",
            replay_tool_name=None,
            replay_expected_sha256=None,
            replay_actual_sha256=None,
            replay_matched=None,
            replay_error=None,
        )
    tool_name = citation.get("tool_name")
    if not isinstance(tool_name, str) or tool_name not in _REPLAY_SAFE_TOOLS:
        return VerifyFindingOutput(
            action="rejected",
            finding_id=finding.finding_id,
            reason=f"cited tool {tool_name!r} is not replay-safe",
            replay_tool_name=tool_name if isinstance(tool_name, str) else None,
            replay_expected_sha256=None,
            replay_actual_sha256=None,
            replay_matched=None,
            replay_error=None,
        )
    client = _make_mcp_client()
    try:
        action, replay = reverify_finding(
            finding,
            mcp=client,
            tool_call_index=inp.tool_call_index,
            force_fresh=inp.force_fresh_replay,
            downgrade_on_drift=inp.downgrade_on_drift,
        )
    finally:
        client.close()

    return VerifyFindingOutput(
        action=action.action,
        finding_id=action.finding_id,
        reason=action.reason,
        replay_tool_name=replay.tool_name if replay else None,
        replay_expected_sha256=replay.expected_sha256 if replay else None,
        replay_actual_sha256=replay.actual_sha256 if replay else None,
        replay_matched=replay.matched if replay else None,
        replay_error=replay.error if replay else None,
        replay_artifact=replay.artifact if replay else None,
    )


SPEC = ToolSpec(
    name="verify_finding",
    description=(
        "M4 verifier stage — re-run the Rust DFIR tool call cited by a Finding's "
        "tool_call_id and decide approve / reject / downgrade. Run this AFTER both "
        "pools have emitted findings and BEFORE judge_findings. The verifier is the "
        "architectural guard for the 'every Finding cites a tool_call_id' invariant: "
        "rejected = no tool_call_id (Spec violation) or replay raised an MCP error; "
        "downgraded = output_sha256 drifted between original run and replay (still "
        "real evidence, just one tier less confident); approved = byte-for-byte match. "
        "Spawns a fresh findevil-mcp subprocess per call so replays are independent. "
        "tool_call_index must map every cited tool_call_id to its original "
        "{tool_name, arguments, output_sha256} from the audit log — build this index "
        "from your audit_verify pass before calling here. The replay executable, "
        "working directory, and environment are fixed server-side and are not "
        "caller-configurable."
    ),
    input_model=VerifyFindingInput,
    output_model=VerifyFindingOutput,
    handler=_handle,
)

__all__ = [
    "SPEC",
    "VerifyFindingInput",
    "VerifyFindingOutput",
    "_make_mcp_client",
]
