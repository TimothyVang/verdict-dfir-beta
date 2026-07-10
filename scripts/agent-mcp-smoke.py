#!/usr/bin/env python3
"""End-to-end smoke for the findevil-agent-mcp Python MCP server.

Two modes:

**Synthetic** (default): spawns the server as a subprocess (matching
the ``.mcp.json`` boot recipe) and drives a full investigation
through 11 of 12 MCP tools with hand-crafted Findings. This is the
demo flow under Amendment A2/A3 minus an actual disk image —
exercises the same crypto/ACH/memory/ACP paths the live demo
will. Skipped: ``verify_finding`` (needs the Rust DFIR MCP server).
The A3 additions (``memory_remember`` + ``memory_recall`` cold→warm
transition, ``pool_handoff`` IBM-ACP envelope) and the expert-miss
ledger capture are exercised in steps 4a-4g.

**Real-evidence** (``--real-evidence [<auto-run-dir>]``): replays a
real ``find-evil-auto`` case directory through the agent_mcp surface.
Loads its ``verdict.json`` + ``audit.jsonl`` + ``run.manifest.json``,
splits findings by ``pool_origin``, and pushes them through the
ACH stack (audit_verify → manifest_verify → detect_contradictions
→ judge_findings → correlate_findings). The point is regression
coverage: prove the agent_mcp tools still parse production output
shape after any schema change. ``verify_finding`` is skipped — it
needs the Rust DFIR server. If no path is given, the latest dir
under ``tmp/auto-runs/`` is used.

Usage::

    uv run --directory services/agent_mcp python ../../scripts/agent-mcp-smoke.py
    uv run --directory services/agent_mcp python ../../scripts/agent-mcp-smoke.py --real-evidence
    uv run --directory services/agent_mcp python ../../scripts/agent-mcp-smoke.py --real-evidence tmp/auto-runs/auto-<uuid>

Exit code: 0 on full success, 1 on the first assertion failure.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from queue import Empty, Queue
from typing import Any

REPO = Path(__file__).resolve().parent.parent
AGENT_MCP_DIR = REPO / "services" / "agent_mcp"
CONTROLLER_ONLY_TOOLS = frozenset(
    {
        "audit_append",
        "expert_miss_capture",
        "manifest_finalize",
        "manifest_verify",
        "memory_remember",
        "pool_handoff",
    }
)

# The fact-fidelity gate is production-default-ON (Stage A). This smoke exercises
# the audit/crypto chain over hand-crafted synthetic Findings, not the gate, so
# disable it here — also propagated to the spawned MCP server via os.environ.copy().
os.environ.setdefault("FIND_EVIL_REQUIRE_ASSERTED_VALUES", "0")


def fatal(msg: str) -> None:
    print(f"\n[FAIL] {msg}", file=sys.stderr)
    sys.exit(1)


def log(msg: str) -> None:
    print(f"  {msg}")


# ---------------------------------------------------------------------------
# Stdio JSON-RPC harness — line-delimited JSON, NOT LSP framing.
# ---------------------------------------------------------------------------


class StdioClient:
    def __init__(
        self,
        cmd: list[str],
        *,
        env_overrides: dict[str, str],
        controller_capability: str,
    ) -> None:
        env = os.environ.copy()
        env.update(env_overrides)
        env["PYTHONUNBUFFERED"] = "1"
        env["FINDEVIL_LOG_LEVEL"] = "WARNING"
        self._controller_capability = controller_capability
        self.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        self._next_id = 1
        self._queue: Queue[str | None] = Queue()
        self._t = threading.Thread(target=self._reader, daemon=True)
        self._t.start()

    def _reader(self) -> None:
        try:
            assert self.proc.stdout is not None
            for line in iter(self.proc.stdout.readline, ""):
                if not line:
                    break
                self._queue.put(line)
        finally:
            self._queue.put(None)

    def send(self, message: dict[str, Any]) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
        self.proc.stdin.flush()

    def read(self, timeout_s: float = 30.0) -> dict[str, Any]:
        deadline = time.monotonic() + timeout_s
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("read timed out")
            try:
                line = self._queue.get(timeout=remaining)
            except Empty:
                continue
            if line is None:
                raise RuntimeError("server closed stdout")
            line = line.strip()
            if not line:
                continue
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue

    def call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        msg_id = self._next_id
        self._next_id += 1
        self.send(
            {
                "jsonrpc": "2.0",
                "id": msg_id,
                "method": method,
                "params": params or {},
            }
        )
        resp = self.read()
        if resp.get("id") != msg_id:
            fatal(f"id mismatch: sent {msg_id}, got {resp.get('id')}")
        if "error" in resp:
            fatal(f"server error on {method}: {resp['error']}")
        return resp["result"]

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        authorized_arguments = dict(arguments)
        if name in CONTROLLER_ONLY_TOOLS:
            authorized_arguments["_controller_capability"] = self._controller_capability
        result = self.call(
            "tools/call", {"name": name, "arguments": authorized_arguments}
        )
        content = result.get("content") or []
        if not content:
            fatal(f"empty content from {name}")
        raw_text = content[0].get("text")
        try:
            body = json.loads(raw_text)
        except (TypeError, json.JSONDecodeError) as exc:
            fatal(f"{name} returned non-JSON content {raw_text!r}: {exc}")
        if (
            isinstance(body, dict)
            and "error" in body
            and isinstance(body["error"], dict)
        ):
            fatal(f"{name} returned error: {body['error']}")
        return body

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        self.send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def close(self) -> None:
        if self.proc.stdin is not None and not self.proc.stdin.closed:
            self.proc.stdin.close()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


# ---------------------------------------------------------------------------
# The smoke flow.
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _prepare_reservation(
    case_dir: Path,
    *,
    case_id: str,
    run_id: str,
    started_at: str,
    signer: str,
    controller_capability: str,
) -> dict[str, str]:
    """Create a private smoke Case and its launcher-owned custody contract."""
    case_dir.mkdir(parents=True, exist_ok=True)
    case_dir.chmod(0o700)
    marker = case_dir / ".verdict-case-marker"
    marker.write_text(case_id + "\n", encoding="utf-8")
    marker.chmod(0o600)
    return {
        "FINDEVIL_CUSTODY_BOUNDARY": "reserved_case",
        "FINDEVIL_ACTIVE_CASE_DIR": str(case_dir),
        "FINDEVIL_ACTIVE_CASE_ID": case_id,
        "FINDEVIL_ACTIVE_RUN_ID": run_id,
        "FINDEVIL_ACTIVE_STARTED_AT": started_at,
        "FINDEVIL_ACTIVE_SIGNER": signer,
        "FINDEVIL_CONTROLLER_CAPABILITY": controller_capability,
        "FINDEVIL_MEMORY_STORE": str(case_dir / "memory.sqlite"),
        "FINDEVIL_EXPERT_MISS_LEDGER": str(case_dir / "expert_misses.jsonl"),
        "FINDEVIL_ALLOW_STUB_SIGNER": "1",
        "FINDEVIL_OUTPUT_ROUTE": "local_controller",
    }


def _finding(
    *,
    case_id: str,
    finding_id: str,
    tool_call_id: str,
    artifact: str,
    description: str,
    confidence: str,
    pool: str,
    mitre: str | None = None,
) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "finding_id": finding_id,
        "tool_call_id": tool_call_id,
        "artifact_path": artifact,
        "confidence": confidence,
        "description": description,
        "mitre_technique": mitre,
        "pool_origin": pool,
    }


def _verifier_actions(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    for finding in findings:
        action = str(finding.get("verifier_action") or "approved")
        actions.append(
            {
                "case_id": str(finding.get("case_id") or "smoke-case"),
                "finding_id": str(finding["finding_id"]),
                "action": action,
                "reason": "smoke verifier action supplied before judge_findings",
            }
        )
    return actions


def latest_auto_run() -> Path | None:
    base = REPO / "tmp" / "auto-runs"
    if not base.is_dir():
        return None
    candidates = sorted(
        (p for p in base.glob("auto-*") if (p / "verdict.json").is_file()),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def _resolve_real_case_dir(requested: str) -> Path:
    if requested == "<latest>":
        latest = latest_auto_run()
        if latest is None:
            fatal(
                "no auto-run dir found under tmp/auto-runs/ — "
                "run scripts/find-evil-auto first"
            )
        return latest
    raw = Path(requested)
    candidates = (raw,) if raw.is_absolute() else (REPO / raw, raw)
    for candidate in candidates:
        if candidate.is_dir():
            return candidate.resolve()
    fatal(
        f"--real-evidence path is not a directory: {requested} "
        f"(also tried {REPO / raw})"
    )
    raise AssertionError("fatal() does not return")


def _copy_real_case_for_replay(source: Path, destination: Path) -> str:
    """Copy only signed replay inputs so the source Case stays untouched."""
    required_names = ("audit.jsonl", "run.manifest.json", "verdict.json")
    for name in required_names:
        source_file = source / name
        if not source_file.is_file():
            fatal(f"missing required file in case_dir: {source_file}")
    verdict = json.loads((source / "verdict.json").read_text(encoding="utf-8"))
    case_id = str(verdict.get("case_id") or f"real-replay-{uuid.uuid4()}")
    destination.mkdir(parents=True, exist_ok=True)
    for name in required_names:
        target = destination / name
        shutil.copyfile(source / name, target)
        target.chmod(0o600)
    return case_id


def real_evidence_flow(client: StdioClient, case_dir: Path) -> int:
    """Drive the agent_mcp surface against a real find-evil-auto case dir.

    Skips verify_finding (needs Rust DFIR server) — demonstrated in
    the synthetic flow's siblings.
    """
    audit_path = case_dir / "audit.jsonl"
    manifest_path = case_dir / "run.manifest.json"
    verdict_path = case_dir / "verdict.json"
    for required in (audit_path, manifest_path, verdict_path):
        if not required.is_file():
            fatal(f"missing required file in case_dir: {required}")

    verdict = json.loads(verdict_path.read_text(encoding="utf-8"))
    findings = verdict.get("findings", [])
    case_id = verdict.get("case_id") or "real-evidence-case"
    log(f"loaded {len(findings)} findings from {verdict_path}")
    log(f"  case_id      = {case_id}")
    log(f"  verdict      = {verdict.get('verdict')}")
    log(f"  evidence     = {verdict.get('evidence_path')}")

    # ---- 1. audit_verify on the recorded chain ------------------------
    log("audit_verify: replay the recorded chain...")
    av = client.call_tool("audit_verify", {"path": str(audit_path)})
    if not av["ok"]:
        fatal(f"recorded audit chain did NOT verify: {av}")
    log(f"  -> chain verifies, {av['record_count']} records")

    # ---- 2. manifest_verify on the recorded manifest ------------------
    # The manifest's signed `audit_log_path` can name the path as seen by the
    # original transport. Verify the copied chain through the explicit replay
    # override; never rewrite the signed manifest body.
    log("manifest_verify: replay the recorded manifest...")
    loaded = json.loads(manifest_path.read_text(encoding="utf-8"))
    saved_audit_log_path = loaded.get("audit_log_path")
    mv = client.call_tool(
        "manifest_verify",
        {
            "manifest_path": str(manifest_path),
            "audit_log_path": str(audit_path),
        },
    )

    if not mv["overall"]:
        fatal(f"recorded manifest did NOT verify against the replay copy: {mv}")
    log(
        "  -> overall=True  audit_chain={a}  merkle={m}  sig_present={s} "
        "(signed audit_log_path={orig!r}; verified through replay override)".format(
            a=mv["audit_chain_ok"],
            m=mv["merkle_root_ok"],
            s=mv["signature_present"],
            orig=saved_audit_log_path,
        )
    )

    # ---- 3. split findings by pool_origin -----------------------------
    pool_a = [f for f in findings if f.get("pool_origin") == "A"]
    pool_b = [f for f in findings if f.get("pool_origin") == "B"]
    if not (pool_a or pool_b):
        log("no pool-tagged findings — synthesizing by index for A/B split")
        # detect_contradictions / judge_findings still need *some* split;
        # spread findings round-robin across pools so the shape assertions
        # exercise both branches.
        for i, f in enumerate(findings):
            (pool_a if i % 2 == 0 else pool_b).append(f)

    log(f"split: pool_a={len(pool_a)}  pool_b={len(pool_b)}")

    # ---- 4. detect_contradictions -------------------------------------
    log("detect_contradictions: replay against real findings...")
    cs = client.call_tool(
        "detect_contradictions",
        {
            "case_id": case_id,
            "pool_a": pool_a,
            "pool_b": pool_b,
            "resolution_required": False,
        },
    )
    if cs["pool_a_count"] != len(pool_a) or cs["pool_b_count"] != len(pool_b):
        fatal(f"pool counts mismatch: {cs}")
    log(f"  -> {len(cs['contradictions'])} contradictions surfaced")

    # ---- 5. judge_findings --------------------------------------------
    log("judge_findings: replay against real findings...")
    j = client.call_tool(
        "judge_findings",
        {
            "pool_a_findings": pool_a,
            "pool_b_findings": pool_b,
            "pool_a_verifier_actions": _verifier_actions(pool_a),
            "pool_b_verifier_actions": _verifier_actions(pool_b),
        },
    )
    if "merged" not in j:
        fatal(f"judge response missing 'merged' key: {j}")
    log(
        f"  -> {len(j['merged'])} merged findings (budget_exceeded={j['budget_exceeded']})"
    )

    # ---- 6. correlate_findings ----------------------------------------
    log("correlate_findings: replay against real findings...")
    merged_only = [m["finding"] for m in j["merged"]]
    if merged_only:
        c = client.call_tool("correlate_findings", {"findings": merged_only})
        kept = sum(1 for o in c["outcomes"] if o["action"] == "kept")
        downgraded = sum(1 for o in c["outcomes"] if o["action"] == "downgraded")
        log(f"  -> {kept} kept, {downgraded} downgraded by SOUL.md rules")
    else:
        log("  -> skipped (judge produced no merged findings)")

    print()
    print("=" * 60)
    print("OK — agent_mcp surface still parses real production output.")
    print(f"  case_dir       : {case_dir}")
    print(f"  case_id        : {case_id}")
    print(f"  audit records  : {av['record_count']}")
    print(f"  findings       : {len(findings)} ({len(pool_a)} A + {len(pool_b)} B)")
    print(f"  contradictions : {len(cs['contradictions'])}")
    print(f"  merged         : {len(j['merged'])}")
    print("=" * 60)
    return 0


def synthetic_flow(
    client: StdioClient,
    *,
    case_id: str,
    run_id: str,
    workdir: Path,
    started_at: str,
) -> int:
    audit_path = workdir / "audit.jsonl"
    manifest_path = workdir / "run.manifest.json"

    try:
        # ---- 1. audit_append a representative tool-call sequence -------
        # (initialize + tools/list happened in main() before dispatch.)
        log("audit_append: chaining representative parser records...")
        records = [
            (
                "agent_message",
                {"role": "supervisor", "content": "starting investigation"},
            ),
            ("tool_call_start", {"tool_call_id": "tc-1", "tool": "case_open"}),
            ("tool_call_output", {"tool_call_id": "tc-1", "output_hash": "a" * 64}),
            ("tool_call_start", {"tool_call_id": "tc-2", "tool": "evtx_query"}),
            (
                "tool_call_output",
                {"tool_call_id": "tc-2", "output_hash": "b" * 64, "row_count": 42},
            ),
            ("tool_call_start", {"tool_call_id": "tc-3", "tool": "prefetch_parse"}),
            ("tool_call_output", {"tool_call_id": "tc-3", "output_hash": "c" * 64}),
            ("tool_call_start", {"tool_call_id": "tc-4", "tool": "mft_timeline"}),
            ("tool_call_output", {"tool_call_id": "tc-4", "output_hash": "d" * 64}),
        ]
        for kind, payload in records:
            client.call_tool(
                "audit_append",
                {"path": str(audit_path), "kind": kind, "payload": payload},
            )

        # ---- 4. audit_verify replay ------------------------------------
        log("audit_verify: replay the chain...")
        v = client.call_tool("audit_verify", {"path": str(audit_path)})
        if not (v["ok"] and v["record_count"] == len(records)):
            fatal(f"audit chain replay failed: {v}")
        log(f"  -> chain verifies, {v['record_count']} records")

        # ---- 4a. verifier replay + pool handoff (IBM-ACP, A3 §2.3) ----
        # Exercise the same controller-authenticated prerequisites that the
        # production manifest workflow requires for every approved Finding.
        log("verifier replay + handoff: authenticate both Findings...")
        for finding_id, replay_sha in (("f-A-1", "a" * 64), ("f-B-1", "b" * 64)):
            client.call_tool(
                "audit_append",
                {
                    "path": str(audit_path),
                    "kind": "verifier_action",
                    "payload": {
                        "finding_id": finding_id,
                        "action": "approved",
                        "replay_matched": True,
                        "replay_artifact": {"entailment": {"passed": True}},
                    },
                },
            )
            ph = client.call_tool(
                "pool_handoff",
                {
                    "audit_path": str(audit_path),
                    "from_role": "verifier",
                    "to_role": "judge",
                    "correlation_id": finding_id,
                    "payload": {
                        "finding_id": finding_id,
                        "action": "approved",
                        "replay_record_sha256": replay_sha,
                    },
                },
            )
            if (
                ph["acp_version"] != "1.0"
                or ph["from_role"] != "verifier"
                or ph["correlation_id"] != finding_id
            ):
                fatal(f"pool_handoff returned unexpected envelope: {ph}")

        for finding_id, tool_call_id, confidence in (
            ("f-A-1", "tc-2", "CONFIRMED"),
            ("f-B-1", "tc-3", "INFERRED"),
        ):
            client.call_tool(
                "audit_append",
                {
                    "path": str(audit_path),
                    "kind": "finding_approved",
                    "payload": {
                        "finding_id": finding_id,
                        "tool_call_id": tool_call_id,
                        "confidence": confidence,
                    },
                },
            )
        log("  -> 2 verifier actions, 2 handoffs, 2 approved Findings")

        # ---- 4b. audit_verify (post-handoff): chain still verifies ---
        # Proves kind="acp_handoff" doesn't break the prev_hash chain.
        log(
            "audit_verify (post-handoff): chain still verifies with acp_handoff line..."
        )
        v_post = client.call_tool("audit_verify", {"path": str(audit_path)})
        expected_post_records = len(records) + 6
        if not (v_post["ok"] and v_post["record_count"] == expected_post_records):
            fatal(f"audit chain replay failed after acp_handoff: {v_post}")
        log(f"  -> chain verifies, {v_post['record_count']} records")

        # ---- 4c. memory_recall (cold): empty store returns no hits ---
        # Demonstrates the cold-start case Pool A/B sees on the first
        # investigation against a fresh memory store.
        memory_path = workdir / "memory.sqlite"
        log("memory_recall (cold): empty store returns no hits...")
        rc_cold = client.call_tool(
            "memory_recall",
            {"store_path": str(memory_path), "query": "evil.example.com", "limit": 5},
        )
        if rc_cold["hits"]:
            fatal(f"cold recall expected 0 hits, got {len(rc_cold['hits'])}: {rc_cold}")
        log("  -> 0 hits (expected on first run)")

        # ---- 4d. memory_remember: seed an IOC the next case should see ---
        log("memory_remember: seed a Pool B IOC (A3 §2.2)...")
        mr = client.call_tool(
            "memory_remember",
            {
                "store_path": str(memory_path),
                "case_id": case_id,
                "kind": "ioc",
                "key": "evil.example.com",
                "value": "evil.example.com C2 from Pool B exfil finding",
                "sha256": "sha256:" + "f" * 64,
                "case_path": str(workdir),
                "audit_log_path": str(audit_path),
            },
        )
        if mr["case_id"] != case_id or mr["kind"] != "ioc":
            fatal(f"memory_remember returned unexpected echo: {mr}")
        log(
            f"  -> remembered case_id={mr['case_id'][:12]}... kind={mr['kind']} key={mr['key']!r}"
        )

        # ---- 4e. memory_recall (warm): same key now returns the hit ---
        # The cold/warm transition is what makes this a "cross-case
        # memory" tool — a future case investigating evil.example.com
        # gets this hit back as prior context. Memory recall is
        # context only; it does NOT count toward the SOUL.md
        # ≥2-artifact-class corroboration rule.
        log("memory_recall (warm): expect 1 hit with confidence > 0...")
        rc_warm = client.call_tool(
            "memory_recall",
            {"store_path": str(memory_path), "query": "evil.example.com", "limit": 5},
        )
        if len(rc_warm["hits"]) != 1:
            fatal(f"warm recall expected 1 hit, got {len(rc_warm['hits'])}: {rc_warm}")
        hit = rc_warm["hits"][0]
        if hit["case_id"] != case_id or hit["kind"] != "ioc" or hit["confidence"] <= 0:
            fatal(f"warm recall hit shape unexpected: {hit}")
        log(
            f"  -> hit case_id={hit['case_id'][:12]}... kind={hit['kind']} "
            f"confidence={hit['confidence']:.3f}"
        )

        # ---- 4f. memory_recall (kind-filtered): only the wrong kind --
        # Proves the optional kind filter actually filters. We seeded
        # an "ioc"; ask for "hash" — should be empty.
        log("memory_recall (kind=hash): expect 0 hits (we seeded only ioc)...")
        rc_kf = client.call_tool(
            "memory_recall",
            {
                "store_path": str(memory_path),
                "query": "evil.example.com",
                "kind": "hash",
            },
        )
        if rc_kf["hits"]:
            fatal(f"kind-filtered recall expected 0 hits, got {len(rc_kf['hits'])}")
        log("  -> 0 hits (kind filter correctly excluded the ioc seed)")

        # ---- 4g. expert_miss_capture: expert correction ledger -------
        miss_ledger = workdir / "expert_misses.jsonl"
        log("expert_miss_capture: record one expert correction...")
        miss = client.call_tool(
            "expert_miss_capture",
            {
                "case_id": case_id,
                "finding_id": "f-A-1",
                "edit_type": "qa",
                "edit_text": "Expert requested a stronger replay caveat before release.",
                "expert_name": "smoke-test",
                "ledger_path": str(miss_ledger),
            },
        )
        if miss["seq"] != 0 or not miss["line_hash"] or miss["github_issue_url"]:
            fatal(f"expert_miss_capture returned unexpected payload: {miss}")
        miss_lines = [
            line
            for line in miss_ledger.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        persisted_hash = (
            hashlib.sha256(miss_lines[0].encode("utf-8")).hexdigest()
            if len(miss_lines) == 1
            else None
        )
        if persisted_hash != miss["line_hash"]:
            fatal(
                "expert miss ledger did not persist the returned hash: "
                f"expected={miss['line_hash']!r}, actual={persisted_hash!r}"
            )
        log(f"  -> ledger verifies, line_hash={miss['line_hash'][:12]}...")

        # ---- 5. detect_contradictions ----------------------------------
        log("detect_contradictions: Pool A persistence vs Pool B exfil...")
        a_findings = [
            _finding(
                case_id=case_id,
                finding_id="f-A-1",
                tool_call_id="tc-2",
                artifact="C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
                description="Type 10 RDP logon at 02:14 UTC from external IP",
                confidence="CONFIRMED",
                pool="A",
                mitre="T1078",
            ),
            _finding(
                case_id=case_id,
                finding_id="f-A-2",
                tool_call_id="tc-3",
                artifact="C:\\Windows\\Prefetch\\STAGER.EXE-D269B812.pf",
                description="Prefetch shows STAGER.EXE ran 3 times, last 03:08 UTC",
                confidence="CONFIRMED",
                pool="A",
                mitre="T1547.001",
            ),
        ]
        b_findings = [
            _finding(
                case_id=case_id,
                finding_id="f-B-1",
                tool_call_id="tc-2",
                artifact="C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
                description="Possible RDP brute-force; not a successful logon",
                confidence="HYPOTHESIS",
                pool="B",
                mitre="T1110.001",
            ),
        ]
        cs = client.call_tool(
            "detect_contradictions",
            {
                "case_id": case_id,
                "pool_a": a_findings,
                "pool_b": b_findings,
                "resolution_required": True,
            },
        )
        if cs["pool_a_count"] != 2 or cs["pool_b_count"] != 1:
            fatal(f"unexpected pool counts: {cs}")
        if not cs["contradictions"]:
            fatal(
                "expected at least one contradiction (CONFIRMED vs HYPOTHESIS on tc-2)"
            )
        log(f"  -> {len(cs['contradictions'])} contradictions surfaced")

        # ---- 6. judge_findings -----------------------------------------
        log("judge_findings: credibility-weighted merge...")
        j = client.call_tool(
            "judge_findings",
            {
                "pool_a_findings": a_findings,
                "pool_b_findings": b_findings,
                "pool_a_verifier_actions": _verifier_actions(a_findings),
                "pool_b_verifier_actions": _verifier_actions(b_findings),
            },
        )
        if not j["merged"] or j["budget_exceeded"]:
            fatal(f"judge produced no merged findings: {j}")
        log(f"  -> {len(j['merged'])} merged findings; budget OK")

        # ---- 7. correlate_findings -------------------------------------
        log("correlate_findings: SOUL.md cross-artifact rules...")
        merged_only = [m["finding"] for m in j["merged"]]
        c = client.call_tool("correlate_findings", {"findings": merged_only})
        kept = sum(1 for o in c["outcomes"] if o["action"] == "kept")
        downgraded = sum(1 for o in c["outcomes"] if o["action"] == "downgraded")
        log(f"  -> {kept} kept, {downgraded} downgraded by SOUL.md rules")

        # ---- 7a. report QA gate ----------------------------------------
        report_qa = {"status": "PASS", "checks": []}
        report_qa_sha256 = hashlib.sha256(
            json.dumps(report_qa, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ).hexdigest()
        client.call_tool(
            "audit_append",
            {
                "path": str(audit_path),
                "kind": "report_qa",
                "payload": {
                    "status": "PASS",
                    "report_qa": report_qa,
                    "report_qa_sha256": report_qa_sha256,
                },
            },
        )
        log("report_qa: audited PASS document and digest")

        # ---- 8. manifest_finalize --------------------------------------
        log("manifest_finalize: build + sign run.manifest.json...")
        mf = client.call_tool(
            "manifest_finalize",
            {
                "case_id": case_id,
                "run_id": run_id,
                "started_at": started_at,
                "audit_log_path": str(audit_path),
                "output_path": str(manifest_path),
                "signer": "stub",
                "extra": {
                    "image_path": "/fixtures/sample-case/sample-disk.001",
                    "model": "claude-opus-4-7",
                },
            },
        )
        if not (mf["leaf_count"] >= 4 and len(mf["merkle_root_hex"]) == 64):
            fatal(f"manifest finalize unexpected: {mf}")
        # Transparency anchoring is opt-in and absent by default: without
        # anchor_transparency the manifest carries NO transparency_log block.
        if (
            mf.get("transparency_anchored") is not False
            or mf.get("transparency_kind") is not None
        ):
            fatal(f"transparency anchor must be absent by default, got: {mf}")
        log(
            f"  -> {mf['leaf_count']} Merkle leaves, root={mf['merkle_root_hex'][:12]}..., "
            f"sig sha256={mf['signature_payload_sha256'][:12]}... "
            "(transparency anchor absent by default)"
        )

        # ---- 9. manifest_verify (offline) ------------------------------
        log("manifest_verify: offline replay...")
        mv = client.call_tool(
            "manifest_verify",
            {
                "manifest_path": str(manifest_path),
                "audit_log_path": str(audit_path),
            },
        )
        if not mv["overall"]:
            fatal(f"manifest verification failed: {mv}")
        # No anchor present -> transparency_ok is vacuously True and never gates.
        if mv.get("transparency_ok") is not True:
            fatal(f"transparency_ok must be vacuously True with no anchor, got: {mv}")
        log(
            "  -> overall=True, audit_chain_ok={a}, merkle_root_ok={m}, sig_present={s}, "
            "transparency_ok={t}".format(
                a=mv["audit_chain_ok"],
                m=mv["merkle_root_ok"],
                s=mv["signature_present"],
                t=mv["transparency_ok"],
            )
        )

        # ---- 10. tampered manifest is rejected -------------------------
        log("manifest_verify (tampered): expect failure...")
        loaded = json.loads(manifest_path.read_text(encoding="utf-8"))
        loaded["merkle_root_hex"] = "ff" * 32
        manifest_path.write_text(
            json.dumps(loaded, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        mv2 = client.call_tool(
            "manifest_verify",
            {
                "manifest_path": str(manifest_path),
                "audit_log_path": str(audit_path),
            },
        )
        if mv2["overall"]:
            fatal("tampered manifest must NOT verify, but it did")
        log(f"  -> tampered manifest correctly rejected: {mv2['merkle_root_detail']!r}")

        print()
        print("=" * 60)
        print("OK — full A2+A3 demo flow round-trips clean.")
        print(f"  case_id        : {case_id}")
        print(f"  run_id         : {run_id}")
        print(
            f"  audit log      : {audit_path} ({mf['audit_log_record_count']} records, "
            f"includes 2 verifier handoffs)"
        )
        print(f"  memory store   : {memory_path} (1 ioc seeded)")
        print(f"  manifest       : {manifest_path}")
        print("=" * 60)
        return 0
    finally:
        # Client lifecycle is owned by the caller (main); leaving the
        # try/finally as a structural placeholder so the flow's nested
        # exits (`fatal`) still unwind cleanly even when extended later.
        pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--real-evidence",
        nargs="?",
        const="<latest>",
        default=None,
        metavar="AUTO_RUN_DIR",
        help=(
            "Replay a real find-evil-auto case dir through the agent_mcp "
            "surface. Pass a path, or omit to use the latest dir under "
            "tmp/auto-runs/."
        ),
    )
    args = parser.parse_args()

    print("=" * 60)
    if args.real_evidence is not None:
        print("Find Evil! — agent_mcp real-evidence regression smoke")
    else:
        print("Find Evil! — agent_mcp end-to-end smoke (Amendment A2)")
    print("=" * 60)

    cmd = [
        "uv",
        "run",
        "--directory",
        str(AGENT_MCP_DIR),
        "python",
        "-m",
        "findevil_agent_mcp.server",
    ]
    controller_capability = secrets.token_hex(32)
    started_at = _now_iso()
    if args.real_evidence is not None:
        source_case_dir = _resolve_real_case_dir(args.real_evidence)
        case_dir = REPO / "tmp" / "smoke" / f"real-replay-{uuid.uuid4()}"
        case_id = _copy_real_case_for_replay(source_case_dir, case_dir)
        run_id = f"replay-{uuid.uuid4()}"
        signer = "ed25519"
    else:
        case_id = f"smoke-{uuid.uuid4()}"
        run_id = f"run-{int(time.time())}-{uuid.uuid4().hex[:8]}"
        case_dir = REPO / "tmp" / "smoke" / case_id
        signer = "stub"
    env_overrides = _prepare_reservation(
        case_dir,
        case_id=case_id,
        run_id=run_id,
        started_at=started_at,
        signer=signer,
        controller_capability=controller_capability,
    )
    log(f"spawning: {' '.join(cmd)}")
    client = StdioClient(
        cmd,
        env_overrides=env_overrides,
        controller_capability=controller_capability,
    )
    try:
        log("initialize handshake...")
        init = client.call(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "agent-mcp-smoke", "version": "1.0"},
            },
        )
        assert "capabilities" in init, f"no capabilities in init result: {init}"
        client.notify("notifications/initialized")

        log("tools/list...")
        tools_resp = client.call("tools/list")
        names = sorted(t["name"] for t in tools_resp["tools"])
        expected = sorted(
            [
                # A2 baseline minus the OTS pair removed under A5 (8 tools)
                "audit_append",
                "audit_verify",
                "manifest_finalize",
                "manifest_verify",
                "verify_finding",
                "detect_contradictions",
                "judge_findings",
                "correlate_findings",
                # A3 additions (cross-case memory + IBM-ACP handoff)
                "memory_remember",
                "memory_recall",
                "pool_handoff",
                "expert_miss_capture",
                # read-only accuracy diagnostic (13th Python tool)
                "accuracy_compare",
                # read-only AI/agent-tradecraft signature lead tool (14th Python tool)
                "find_ai_signatures",
            ]
        )
        if names != expected:
            fatal(f"tools mismatch: got {names}, expected {expected}")
        log(f"  -> {len(names)} tools registered")

        if args.real_evidence is not None:
            return real_evidence_flow(client, case_dir)
        return synthetic_flow(
            client,
            case_id=case_id,
            run_id=run_id,
            workdir=case_dir,
            started_at=started_at,
        )
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())
