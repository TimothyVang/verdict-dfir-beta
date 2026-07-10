#!/usr/bin/env python3
"""n8n_post — fire a completed case's verdict at the optional n8n
finding-to-action workflow and record the outcome as automation.json.

n8n is operator tooling that lives OUTSIDE the evidentiary chain. This script
deliberately:
  - reads the SIGNED verdict.json (read-only),
  - POSTs a summary to the n8n webhook,
  - writes the result to <case>/automation.json — a separate file, NOT the
    hash-chained audit.jsonl (appending there would invalidate the manifest's
    audit_log_final_hash), and never cited as a Finding.

Graceful: if n8n is unreachable it still writes automation.json with
n8n_reachable=false so the dashboard can say so honestly.

Usage: n8n_post.py <case-dir>
Env:   FINDEVIL_N8N_WEBHOOK  (default http://localhost:5678/webhook/findevil-finding-to-action)
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from n8n_security import read_private_secret, validate_loopback_http_url

ROOT = Path(__file__).resolve().parent.parent
WEBHOOK = validate_loopback_http_url(
    os.environ.get(
        "FINDEVIL_N8N_WEBHOOK",
        "http://127.0.0.1:5678/webhook/findevil-finding-to-action",
    )
)
WEBHOOK_SECRET_FILE = ROOT / "tmp" / "n8n-webhook-secret.txt"
WEBHOOK_HEADER = "X-Findevil-Grounding-Token"
MAX_VERDICT_BYTES = 4 * 1024 * 1024
MAX_PAYLOAD_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
HTTP_TIMEOUT_S = 10
NODES = ("trigger", "route", "ticket")
SOURCE = "n8n finding-to-action (operator harness; not evidence, not in audit chain)"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _summarize_findings(verdict: dict) -> list[dict]:
    out = []
    for f in (verdict.get("findings") or [])[:64]:
        out.append(
            {
                "title": str(f.get("description") or f.get("title") or "finding")[:512],
                "mitre": str(f.get("mitre_technique") or f.get("mitre") or "")[:32]
                or None,
                "confidence": str(f.get("confidence") or "")[:32] or None,
            }
        )
    return out


def build_webhook_request(payload: dict, secret: str) -> urllib.request.Request:
    if len(secret.encode("utf-8")) < 32:
        raise ValueError("n8n webhook capability must contain at least 32 bytes")
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_PAYLOAD_BYTES:
        raise ValueError("n8n automation payload exceeds 64 KiB")
    request = urllib.request.Request(
        validate_loopback_http_url(WEBHOOK), data=encoded, method="POST"
    )
    request.add_header("Content-Type", "application/json")
    request.add_header(WEBHOOK_HEADER, secret)
    return request


def main() -> int:
    if os.environ.get("FINDEVIL_ACKNOWLEDGE_POST_VERDICT_EGRESS") != "1":
        print(
            "n8n_post: refused without FINDEVIL_ACKNOWLEDGE_POST_VERDICT_EGRESS=1",
            file=sys.stderr,
        )
        return 2
    if len(sys.argv) < 2:
        print("usage: n8n_post.py <case-dir>", file=sys.stderr)
        return 2
    case_dir = Path(sys.argv[1])
    verdict_file = case_dir / "verdict.json"
    out_file = case_dir / "automation.json"
    case_dir.mkdir(parents=True, exist_ok=True)

    if not verdict_file.is_file():
        out_file.write_text(
            json.dumps(
                {"ran": False, "reason": "no verdict.json", "source": SOURCE}, indent=2
            )
        )
        return 0

    if verdict_file.stat().st_size > MAX_VERDICT_BYTES:
        print("n8n_post: verdict.json exceeds 4 MiB", file=sys.stderr)
        return 2
    verdict = json.loads(verdict_file.read_text())
    findings = _summarize_findings(verdict)
    payload = {
        "case_id": verdict.get("case_id"),
        "verdict": verdict.get("verdict"),
        "findings": findings,
    }
    record: dict = {
        "ran": True,
        "posted_at": _now(),
        "webhook": WEBHOOK,
        "verdict": verdict.get("verdict"),
        "finding_count": len(findings),
        "source": SOURCE,
    }

    try:
        secret = read_private_secret(WEBHOOK_SECRET_FILE, minimum_bytes=32)
        req = build_webhook_request(payload, secret)
        with _OPENER.open(req, timeout=HTTP_TIMEOUT_S) as resp:
            raw = resp.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise ValueError("n8n response exceeds 1 MiB")
            body = raw.decode("utf-8", errors="replace")
        rj = json.loads(body)
        if not isinstance(rj, dict):
            raise ValueError("n8n returned a non-object response")
        action_plan = rj.get("action_plan")
        if not isinstance(action_plan, list) or len(action_plan) > 64:
            raise ValueError(
                "finding-to-action workflow is unavailable or returned an invalid plan"
            )
        ticket_file = rj.get("ticket_file")
        record.update(
            {
                "n8n_reachable": True,
                "automation_supported": True,
                "steps": [{"node": n, "status": "ok"} for n in NODES],
                "action_plan": action_plan,
                "ticket_file": str(ticket_file)[:512] if ticket_file else None,
            }
        )
    except urllib.error.HTTPError as exc:
        record.update(
            {
                "n8n_reachable": exc.code != 0,
                "automation_supported": False,
                "reason": (
                    "finding-to-action workflow is retired or unavailable"
                    if exc.code in (404, 410)
                    else f"authenticated webhook returned HTTP {exc.code}"
                ),
                "steps": [{"node": n, "status": "idle"} for n in NODES],
                "ticket_file": None,
                "action_plan": [],
            }
        )
    except (
        FileNotFoundError,
        PermissionError,
        urllib.error.URLError,
        json.JSONDecodeError,
        OSError,
        TimeoutError,
        ValueError,
    ) as exc:
        record.update(
            {
                "n8n_reachable": False,
                "automation_supported": False,
                "reason": str(exc)[:240],
                "steps": [{"node": n, "status": "idle"} for n in NODES],
                "ticket_file": None,
                "action_plan": [],
            }
        )

    out_file.write_text(json.dumps(record, indent=2))
    state = (
        "n8n routed"
        if record.get("automation_supported")
        else "n8n automation unavailable/unsupported (skipped)"
    )
    print(f"[n8n_post] {state} -> {out_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
