#!/usr/bin/env python3
"""ground_verdict.py — post-verdict grounding helper (Phase 1, keyless).

Reads a finished Case's `verdict.json`, collects every MITRE technique the verdict
references (techniques asserted by findings / the attack story, plus coverage
targets), asks the self-hosted `findevil-grounding` n8n workflow to research each
one against MITRE ATT&CK, and writes the UNJUDGED research bundle to
`<case>/grounding_research.json`.

This helper does NOT judge. Claude Code reads the bundle and judges each claim
(supported/unsupported/contradicted/unknown) per `agent-config/GROUNDING.md`, then
writes `<case>/grounding.json`. There is no LLM and no API key in this path.

BOUNDARY (agent-config/GROUNDING.md): the output is a post-verdict operator aid —
never evidence, never a tool_call_id, never appended to `audit.jsonl` or the signed
`run.manifest.json`. This helper only ever writes `grounding_research.json`.

Usage:
    python3 scripts/ground_verdict.py <case-dir | verdict.json | case-id>
    GROUNDING_WEBHOOK=http://127.0.0.1:5678/webhook/findevil-grounding  (override)
"""

from __future__ import annotations

import json
import os
import re
import stat
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from n8n_security import (
    read_private_secret,
    validate_loopback_http_url,
    validate_public_http_url,
)

ROOT = Path(__file__).resolve().parent.parent
AUTO_RUNS = ROOT / "tmp" / "auto-runs"
WEBHOOK = validate_loopback_http_url(
    os.environ.get(
        "GROUNDING_WEBHOOK", "http://127.0.0.1:5678/webhook/findevil-grounding"
    )
)
WEBHOOK_SECRET_FILE = ROOT / "tmp" / "n8n-webhook-secret.txt"
WEBHOOK_HEADER = "X-Findevil-Grounding-Token"
RESEARCH_FILENAME = "grounding_research.json"
HTTP_TIMEOUT_S = 240
MAX_TECHNIQUES_PER_REQUEST = 16
MAX_TECHNIQUES_TOTAL = 128
MAX_WEBHOOK_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_VERDICT_BYTES = 16 * 1024 * 1024
MAX_NVD_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_CVES = 32


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_WEBHOOK_OPENER = urllib.request.build_opener(_NoRedirect)
_PUBLIC_OPENER = urllib.request.build_opener(_NoRedirect)

# NVD JSON REST API (keyless; ~5 req/30s unauthenticated, so space the calls).
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RATE_DELAY_S = float(os.environ.get("NVD_RATE_DELAY", "6"))
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _read_bounded_json_object(path: Path, limit: int) -> dict[str, Any]:
    if path.is_symlink():
        raise SystemExit(f"error: refusing symlinked JSON input: {path}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise SystemExit(
                f"error: JSON input must be an unlinked regular file: {path}"
            )
        chunks = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(fd, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    finally:
        os.close(fd)
    if len(raw) > limit:
        raise SystemExit(f"error: JSON input exceeds {limit} bytes: {path}")
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"error: invalid JSON input: {path}") from exc
    if not isinstance(parsed, dict):
        raise SystemExit(f"error: JSON input must contain an object: {path}")
    return parsed


def resolve_case_dir(arg: str) -> Path:
    """Accept a case dir, a path to verdict.json, or a bare case-id."""
    p = Path(arg)
    if p.is_file() and p.name == "verdict.json":
        return p.parent
    if p.is_dir():
        return p
    candidate = AUTO_RUNS / arg
    if candidate.is_dir():
        return candidate
    raise SystemExit(f"error: cannot resolve a case directory from {arg!r}")


def _touch(techs: dict[str, dict[str, Any]], tid: str) -> dict[str, Any]:
    key = tid.strip().upper()
    return techs.setdefault(
        key,
        {
            "technique_id": key,
            "claimed": False,
            "claimed_by": [],
            "finding_confidences": [],
            "names": [],
            "claim_snippets": [],
            "coverage_status": None,
        },
    )


def _add_unique(seq: list[Any], value: Any) -> None:
    if value and value not in seq:
        seq.append(value)


def collect_techniques(verdict: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Union of every MITRE technique the verdict references, with provenance.

    Asserted techniques (findings + attack-story chain) are real claims to judge;
    coverage-only targets are playbook entries (claimed=False).
    """
    techs: dict[str, dict[str, Any]] = {}

    for f in verdict.get("findings") or []:
        mt = f.get("mitre_technique")
        if not mt:
            continue
        e = _touch(techs, mt)
        e["claimed"] = True
        _add_unique(e["claimed_by"], f.get("finding_id") or f.get("id"))
        _add_unique(e["finding_confidences"], f.get("confidence"))
        _add_unique(e["claim_snippets"], (f.get("description") or "").strip()[:240])

    story = verdict.get("attack_story") or {}
    for s in story.get("attack_chain") or []:
        mt = s.get("mitre_technique")
        if not mt:
            continue
        e = _touch(techs, mt)
        e["claimed"] = True
        _add_unique(e["claimed_by"], s.get("finding_id"))
        _add_unique(e["finding_confidences"], s.get("confidence"))
        _add_unique(
            e["claim_snippets"],
            (s.get("summary") or s.get("title") or "").strip()[:240],
        )

    coverage = verdict.get("attack_coverage") or {}
    for t in coverage.get("targets") or []:
        tid = t.get("technique_id")
        if not tid:
            continue
        e = _touch(techs, tid)
        _add_unique(e["names"], t.get("technique_name"))
        e["coverage_status"] = t.get("status")
    for tid in coverage.get("observed_techniques") or []:
        _touch(techs, tid)

    return techs


def claim_for(entry: dict[str, Any]) -> str:
    if entry["claim_snippets"]:
        return entry["claim_snippets"][0]
    if entry["names"]:
        return entry["names"][0]
    return "coverage target (no finding asserts this)"


def build_queries(
    techs: dict[str, dict[str, Any]], ioc_block: dict[str, Any] | None
) -> list[dict[str, str]]:
    """Open-web search terms (capped, deduped): malware families surfaced by IOC
    enrichment first (highest signal), then the top asserted-technique claims."""
    seen: set[str] = set()
    queries: list[dict[str, str]] = []

    def add(term: str, why: str) -> None:
        term = " ".join(term.split())[:120]
        key = term.lower()
        if term and key not in seen:
            seen.add(key)
            queries.append({"query": term, "why": why})

    if ioc_block:
        for r in ioc_block.get("results", []):
            for s in r.get("sources", []):
                if s.get("malicious") and s.get("label"):
                    add(
                        f"{s['label']} malware analysis", f"ioc:{r.get('ioc', '')[:24]}"
                    )
    for e in techs.values():
        if not e["claimed"]:
            continue
        snippet = (e["claim_snippets"] or e["names"] or [""])[0]
        add(f"{e['technique_id']} {snippet}".strip(), "technique-claim")
    return queries[:4]


def extract_cves(verdict: dict[str, Any]) -> dict[str, list[str]]:
    """CVE id -> [finding_ids] from findings' `cves` field (tagged by the engine),
    falling back to a literal scan of finding text for older cases."""
    out: dict[str, list[str]] = {}
    for f in verdict.get("findings") or []:
        fid = f.get("finding_id") or f.get("id") or ""
        ids = list(f.get("cves") or [])
        if not ids:
            text = " ".join(
                str(f.get(k) or "") for k in ("description", "title", "summary")
            )
            ids = CVE_RE.findall(text)
        for c in ids:
            c = c.upper()
            out.setdefault(c, [])
            if fid and fid not in out[c]:
                out[c].append(fid)
    return out


def _nvd_get(cve_id: str) -> dict[str, Any]:
    url = validate_public_http_url(f"{NVD_API}?cveId={cve_id}", resolve=True)
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "findevil-grounding")
    with _PUBLIC_OPENER.open(req, timeout=30) as response:
        raw = response.read(MAX_NVD_RESPONSE_BYTES + 1)
    if len(raw) > MAX_NVD_RESPONSE_BYTES:
        raise ValueError("NVD response exceeded 4 MiB")
    parsed = json.loads(raw.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("NVD returned a non-object response")
    return parsed


def ground_cves(cve_map: dict[str, list[str]]) -> dict[str, Any] | None:
    """Validate each CVE id against the keyless NVD JSON API (host-side)."""
    if not cve_map:
        return None
    results: list[dict[str, Any]] = []
    first = True
    for cve_id, fids in cve_map.items():
        if not first:
            time.sleep(NVD_RATE_DELAY_S)  # respect NVD unauthenticated rate limit
        first = False
        entry: dict[str, Any] = {
            "cve_id": cve_id,
            "claimed_by": fids,
            "found": False,
            "source": "nvd",
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        }
        try:
            data = _nvd_get(cve_id)
            vulns = data.get("vulnerabilities") or []
            if vulns:
                cve = vulns[0].get("cve", {})
                desc = next(
                    (
                        d["value"]
                        for d in cve.get("descriptions", [])
                        if d.get("lang") == "en"
                    ),
                    None,
                )
                cvss = sev = None
                metrics = cve.get("metrics", {})
                for mk in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if metrics.get(mk):
                        m0 = metrics[mk][0]
                        cd = m0.get("cvssData", {})
                        cvss = cd.get("baseScore")
                        sev = cd.get("baseSeverity") or m0.get("baseSeverity")
                        break
                entry.update(
                    {
                        "found": True,
                        "description": (desc or "")[:600],
                        "cvss": cvss,
                        "severity": sev,
                    }
                )
            else:
                entry["error"] = "not_found"
        except (urllib.error.URLError, OSError, ValueError) as e:
            entry["error"] = str(e)[:120]
        results.append(entry)
    return {"results": results}


def build_webhook_request(
    payload: dict[str, Any], secret: str
) -> urllib.request.Request:
    if len(secret.encode("utf-8")) < 32:
        raise ValueError("grounding webhook capability must contain at least 32 bytes")
    request = urllib.request.Request(
        validate_loopback_http_url(WEBHOOK),
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        method="POST",
    )
    request.add_header("Content-Type", "application/json")
    request.add_header(WEBHOOK_HEADER, secret)
    return request


def _call_workflow_once(payload: dict[str, Any], secret: str) -> dict[str, Any]:
    req = build_webhook_request(payload, secret)
    try:
        with _WEBHOOK_OPENER.open(req, timeout=HTTP_TIMEOUT_S) as resp:
            raw = resp.read(MAX_WEBHOOK_RESPONSE_BYTES + 1)
            if len(raw) > MAX_WEBHOOK_RESPONSE_BYTES:
                raise SystemExit("error: grounding webhook response exceeded 2 MiB")
            parsed = json.loads(raw.decode("utf-8"))
            if not isinstance(parsed, dict):
                raise SystemExit(
                    "error: grounding webhook returned a non-object response"
                )
            return parsed
    except urllib.error.HTTPError as e:
        raise SystemExit(
            f"error: grounding webhook returned HTTP {e.code}. "
            f"Is the authenticated workflow deployed? Run: "
            f"python3 scripts/setup-grounding-workflow.py"
        ) from None
    except (urllib.error.URLError, OSError) as e:
        raise SystemExit(
            f"error: cannot reach grounding webhook at {WEBHOOK} ({e}).\n"
            "  - start the local n8n sidecar with scripts/setup-n8n.py, and\n"
            "  - deploy the authenticated workflow: "
            "python3 scripts/setup-grounding-workflow.py"
        ) from None
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit("error: grounding webhook returned invalid JSON") from exc


def call_workflow(
    case_id: str,
    techs: dict[str, dict[str, Any]],
    queries: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    try:
        secret = read_private_secret(WEBHOOK_SECRET_FILE, minimum_bytes=32)
    except (FileNotFoundError, PermissionError, ValueError, OSError) as exc:
        raise SystemExit(
            f"error: refusing unauthenticated grounding webhook: {exc}. "
            "Run scripts/setup-n8n.py first."
        ) from None
    items = [
        {"id": entry["technique_id"], "claim": claim_for(entry)}
        for entry in techs.values()
    ]
    technique_research: list[dict[str, Any]] = []
    open_web_research: list[dict[str, Any]] = []
    generated_at = None
    for offset in range(0, len(items), MAX_TECHNIQUES_PER_REQUEST):
        response = _call_workflow_once(
            {
                "case_id": str(case_id)[:128],
                "techniques": items[offset : offset + MAX_TECHNIQUES_PER_REQUEST],
                "queries": (queries or [])[:4] if offset == 0 else [],
            },
            secret,
        )
        technique_research.extend(response.get("technique_research") or [])
        if offset == 0:
            open_web_research = response.get("open_web_research") or []
            generated_at = response.get("generated_at")
    return {
        "case_id": case_id,
        "generated_at": generated_at,
        "technique_research": technique_research,
        "open_web_research": open_web_research,
    }


def merge_bundle(
    techs: dict[str, dict[str, Any]], research: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    by_id = {r.get("technique_id", "").upper(): r for r in research}
    merged: list[dict[str, Any]] = []
    # claimed techniques first, then by id — the asserted claims are what matter
    for key, e in sorted(techs.items(), key=lambda kv: (not kv[1]["claimed"], kv[0])):
        r = by_id.get(key, {})
        merged.append(
            {
                "technique_id": key,
                "claimed": e["claimed"],
                "claimed_by": e["claimed_by"],
                "finding_confidences": e["finding_confidences"],
                "coverage_status": e["coverage_status"],
                "found": r.get("found", False),
                "id_match": r.get("id_match", False),
                "mitre_id": r.get("mitre_id"),
                "mitre_name": r.get("mitre_name"),
                "excerpt": r.get("excerpt"),
                "sources": r.get("sources", []),
                "error": r.get("error"),
            }
        )
    return merged


def first_pass_grounding(bundle: dict[str, Any]) -> dict[str, Any]:
    """Deterministic, headless first-pass judgment of a research bundle.

    For unattended runs (no agent in the loop) so the dashboard populates. It only
    encodes the MECHANICAL facts — MITRE lists the id / NVD lists the CVE / a vendor
    flagged the IOC — and explicitly defers the semantic "does it match the finding"
    call to a Claude Code session (judged_by says so). An interactive judge per
    agent-config/GROUNDING.md overwrites this with the real verdict.
    """
    grounding: list[dict[str, Any]] = []
    for t in bundle.get("techniques", []):
        if not t.get("claimed"):
            continue
        srcs = (
            [
                {
                    "source": "mitre_attack",
                    "url": (t.get("sources") or [{}])[0].get("url"),
                    "excerpt": t.get("excerpt"),
                }
            ]
            if t.get("excerpt")
            else []
        )
        found, idm = t.get("found"), t.get("id_match")
        status = "supported" if found else "contradicted"
        grounding.append(
            {
                "technique_id": t["technique_id"],
                "claimed": True,
                "claimed_by": t.get("claimed_by", []),
                "finding_confidence": (t.get("finding_confidences") or [None])[0],
                "status": status,
                "possible_hallucination": not found,
                "id_status": "renumbered" if (found and not idm) else "current",
                "mitre_current_id": t.get("mitre_id"),
                "mitre_name": t.get("mitre_name"),
                "sources": srcs,
                "rationale": "first-pass: MITRE "
                + ("lists this id" if found else "does NOT list this id")
                + " — confirm it matches the finding in a Claude Code session.",
            }
        )

    ioc_grounding: list[dict[str, Any]] = []
    for r in (bundle.get("ioc_enrichment") or {}).get("results", []):
        if not r.get("found"):
            st = "unknown"
        elif (r.get("malicious_sources") or 0) > 0:
            st = "malicious"
        else:
            st = "clean"
        srcs = [
            {
                "source": s.get("provider"),
                "url": s.get("url"),
                "excerpt": s.get("detail"),
            }
            for s in r.get("sources", [])
            if s.get("found")
        ]
        ioc_grounding.append(
            {
                "ioc": r.get("ioc"),
                "type": r.get("type"),
                "status": st,
                "possible_overclaim": False,
                "sources": srcs,
                "rationale": "first-pass: provider reputation only — analyst confirms.",
            }
        )

    cve_grounding: list[dict[str, Any]] = []
    for c in (bundle.get("cve_research") or {}).get("results", []):
        found = c.get("found")
        cve_grounding.append(
            {
                "cve_id": c.get("cve_id"),
                "status": "supported" if found else "unsupported",
                "possible_hallucination": not found,
                "cvss": c.get("cvss"),
                "severity": c.get("severity"),
                "sources": [
                    {
                        "source": "nvd",
                        "url": c.get("url"),
                        "excerpt": c.get("description") or c.get("error"),
                    }
                ],
                "rationale": "first-pass: NVD "
                + (
                    "lists this CVE (severity context only)"
                    if found
                    else "does NOT list this CVE id"
                )
                + ".",
            }
        )

    open_web = [
        {
            "query": o.get("query"),
            "relevance": "unknown",
            "note": "first-pass: not yet judged",
            "sources": [
                {"source": "open_web", "url": x.get("url"), "excerpt": x.get("excerpt")}
                for x in (o.get("results") or [])
                if x.get("excerpt")
            ][:2],
        }
        for o in bundle.get("open_web_research", [])
    ]

    return {
        "case_id": bundle.get("case_id"),
        "verdict": bundle.get("verdict"),
        "generated_at": bundle.get("generated_at"),
        "source": "grounding first-pass (operator aid; not evidence, not in audit chain)",
        "judged_by": "deterministic first-pass (headless) — refine in a Claude Code session",
        "grounding": grounding,
        "ioc_grounding": ioc_grounding,
        "cve_grounding": cve_grounding,
        "open_web": open_web,
        "summary": {
            "claims_judged": len(grounding),
            "supported": sum(1 for g in grounding if g["status"] == "supported"),
            "contradicted": sum(1 for g in grounding if g["status"] == "contradicted"),
            "unsupported": 0,
            "unknown": 0,
            "possible_hallucinations": sum(
                1 for g in grounding if g["possible_hallucination"]
            ),
            "iocs_judged": len(ioc_grounding),
            "iocs_malicious": sum(
                1 for i in ioc_grounding if i["status"] == "malicious"
            ),
            "cves_judged": len(cve_grounding),
        },
    }


# Typed IOC buckets we can reputation-enrich (from malware_triage.aggregate_iocs).
ENRICHABLE_IOC_TYPES = ("hashes", "domains", "ips", "urls")


def extract_iocs(verdict: dict[str, Any]) -> dict[str, list[str]]:
    """Pull typed IOCs from malware_triage.aggregate_iocs only.

    Deliberately NOT a regex over the verdict: every tool output is SHA-256'd
    into the crypto chain, so a blind hash regex would scoop up custody hashes
    and manufacture bogus IOCs. Only the engine's typed observables enrich.
    """
    agg = (verdict.get("malware_triage") or {}).get("aggregate_iocs") or {}
    return {k: [v for v in (agg.get(k) or []) if v] for k in ENRICHABLE_IOC_TYPES}


def run_ioc_enrichment(iocs: dict[str, list[str]]) -> dict[str, Any] | None:
    """Host-side reputation enrichment (VirusTotal). Key never enters n8n.

    Returns None when there are no IOCs to enrich; otherwise the enrichment
    block (results + availability note) for the research bundle.
    """
    if not any(iocs.values()):
        return None
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        import ioc_enrich
    except Exception as e:  # ioc_enrich is optional; never break technique grounding
        return {
            "results": [],
            "available": False,
            "note": f"ioc_enrich unavailable: {e}",
        }
    return ioc_enrich.enrich(iocs)


def main(argv: list[str]) -> int:
    if os.environ.get("FINDEVIL_ACKNOWLEDGE_POST_VERDICT_EGRESS") != "1":
        print(
            "ground_verdict: refused without "
            "FINDEVIL_ACKNOWLEDGE_POST_VERDICT_EGRESS=1",
            file=sys.stderr,
        )
        return 2
    if len(argv) != 1:
        print(__doc__)
        return 2
    case_dir = resolve_case_dir(argv[0])
    verdict_path = case_dir / "verdict.json"
    if not verdict_path.is_file():
        raise SystemExit(f"error: no verdict.json in {case_dir}")
    verdict = _read_bounded_json_object(verdict_path, MAX_VERDICT_BYTES)
    case_id = verdict.get("case_id") or case_dir.name

    techs = collect_techniques(verdict)
    if not techs:
        raise SystemExit(
            "error: verdict references no MITRE techniques — nothing to ground."
        )
    if len(techs) > MAX_TECHNIQUES_TOTAL:
        raise SystemExit(
            f"error: verdict references {len(techs)} techniques; "
            f"limit is {MAX_TECHNIQUES_TOTAL}"
        )
    claimed = sum(1 for e in techs.values() if e["claimed"])
    print(
        f"grounding {len(techs)} technique(s) "
        f"({claimed} asserted by findings, {len(techs) - claimed} coverage-only) "
        f"for case {case_id} via {WEBHOOK}"
    )

    # Enrich IOCs first (host-side) so malware families can seed open-web queries.
    iocs = extract_iocs(verdict)
    ioc_total = sum(len(v) for v in iocs.values())
    if ioc_total:
        print(f"enriching {ioc_total} IOC(s) host-side (VirusTotal + abuse.ch)…")
    ioc_block = run_ioc_enrichment(iocs)

    cve_map = extract_cves(verdict)
    if len(cve_map) > MAX_CVES:
        raise SystemExit(
            f"error: verdict references {len(cve_map)} CVEs; limit is {MAX_CVES}"
        )
    if cve_map:
        print(f"grounding {len(cve_map)} CVE(s) host-side via NVD…")
    cve_block = ground_cves(cve_map)

    queries = build_queries(techs, ioc_block)
    if queries:
        print(f"open-web research: {len(queries)} query(ies) via self-hosted SearXNG")

    response = call_workflow(case_id, techs, queries)
    merged = merge_bundle(techs, response.get("technique_research") or [])
    open_web = response.get("open_web_research") or []

    bundle = {
        "case_id": case_id,
        "verdict": verdict.get("verdict"),
        "generated_at": response.get("generated_at")
        or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "n8n findevil-grounding research bundle "
        "(operator aid; not evidence, not in audit chain) — UNJUDGED",
        "note": "Claude Code judges this per agent-config/GROUNDING.md, then writes "
        "grounding.json. No technique is 'supported' without a quoted excerpt.",
        "techniques": merged,
    }
    if ioc_block is not None:
        bundle["ioc_enrichment"] = ioc_block
    if cve_block is not None:
        bundle["cve_research"] = cve_block
    if open_web:
        bundle["open_web_research"] = open_web
    out_path = case_dir / RESEARCH_FILENAME
    out_path.write_text(json.dumps(bundle, indent=2))

    # Headless support: write a deterministic first-pass grounding.json so the
    # dashboard populates in unattended runs. Non-clobbering — never overwrite an
    # existing (likely agent-judged) grounding.json.
    grounding_path = case_dir / "grounding.json"
    wrote_first_pass = False
    if not grounding_path.is_file():
        grounding_path.write_text(json.dumps(first_pass_grounding(bundle), indent=2))
        wrote_first_pass = True

    for m in merged:
        tag = "claim" if m["claimed"] else "cover"
        if not m["found"]:
            mark, name = "MISS", "(not on MITRE)"
        elif not m["id_match"]:
            mark = "RENUM"
            name = f"{m['mitre_name']} -> now {m['mitre_id']}"
        else:
            mark, name = "ok   ", (m["mitre_name"] or "-")
        print(f"  [{tag}] {mark} {m['technique_id']:<12} {name}")
    if ioc_block is not None:
        if not ioc_block.get("available"):
            print(f"  [ioc] skipped — {ioc_block.get('note')}")
        else:
            for r in ioc_block.get("results", []):
                mk = "ok  " if r.get("found") else "MISS"
                prov = ",".join(r.get("providers") or []) or "-"
                print(
                    f"  [ioc] {mk} {r.get('type'):<6} mal_src={r.get('malicious_sources')} "
                    f"[{prov}] {r.get('ioc', '')[:40]}"
                )
    if cve_block is not None:
        for c in cve_block.get("results", []):
            mk = "ok  " if c.get("found") else "MISS"
            extra = (
                f"CVSS {c.get('cvss')} {c.get('severity') or ''}"
                if c.get("found")
                else c.get("error")
            )
            print(f"  [cve] {mk} {c.get('cve_id'):<16} {extra}")
    for ow in open_web:
        n = len(ow.get("results") or [])
        err = ow.get("error")
        print(
            f"  [web] {('ERR ' + err) if err else str(n) + ' hits'} :: {ow.get('query', '')[:50]}"
        )
    print(f"\nwrote {out_path}")
    if wrote_first_pass:
        print(f"wrote first-pass {grounding_path} (headless default)")
        print(
            "next: Claude Code refines it per agent-config/GROUNDING.md "
            "(replaces the deterministic first-pass with real judgment)"
        )
    else:
        print(
            f"next: Claude Code judges this bundle per agent-config/GROUNDING.md "
            f"and writes {grounding_path}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
