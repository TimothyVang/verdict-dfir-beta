#!/usr/bin/env python3
"""Fair-fight EVTX hard-quiz scorecard — same goldens, publishable recall.

Scores the amber EVTX technique pack against finished case dirs (or runs the
deterministic rulebook engine). This is the hard-quiz gate: raise MITRE findings
for techniques, not merely "see" events.

Default cases (from goldens/CORPUS.json amber EVTX pack):
  - security-log-cleared   → T1070.001 (EID 1102)
  - win-lateral-movement   → T1047 + T1543.003 (multi-file)
  - wmi-execution          → T1047
  - service-install-spoolfool → T1543.003

Usage:
  # Re-score existing tmp/auto-runs/<case-id> dirs (no re-run):
  python3 scripts/fair-fight-evtx-scorecard.py

  # Run rulebook find_evil_auto on each case, then score:
  python3 scripts/fair-fight-evtx-scorecard.py --run-rulebook

  # Attach a second arm label (e.g. spark-agent case dirs):
  python3 scripts/fair-fight-evtx-scorecard.py --arm rulebook=tmp/auto-runs \\
      --arm spark=/path/to/spark-runs

Writes:
  tmp/fair-fight/<stamp>/scorecard.json
  tmp/fair-fight/<stamp>/SCORECARD.md
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_REPO = Path(__file__).resolve().parent.parent
_SCORE = _REPO / "scripts" / "score-recall.py"
_AUTO = _REPO / "scripts" / "find_evil_auto.py"
_CORPUS = _REPO / "goldens" / "CORPUS.json"

# Hard-quiz pack: technique findings the product must raise (not just parse).
DEFAULT_CASES = (
    "security-log-cleared",
    "win-lateral-movement",
    "wmi-execution",
    "service-install-spoolfool",
)


def _load_corpus_cases() -> dict[str, dict[str, Any]]:
    if not _CORPUS.is_file():
        return {}
    data = json.loads(_CORPUS.read_text(encoding="utf-8"))
    return {c["name"]: c for c in data.get("cases", []) if isinstance(c, dict) and "name" in c}


def _expected_techniques(golden_dir: Path) -> list[str]:
    key = golden_dir / "expected-findings.json"
    if not key.is_file():
        return []
    data = json.loads(key.read_text(encoding="utf-8"))
    out: list[str] = []
    for f in data.get("findings") or []:
        tech = f.get("mitre_technique")
        if tech and tech not in out:
            out.append(str(tech))
    return out


def _resolve_case_dir(arm_root: Path, case_id: str) -> Path | None:
    """Prefer arm_root/<case_id>, else newest arm_root/* containing matching golden id."""
    direct = arm_root / case_id
    if (direct / "verdict.json").is_file():
        return direct
    # Some runs use auto-<uuid>; look for recall-score or verdict with case_id.
    candidates: list[tuple[float, Path]] = []
    if not arm_root.is_dir():
        return None
    for child in arm_root.iterdir():
        if not child.is_dir():
            continue
        vpath = child / "verdict.json"
        if not vpath.is_file():
            continue
        try:
            v = json.loads(vpath.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        cid = str(v.get("case_id") or child.name)
        if case_id in cid or cid == case_id or case_id in child.name:
            candidates.append((child.stat().st_mtime, child))
            continue
        # Match via written recall-score golden path
        rs = child / "recall-score.json"
        if rs.is_file():
            try:
                r = json.loads(rs.read_text(encoding="utf-8"))
                if r.get("case_id") == case_id:
                    candidates.append((child.stat().st_mtime, child))
            except json.JSONDecodeError:
                pass
    if not candidates:
        return None
    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates[0][1]


def _score_case(case_dir: Path, golden: Path) -> dict[str, Any]:
    cmd = [sys.executable, str(_SCORE), str(case_dir), "--golden", str(golden), "--quiet"]
    proc = subprocess.run(cmd, cwd=str(_REPO), capture_output=True, text=True)
    # score-recall writes recall-score.json next to case
    rs = case_dir / "recall-score.json"
    if rs.is_file():
        result = json.loads(rs.read_text(encoding="utf-8"))
        result["score_exit"] = proc.returncode
        return result
    return {
        "case_id": case_dir.name,
        "case_dir": str(case_dir),
        "error": "no recall-score.json",
        "stdout": (proc.stdout or "")[-500:],
        "stderr": (proc.stderr or "")[-500:],
        "score_exit": proc.returncode,
        "pass": False,
        "recall_percent": 0,
        "recalled_n": 0,
        "expected_n": 0,
    }


def _run_rulebook(evidence: Path, case_id: str, out_parent: Path) -> Path | None:
    if not evidence.exists():
        return None
    if not _AUTO.is_file():
        return None
    summary = out_parent / f"rulebook-{case_id}-summary.json"
    cmd = [
        sys.executable,
        str(_AUTO),
        "--local",
        "--unattended",
        "--no-report",
        "--signer",
        "ed25519",
        "--run-summary",
        str(summary),
        str(evidence),
    ]
    proc = subprocess.run(cmd, cwd=str(_REPO), capture_output=True, text=True)
    if proc.returncode != 0:
        print(f"  rulebook FAIL {case_id}: exit={proc.returncode}", file=sys.stderr)
        if proc.stderr:
            print(proc.stderr[-800:], file=sys.stderr)
        return None
    if summary.is_file():
        try:
            s = json.loads(summary.read_text(encoding="utf-8"))
            run_dir = s.get("run_dir") or (s.get("result") or {}).get("local_dir")
            if run_dir and Path(run_dir).is_dir():
                return Path(run_dir)
        except json.JSONDecodeError:
            pass
    return None


def _techniques_in_run(case_dir: Path) -> list[str]:
    vpath = case_dir / "verdict.json"
    if not vpath.is_file():
        return []
    v = json.loads(vpath.read_text(encoding="utf-8"))
    techs: list[str] = []
    for f in v.get("findings") or []:
        t = f.get("mitre_technique")
        if t and t not in techs:
            techs.append(str(t))
    return techs


def _parse_arms(raw: list[str]) -> dict[str, Path]:
    arms: dict[str, Path] = {}
    for item in raw:
        if "=" not in item:
            raise SystemExit(f"--arm must be name=path, got: {item}")
        name, path = item.split("=", 1)
        arms[name.strip()] = Path(path).expanduser().resolve()
    return arms


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--arm",
        action="append",
        default=[],
        help="name=case_root (repeatable). Default: rulebook=tmp/auto-runs",
    )
    ap.add_argument(
        "--run-rulebook",
        action="store_true",
        help="Run find_evil_auto --local on each case before scoring the rulebook arm",
    )
    ap.add_argument(
        "--cases",
        default=",".join(DEFAULT_CASES),
        help="Comma-separated case ids (default: amber EVTX hard-quiz pack)",
    )
    ap.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Output directory (default: tmp/fair-fight/<utc-stamp>)",
    )
    args = ap.parse_args()

    cases = [c.strip() for c in args.cases.split(",") if c.strip()]
    corpus = _load_corpus_cases()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = (args.out or (_REPO / "tmp" / "fair-fight" / stamp)).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    arms = _parse_arms(args.arm) if args.arm else {"rulebook": (_REPO / "tmp" / "auto-runs").resolve()}

    if args.run_rulebook:
        print("==> running rulebook find_evil_auto for hard-quiz pack", flush=True)
        rb_root = arms.setdefault("rulebook", (_REPO / "tmp" / "auto-runs").resolve())
        rb_root.mkdir(parents=True, exist_ok=True)
        for case_id in cases:
            meta = corpus.get(case_id) or {}
            evidence = _REPO / str(meta.get("evidence") or f"evidence/{case_id}")
            print(f"  run {case_id} ← {evidence}", flush=True)
            run_dir = _run_rulebook(evidence, case_id, out_dir)
            if run_dir:
                # Symlink/copy pointer under arm root for stable lookup
                pointer = rb_root / case_id
                if pointer.exists() or pointer.is_symlink():
                    if pointer.is_symlink() or pointer.is_file():
                        pointer.unlink()
                # Prefer scoring the run in place; also keep a stable name copy of scores
                print(f"    run_dir={run_dir}", flush=True)
                # If run_dir is not named case_id, write a small pointer file
                pointer_meta = rb_root / f"{case_id}.run-pointer.json"
                pointer_meta.write_text(
                    json.dumps({"case_id": case_id, "run_dir": str(run_dir)}, indent=2) + "\n",
                    encoding="utf-8",
                )
                # Score immediately into run_dir and also cache under fair-fight
                golden = _REPO / "goldens" / case_id
                result = _score_case(run_dir, golden)
                (out_dir / f"rulebook-{case_id}-recall.json").write_text(
                    json.dumps(result, indent=2) + "\n", encoding="utf-8"
                )

    # Build scorecard
    rows: list[dict[str, Any]] = []
    for case_id in cases:
        meta = corpus.get(case_id) or {}
        golden = _REPO / "goldens" / case_id
        expected = _expected_techniques(golden)
        evidence = str(meta.get("evidence") or f"evidence/{case_id}")
        row: dict[str, Any] = {
            "case_id": case_id,
            "evidence": evidence,
            "expected_techniques": expected,
            "arms": {},
        }
        for arm_name, arm_root in arms.items():
            case_dir = _resolve_case_dir(arm_root, case_id)
            # Also honor run-pointer from --run-rulebook
            if case_dir is None:
                ptr = arm_root / f"{case_id}.run-pointer.json"
                if ptr.is_file():
                    try:
                        case_dir = Path(json.loads(ptr.read_text(encoding="utf-8"))["run_dir"])
                    except (json.JSONDecodeError, KeyError, TypeError):
                        case_dir = None
            # Fair-fight out cache
            cached = out_dir / f"{arm_name}-{case_id}-recall.json"
            if case_dir is None and cached.is_file():
                arm_result = json.loads(cached.read_text(encoding="utf-8"))
            elif case_dir is None:
                arm_result = {
                    "missing": True,
                    "pass": False,
                    "recall_percent": None,
                    "note": f"no case dir under {arm_root}",
                }
            else:
                arm_result = _score_case(case_dir, golden)
                arm_result["observed_techniques"] = _techniques_in_run(case_dir)
                arm_result["case_dir"] = str(case_dir)
                # Technique-level HIT/MISS vs golden
                observed = set(arm_result.get("observed_techniques") or [])
                tech_hits = []
                for t in expected:
                    tech_hits.append(
                        {
                            "technique": t,
                            "result": "HIT" if t in observed else "MISS",
                        }
                    )
                arm_result["technique_scorecard"] = tech_hits
                (out_dir / f"{arm_name}-{case_id}-recall.json").write_text(
                    json.dumps(arm_result, indent=2) + "\n", encoding="utf-8"
                )
            row["arms"][arm_name] = arm_result
        rows.append(row)

    # Aggregate
    summary_arms: dict[str, Any] = {}
    for arm_name in arms:
        n = 0
        passed = 0
        tech_hit = 0
        tech_total = 0
        for row in rows:
            ar = row["arms"].get(arm_name) or {}
            if ar.get("missing") or ar.get("error"):
                continue
            n += 1
            # score-recall / accuracy.score emits explicit boolean "pass"
            if ar.get("pass") is True:
                passed += 1
            elif ar.get("pass") is None and ar.get("verdict_match") and (
                float(ar.get("recall_percent") or 0)
                >= float(ar.get("min_recall_percent") or 100)
            ) and not ar.get("planted_bait"):
                passed += 1
            for th in ar.get("technique_scorecard") or []:
                tech_total += 1
                if th.get("result") == "HIT":
                    tech_hit += 1
        summary_arms[arm_name] = {
            "cases_scored": n,
            "cases_pass_recall": passed,
            "technique_hits": tech_hit,
            "technique_total": tech_total,
            "technique_recall_percent": round(100.0 * tech_hit / tech_total, 1) if tech_total else None,
        }

    doc = {
        "kind": "fair_fight_evtx_hard_quiz",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repo": str(_REPO),
        "protocol": {
            "same_evidence": True,
            "same_goldens": True,
            "scorer": "scripts/score-recall.py (MITRE + Jaccard)",
            "win_condition": "Spark/offline arm technique recall >= Claude/rulebook arm on this pack",
            "honesty": "INDETERMINATE on EVTX-only is policy-correct; verdict match alone is not coverage.",
        },
        "cases": cases,
        "arms": {k: str(v) for k, v in arms.items()},
        "summary": summary_arms,
        "rows": rows,
    }
    (out_dir / "scorecard.json").write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")

    # Markdown
    lines = [
        "# Fair-fight EVTX hard-quiz scorecard",
        "",
        f"Generated: `{doc['generated_at']}`",
        "",
        "## Caveat first",
        "",
        "This scores **technique findings against goldens**, not seal marketing.",
        "EVTX-only cases stay **INDETERMINATE** by policy; a matching verdict is not full coverage.",
        "Until an offline/Spark arm meets or exceeds the rulebook arm on this pack, we have not “exceeded.”",
        "",
        "## Arms",
        "",
    ]
    for name, path in arms.items():
        s = summary_arms.get(name, {})
        lines.append(
            f"- **{name}**: `{path}` — cases pass {s.get('cases_pass_recall')}/{s.get('cases_scored')}, "
            f"technique hits {s.get('technique_hits')}/{s.get('technique_total')} "
            f"({s.get('technique_recall_percent')}%)"
        )
    lines += ["", "## Per-case", ""]
    for row in rows:
        lines.append(f"### `{row['case_id']}`")
        lines.append(f"- evidence: `{row['evidence']}`")
        lines.append(f"- expected techniques: {', '.join(row['expected_techniques']) or '(none)'}")
        for arm_name, ar in row["arms"].items():
            if ar.get("missing"):
                lines.append(f"- **{arm_name}**: MISSING — {ar.get('note')}")
                continue
            if ar.get("error"):
                lines.append(f"- **{arm_name}**: ERROR — {ar.get('error')}")
                continue
            tech = ar.get("technique_scorecard") or []
            tech_s = ", ".join(f"{t['technique']}={t['result']}" for t in tech) or "n/a"
            lines.append(
                f"- **{arm_name}**: recall {ar.get('recalled_n')}/{ar.get('expected_n')} "
                f"= {ar.get('recall_percent')}% · verdict run={ar.get('run_verdict')} "
                f"golden={ar.get('golden_verdict')} match={ar.get('verdict_match')} · {tech_s}"
            )
            if ar.get("case_dir"):
                lines.append(f"  - case_dir: `{ar['case_dir']}`")
        lines.append("")
    lines += [
        "## How to re-run",
        "",
        "```bash",
        "# Offline doctor (no Claude login)",
        "bash scripts/doctor.sh --offline",
        "",
        "# Rulebook arm on the hard-quiz pack",
        "python3 scripts/fair-fight-evtx-scorecard.py --run-rulebook",
        "",
        "# Compare a second arm (e.g. Spark agent case dirs)",
        "python3 scripts/fair-fight-evtx-scorecard.py \\",
        "  --arm rulebook=tmp/auto-runs \\",
        "  --arm spark=/path/to/spark/auto-runs",
        "```",
        "",
        f"Machine-readable: `{out_dir / 'scorecard.json'}`",
        "",
    ]
    md_path = out_dir / "SCORECARD.md"
    md_path.write_text("\n".join(lines), encoding="utf-8")

    print(f"wrote {out_dir / 'scorecard.json'}")
    print(f"wrote {md_path}")
    for arm_name, s in summary_arms.items():
        print(
            f"arm={arm_name} cases_pass={s.get('cases_pass_recall')}/{s.get('cases_scored')} "
            f"techniques={s.get('technique_hits')}/{s.get('technique_total')} "
            f"({s.get('technique_recall_percent')}%)"
        )

    # Exit 0 if every scored rulebook case passes when present; missing is not failure.
    rb = summary_arms.get("rulebook")
    if rb and rb.get("cases_scored", 0) > 0:
        if rb.get("cases_pass_recall", 0) < rb.get("cases_scored", 0):
            return 1
        if rb.get("technique_total", 0) and rb.get("technique_hits", 0) < rb.get("technique_total", 0):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
