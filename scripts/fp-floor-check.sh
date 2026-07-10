#!/usr/bin/env bash
# Re-runnable false-positive floor check against synthetic controls.
# Exit 0 when zero Findings and custody verify overall=true.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
OUT_DIR="${1:-$ROOT/.project-local/tmp/fp-floor-check}"
mkdir -p "$OUT_DIR"
export FIND_EVIL_LOCAL=1
EVIDENCE="${FP_FLOOR_EVIDENCE:-$ROOT/fixtures/synthetic-decoy}"
echo "fp-floor-check: evidence=$EVIDENCE"
scripts/verdict "$EVIDENCE" 2>&1 | tee "$OUT_DIR/run.log" | tail -40
CASE="$(rg -o 'tmp/auto-runs/auto-[a-f0-9-]+' "$OUT_DIR/run.log" | tail -1 || true)"
if [[ -z "$CASE" || ! -d "$CASE" ]]; then
  echo "fp-floor-check: FAIL no case dir" >&2
  exit 2
fi
python3 - <<PY
import json, pathlib, sys
case = pathlib.Path("$CASE")
out = pathlib.Path("$OUT_DIR")
v = json.loads((case / "verdict.json").read_text())
mv = json.loads((case / "manifest_verify.json").read_text())
findings = v.get("findings") or v.get("merged_findings") or []
summary = {
    "case_dir": str(case),
    "verdict": v.get("verdict"),
    "finding_count": len(findings),
    "manifest_verify_overall": mv.get("overall"),
    "manifest_signature_verified": mv.get("signature_verified"),
    "ok": (
        len(findings) == 0
        and mv.get("overall") is True
        and mv.get("signature_verified") is True
    ),
}
(out / "summary.json").write_text(json.dumps(summary, indent=2))
print(json.dumps(summary, indent=2))
sys.exit(0 if summary["ok"] else 1)
PY
