#!/usr/bin/env bash
# scripts/nhc003-carve-status.sh — honest status for nhc-003 free-space carve measurement.
#
# Never prints a recall percentage. Never claims SCHARDT improvement without
# a real image + bulk_extractor + recovered content path.
#
# Exit codes:
#   0 — STATUS=UNMEASURED (normal when prerequisites missing) or STATUS=PROBE_OK
#       (binary+image present and a probe ran without tool failure)
#   1 — STATUS=ERROR (tool failure when a probe was attempted)
#
# Env:
#   NHC003_IMAGE / VERDICT_SCHARDT_IMAGE — override path to disk image
#   NHC003_SKIP_PROBE=1 — only check prerequisites, never run bulk_extractor
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

have_bin=0
have_img=0
bin_path=""
img_path=""

if command -v bulk_extractor >/dev/null 2>&1; then
  have_bin=1
  bin_path="$(command -v bulk_extractor)"
fi

for cand in \
  "${NHC003_IMAGE:-}" \
  "${VERDICT_SCHARDT_IMAGE:-}" \
  "${ROOT}/evidence/SCHARDT.dd" \
  "${ROOT}/evidence/SCHARDT.E01" \
  "${ROOT}/evidence/cases/SCHARDT.dd"
do
  if [ -n "${cand}" ] && [ -f "${cand}" ]; then
    have_img=1
    img_path="${cand}"
    break
  fi
done

echo "nhc003-carve-status"
echo "  bulk_extractor: $([ "$have_bin" = 1 ] && echo "yes ($bin_path)" || echo "no")"
echo "  schardt_image:  $([ "$have_img" = 1 ] && echo "yes ($img_path)" || echo "no (set NHC003_IMAGE or place evidence/SCHARDT.dd)")"
echo "  note: synthetic carve smoke is separate (bulk_extract_smoke); this script never claims recall %"

if [ "$have_bin" != 1 ] || [ "$have_img" != 1 ]; then
  echo "STATUS=UNMEASURED"
  echo "reason: missing prerequisites for an end-to-end nhc-003 measurement"
  exit 0
fi

if [ "${NHC003_SKIP_PROBE:-0}" = "1" ]; then
  echo "STATUS=UNMEASURED"
  echo "reason: prerequisites present but NHC003_SKIP_PROBE=1 (no probe run)"
  exit 0
fi

# Bounded probe: only proves the image is readable by bulk_extractor, not golden match.
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
# tiny timeout: status probe, not a full SCHARDT score
set +e
timeout 120 bulk_extractor -q -j 1 -o "$tmp/out" -E find \
  -F <(printf '%s\n' 'intrusion' 'hacking' '@') \
  -- "$img_path" >/tmp/nhc003-probe.log 2>&1
rc=$?
set -e

if [ "$rc" -eq 124 ]; then
  echo "STATUS=UNMEASURED"
  echo "reason: bulk_extractor probe timed out (image present; measurement not completed)"
  exit 0
fi
if [ "$rc" -ne 0 ]; then
  echo "STATUS=ERROR"
  echo "reason: bulk_extractor exited $rc (see probe log if retained)"
  tail -5 /tmp/nhc003-probe.log 2>/dev/null || true
  exit 1
fi

# Even on success we do NOT assert golden nhc-003 match here.
feat_lines=0
if [ -f "$tmp/out/find.txt" ]; then
  feat_lines="$(grep -cv '^#' "$tmp/out/find.txt" 2>/dev/null || echo 0)"
fi
echo "  probe_find_rows: ${feat_lines}"
echo "STATUS=UNMEASURED"
echo "reason: probe completed but golden nhc-003 match is not scored by this script"
exit 0
