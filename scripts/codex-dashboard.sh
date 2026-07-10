#!/usr/bin/env bash
set -euo pipefail

PORT="${1:-3000}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/project-env.sh
source "${REPO_ROOT}/scripts/lib/project-env.sh"
# shellcheck source=lib/dashboard-capability.sh
source "${REPO_ROOT}/scripts/lib/dashboard-capability.sh"
CODEX_URL="http://localhost:${PORT}/codex"
LOG_DIR="${TMPDIR:-/tmp}/opencode"
OUT_LOG="${LOG_DIR}/findevil-codex-dashboard.out"
ERR_LOG="${LOG_DIR}/findevil-codex-dashboard.err"

mkdir -p "$LOG_DIR"

is_up() {
  python - "$CODEX_URL" <<'PY'
import sys
import urllib.request

try:
    with urllib.request.urlopen(sys.argv[1], timeout=3) as response:
        raise SystemExit(0 if response.status == 200 else 1)
except Exception:
    raise SystemExit(1)
PY
}

if ! is_up; then
  DASHBOARD_CAPABILITY="$(dashboard_capability_rotate)"
  DASHBOARD_ED25519_PIN="${FINDEVIL_ED25519_EXPECTED_FINGERPRINT:-}"
  if [ -z "${DASHBOARD_ED25519_PIN}" ]; then
    DASHBOARD_ED25519_PIN="$(dashboard_ed25519_fingerprint "${REPO_ROOT}")"
  fi
  [[ "${DASHBOARD_ED25519_PIN}" =~ ^[0-9a-f]{64}$ ]] \
    || { printf 'The trusted Ed25519 dashboard pin is missing or invalid.\n' >&2; exit 1; }
  (
    cd "$REPO_ROOT"
    FINDEVIL_CODEX_UI_ENABLE=1 \
    FINDEVIL_DASHBOARD_CAPABILITY="${DASHBOARD_CAPABILITY}" \
    FINDEVIL_DASHBOARD_EXCHANGE_FILE="$(dashboard_exchange_file)" \
    FINDEVIL_ED25519_EXPECTED_FINGERPRINT="${DASHBOARD_ED25519_PIN}" \
      pnpm --filter @findevil/web dev -- --hostname 127.0.0.1 --port "$PORT" >"$OUT_LOG" 2>"$ERR_LOG" &
  )

  for _ in $(seq 1 30); do
    if is_up; then
      break
    fi
    sleep 0.5
  done
else
  DASHBOARD_CAPABILITY="$(dashboard_capability_read)" \
    || { printf 'Dashboard is running without this operator session capability; refusing access.\n' >&2; exit 1; }
fi

if ! is_up; then
  printf 'Find Evil dashboard did not start. Logs: %s %s\n' "$OUT_LOG" "$ERR_LOG" >&2
  exit 1
fi

if ! dashboard_authenticated_probe "http://127.0.0.1:${PORT}" "${DASHBOARD_CAPABILITY}"; then
  printf 'Dashboard did not accept this launcher session; refusing access.\n' >&2
  exit 1
fi
DASHBOARD_EXCHANGE="$(dashboard_exchange_rotate)"
BROWSER_BASE="http://verdict-${DASHBOARD_EXCHANGE:0:16}.localhost:${PORT}"
LAUNCH_FILE="$(dashboard_launch_file "${BROWSER_BASE}" "/codex" "${DASHBOARD_EXCHANGE}")"

if command -v xdg-open >/dev/null 2>&1; then
  xdg-open "$LAUNCH_FILE" >/dev/null 2>&1 || true
elif command -v open >/dev/null 2>&1; then
  open "$LAUNCH_FILE" >/dev/null 2>&1 || true
fi

printf 'Dashboard is running:\n'
printf -- '- Codex cockpit: %s/codex (private browser session opened)\n' "$BROWSER_BASE"
printf -- '- Audit dashboard: %s/\n' "$BROWSER_BASE"
printf -- '- Debug stream: %s/debug\n' "$BROWSER_BASE"
printf -- '- Logs: %s %s\n' "$OUT_LOG" "$ERR_LOG"
