#!/usr/bin/env bash
# Private per-dashboard-process capability storage. Source after project-env.sh.

dashboard_capability_file() {
  printf '%s' "${PROJECT_LOCAL:?project-env.sh must be sourced}/state/dashboard-capability"
}

dashboard_exchange_file() {
  printf '%s' "${PROJECT_LOCAL:?project-env.sh must be sourced}/state/dashboard-exchange"
}

dashboard_ed25519_fingerprint() {
  local repo_root="$1"
  command -v uv >/dev/null 2>&1 || return 1
  uv run --quiet --directory "${repo_root}/services/agent" python -c \
    'from findevil_agent.crypto.signer import LocalEd25519Signer; print(LocalEd25519Signer().public_fingerprint())'
}

_dashboard_private_token_python() {
  local token_path="$1" action="$2"
  python3 - "${token_path}" "${action}" <<'PY'
import os
import secrets
import stat
import sys
from pathlib import Path

path = Path(sys.argv[1])
action = sys.argv[2]
path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
parent = os.lstat(path.parent)
if not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode):
    raise SystemExit("dashboard capability parent is not a real directory")
if os.name == "posix" and (parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) & 0o077):
    raise SystemExit("dashboard capability parent is not owner-private")

def read_existing() -> str | None:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise SystemExit("dashboard capability must be one regular, unlinked file")
    if os.name == "posix" and (metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077):
        raise SystemExit("dashboard capability is not owner-private")
    value = path.read_text(encoding="ascii").strip()
    if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise SystemExit("dashboard capability file is invalid")
    return value

if action == "read":
    value = read_existing()
    if value is None:
        raise SystemExit("dashboard capability file is missing")
    print(value)
    raise SystemExit(0)

if action != "rotate":
    raise SystemExit("invalid dashboard capability action")
existing = read_existing()
if existing is not None:
    path.unlink()
value = secrets.token_hex(32)
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
descriptor = os.open(path, flags, 0o600)
with os.fdopen(descriptor, "w", encoding="ascii") as handle:
    handle.write(value + "\n")
    handle.flush()
    os.fsync(handle.fileno())
print(value)
PY
}

dashboard_capability_read() {
  _dashboard_private_token_python "$(dashboard_capability_file)" read
}

dashboard_capability_rotate() {
  _dashboard_private_token_python "$(dashboard_capability_file)" rotate
}

dashboard_exchange_rotate() {
  _dashboard_private_token_python "$(dashboard_exchange_file)" rotate
}

dashboard_authenticated_probe() {
  local base_url="$1" capability="$2"
  DASHBOARD_PROBE_CAPABILITY="${capability}" python3 - "${base_url}" <<'PY'
import os
import sys
import urllib.error
import urllib.request

request = urllib.request.Request(
    sys.argv[1].rstrip("/") + "/api/cases",
    headers={"Cookie": "verdict_dashboard_session=" + os.environ["DASHBOARD_PROBE_CAPABILITY"]},
)
try:
    with urllib.request.urlopen(request, timeout=3) as response:
        raise SystemExit(0 if response.status == 200 else 1)
except (OSError, urllib.error.URLError):
    raise SystemExit(1)
PY
}

dashboard_launch_file() {
  local base_url="$1" next_path="$2" exchange="$3"
  local output="${PROJECT_LOCAL:?project-env.sh must be sourced}/state/dashboard-launch.html"
  python3 - "${base_url}" "${next_path}" "${exchange}" "${output}" <<'PY'
import html
import sys
from pathlib import Path

base, next_path, exchange, raw_output = sys.argv[1:]
output = Path(raw_output)
document = f"""<!doctype html>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; form-action {html.escape(base)}">
<title>Open VERDICT dashboard</title>
<form id="session" method="post" action="{html.escape(base.rstrip('/') + '/api/session')}">
  <input type="hidden" name="token" value="{html.escape(exchange)}">
  <input type="hidden" name="next" value="{html.escape(next_path)}">
  <button type="submit">Open private VERDICT dashboard</button>
</form>
<script>document.getElementById('session').submit()</script>
"""
output.write_text(document, encoding="utf-8")
output.chmod(0o600)
print(output)
PY
}
