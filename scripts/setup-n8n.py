#!/usr/bin/env python3
"""setup-n8n.py — provision the optional n8n automation layer, idempotently.

Called by scripts/install.sh (best-effort, non-fatal) and runnable on its own.
It makes the post-verdict automation reproducible instead of hand-set:

  1. Ensure an n8n instance is reachable at N8N_BASE (optionally `docker run` one).
  2. Ensure an owner account exists (create it on a fresh instance, else log in).
  3. Ensure a REST API key exists (reuse a saved one, else mint one via the
     authenticated session).
  4. (No longer deploys the `findevil-finding-to-action` workflow — superseded by
     grounding-aware routing in scripts/ground_actions.py. The owner + API key
     provisioned here are what scripts/setup-grounding-workflow.py needs.)

Credentials/key are written to gitignored files under tmp/ (the same paths
scripts/n8n_post.py and the dashboard already read):
    tmp/n8n-credentials.txt   (base / email / password)
    tmp/n8n-apikey.txt        (X-N8N-API-KEY value)

BOUNDARY: n8n acts on what the audited product already proved. Its output is
never evidence, never a tool_call_id, never in the audit chain.

Env overrides:
    N8N_BASE            default http://127.0.0.1:5678 (literal loopback only)
    N8N_OWNER_EMAIL     default admin@findevil.local
    N8N_OWNER_PASSWORD  default: generated and saved to tmp/n8n-credentials.txt
    N8N_AUTO_DOCKER=1   start a docker n8n if none is reachable (needs Docker)
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from http.cookiejar import CookieJar
from pathlib import Path

from n8n_security import (
    ensure_private_secret,
    harden_private_file,
    read_private_secret,
    validate_loopback_http_url,
    write_private_text,
)

ROOT = Path(__file__).resolve().parent.parent
TMP = ROOT / "tmp"
CRED_FILE = TMP / "n8n-credentials.txt"
KEY_FILE = TMP / "n8n-apikey.txt"
WEBHOOK_SECRET_FILE = TMP / "n8n-webhook-secret.txt"

BASE = validate_loopback_http_url(
    os.environ.get("N8N_BASE", "http://127.0.0.1:5678")
).rstrip("/")
API = f"{BASE}/api/v1"
EMAIL = os.environ.get("N8N_OWNER_EMAIL", "admin@findevil.local")
N8N_IMAGE = os.environ.get(
    "FINDEVIL_N8N_IMAGE",
    "docker.n8n.io/n8nio/n8n@sha256:"
    "1872cce3548bf4dcfe5aceaf3d9293f4499635823fbdea0ee726bd222d2e44b8",
)
MAX_HTTP_RESPONSE_BYTES = 1024 * 1024


def _require_pinned_image(image: str) -> str:
    name, separator, digest = image.rpartition("@sha256:")
    if not separator or not name or len(digest) != 64:
        raise ValueError("container image must be pinned as name@sha256:<64 hex>")
    try:
        int(digest, 16)
    except ValueError as exc:
        raise ValueError("container image digest must be hexadecimal") from exc
    return image


N8N_IMAGE = _require_pinned_image(N8N_IMAGE)


def log(msg: str) -> None:
    print(f"[setup-n8n] {msg}")


# --- minimal HTTP helpers (cookie session for /rest, api key for /api) --------
_jar = CookieJar()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(_jar), _NoRedirect
)


def _req(method: str, url: str, body=None, api_key: str | None = None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    if api_key:
        r.add_header("X-N8N-API-KEY", api_key)
    try:
        with _opener.open(r, timeout=15) as resp:
            raw = resp.read(MAX_HTTP_RESPONSE_BYTES + 1)
            if len(raw) > MAX_HTTP_RESPONSE_BYTES:
                return 0, {"error": "n8n response exceeded 1 MiB"}
            raw = raw.decode()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw_bytes = e.read(MAX_HTTP_RESPONSE_BYTES + 1)
        if len(raw_bytes) > MAX_HTTP_RESPONSE_BYTES:
            return e.code, {"error": "n8n error response exceeded 1 MiB"}
        raw = raw_bytes.decode(errors="replace")
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"error": raw[:400]}
    except urllib.error.URLError as e:
        return 0, {"error": str(e.reason)}


def build_n8n_docker_command() -> list[str]:
    """Return the reproducible, loopback-only, resource-bounded n8n command."""

    return [
        "docker",
        "run",
        "-d",
        "--name",
        "n8n",
        "--network",
        "findevil-net",
        "--security-opt",
        "no-new-privileges:true",
        "--cap-drop",
        "ALL",
        "--pids-limit",
        "256",
        "--memory",
        "1g",
        "--cpus",
        "2",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=64m",
        "-p",
        "127.0.0.1:5678:5678",
        "-v",
        "n8n_data:/home/node/.n8n",
        "-e",
        "N8N_USER_MANAGEMENT_JWT_DURATION_HOURS=24",
        "-e",
        "N8N_USER_MANAGEMENT_JWT_REFRESH_TIMEOUT_HOURS=-1",
        "-e",
        "N8N_PAYLOAD_SIZE_MAX=1",
        "-e",
        "N8N_CONCURRENCY_PRODUCTION_LIMIT=2",
        "-e",
        "N8N_RUNNERS_MAX_CONCURRENCY=2",
        "-e",
        "EXECUTIONS_TIMEOUT=180",
        "-e",
        "EXECUTIONS_TIMEOUT_MAX=180",
        "-e",
        "N8N_BLOCK_ENV_ACCESS_IN_NODE=true",
        "-e",
        "N8N_DIAGNOSTICS_ENABLED=false",
        "-e",
        "N8N_VERSION_NOTIFICATIONS_ENABLED=false",
        N8N_IMAGE,
    ]


def ensure_reachable() -> bool:
    for _ in range(2):
        status, _ = _req("GET", f"{BASE}/healthz")
        if status == 200:
            return True
        status, _ = _req("GET", f"{BASE}/")
        if status in (200, 401):
            return True
        if os.environ.get("N8N_AUTO_DOCKER") == "1" and shutil.which("docker"):
            log("n8n not reachable — starting a docker container…")
            # Shared network so n8n resolves the local SearXNG sidecar by name.
            # Idempotent: `network create` no-ops if it exists.
            subprocess.run(
                ["docker", "network", "create", "findevil-net"],
                check=False,
                capture_output=True,
                text=True,
            )
            started = subprocess.run(
                build_n8n_docker_command(), check=False, capture_output=True, text=True
            )
            if started.returncode != 0:
                log(f"docker refused to start n8n: {started.stderr.strip()[:300]}")
                break
            for _ in range(30):
                time.sleep(2)
                s, _ = _req("GET", f"{BASE}/")
                if s in (200, 401):
                    return True
        break
    return False


def _gen_password() -> str:
    # n8n requires 8+ chars with a number and an uppercase letter.
    return "Fe" + secrets.token_urlsafe(14).replace("-", "x").replace("_", "y") + "9A"


def ensure_owner_session() -> bool:
    """Create the owner on a fresh instance, else log in. Returns True on a
    usable authenticated session (cookie in _jar)."""
    password = (
        os.environ.get("N8N_OWNER_PASSWORD")
        or (_read_cred("password") if CRED_FILE.exists() else "")
        or _gen_password()
    )

    status, settings = _req("GET", f"{BASE}/rest/settings")
    needs_setup = bool(
        settings.get("data", {}).get("userManagement", {}).get("showSetupOnFirstLoad")
    )

    if needs_setup:
        status, _ = _req(
            "POST",
            f"{BASE}/rest/owner/setup",
            {
                "email": EMAIL,
                "firstName": "Find",
                "lastName": "Evil",
                "password": password,
            },
        )
        if status in (200, 201):
            log(f"created owner {EMAIL}")
            _write_creds(password)
            return True
        log(f"owner setup failed ({status}) — trying login")

    status, _ = _req(
        "POST",
        f"{BASE}/rest/login",
        {
            "emailOrLdapLoginId": EMAIL,
            "password": password,
        },
    )
    if status == 200:
        log(f"logged in as {EMAIL}")
        _write_creds(password)
        return True
    log(
        f"login failed ({status}); set N8N_OWNER_PASSWORD to the existing owner password"
    )
    return False


def ensure_api_key() -> str | None:
    """Reuse a working saved key, else mint one through the authed session."""
    if KEY_FILE.exists():
        try:
            key = read_private_secret(KEY_FILE, minimum_bytes=20)
        except PermissionError:
            try:
                harden_private_file(KEY_FILE)
                key = read_private_secret(KEY_FILE, minimum_bytes=20)
                log("upgraded saved API key permissions to 0600")
            except (PermissionError, ValueError, OSError) as exc:
                log(f"refusing insecure saved API key: {exc}")
                return None
        except (ValueError, OSError) as exc:
            log(f"refusing insecure saved API key: {exc}")
            return None
        status, _ = _req("GET", f"{API}/workflows", api_key=key)
        if status == 200:
            log("reusing existing API key")
            return key

    status, created = _req("POST", f"{BASE}/rest/api-keys", {"label": "findevil-setup"})
    if status in (200, 201):
        d = created.get("data", created)
        key = d.get("rawApiKey") or d.get("apiKey") or d.get("key")
        if key:
            write_private_text(KEY_FILE, key + "\n")
            log("minted API key -> tmp/n8n-apikey.txt")
            return key
    log(
        f"could not mint API key ({status}). Create one in n8n → Settings → API "
        f"and save it to {KEY_FILE.relative_to(ROOT)}"
    )
    return None


def _read_cred(field: str) -> str:
    if not CRED_FILE.exists():
        return ""
    for line in read_private_secret(CRED_FILE).splitlines():
        if line.startswith(f"{field}:"):
            return line.split(":", 1)[1].strip()
    return ""


def _write_creds(password: str) -> None:
    TMP.mkdir(exist_ok=True)
    write_private_text(
        CRED_FILE, f"n8n instance: {BASE}\nemail: {EMAIL}\npassword: {password}\n"
    )


def main() -> int:
    if not ensure_reachable():
        log(
            f"no n8n at {BASE} (optional). Start one: "
            "set N8N_AUTO_DOCKER=1 so this script applies the loopback, digest, "
            "and resource policy. Skipping."
        )
        return 0  # optional component — never fail the install
    try:
        ensure_private_secret(WEBHOOK_SECRET_FILE, minimum_bytes=32)
    except (PermissionError, ValueError, OSError) as exc:
        log(f"refusing insecure webhook capability: {exc}")
        return 0
    if not ensure_owner_session():
        return 0
    key = ensure_api_key()
    if not key:
        return 0
    # NOTE: the `findevil-finding-to-action` workflow (deploy_workflow / WRITE_JS /
    # ACTIONS / JS_CODE below) is SUPERSEDED by grounding-aware routing in
    # scripts/ground_actions.py (host-side, written into grounding.json,
    # human-in-the-loop). Its in-node fs.writeFileSync is also disallowed on
    # n8n 2.x. We no longer deploy it; the owner + API key provisioned above are
    # what the grounding workflow (scripts/setup-grounding-workflow.py) needs.
    log(
        f"done. creds -> {CRED_FILE.relative_to(ROOT)}, key -> {KEY_FILE.relative_to(ROOT)}"
    )
    log(
        "n8n owner + API key ready. Deploy grounding: "
        "python3 scripts/setup-grounding-workflow.py"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
