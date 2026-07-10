#!/usr/bin/env python3
"""setup-grounding-workflow.py — deploy the `findevil-grounding` n8n workflow.

The ultimate post-verdict DFIR GROUNDING workflow (Phase 1, keyless): given a
case's claimed MITRE techniques, it researches each one against MITRE ATT&CK via
a bounded direct HTTPS request and returns a structured research_bundle
with provenance ({source, url, retrieved_at, excerpt}) in the webhook response.
Claude Code then reads that bundle and JUDGES each claim (supported/unsupported/
contradicted) — n8n itself contains NO LLM.

BOUNDARY: runs AFTER the verdict; output is never evidence, never a tool_call_id,
never in the audit/crypto chain (docs/runbooks/n8n-automation-integration.md).

Phase 2 (keyed) adds abuse.ch/VirusTotal IOC enrichment + open-web search; keys
via scripts/get-api-key.py (browser login).

Design notes:
- n8n 2.x disallows require('fs') in Code nodes, so n8n RETURNS the bundle in the
  webhook response; the host (scripts/ground_verdict.py) persists it.
- A single async Code node loops the techniques via this.helpers.httpRequest —
  avoids per-item pairing fragility of a fan-out HTTP node.

Prereqs: n8n running, API key + webhook capability under tmp/, and n8n + SearXNG
on the private shared Docker network. Run:
    python3 scripts/setup-grounding-workflow.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

from n8n_security import (
    read_private_secret,
    validate_loopback_http_url,
    validate_public_http_url,
    write_private_text,
)

ROOT = Path(__file__).resolve().parent.parent
TMP = ROOT / "tmp"
BASE = validate_loopback_http_url(
    os.environ.get("N8N_BASE", "http://127.0.0.1:5678")
).rstrip("/")
API = f"{BASE}/api/v1"
KEY_FILE = TMP / "n8n-apikey.txt"
WEBHOOK_SECRET_FILE = TMP / "n8n-webhook-secret.txt"
WF_NAME = "findevil-grounding"
WEBHOOK_PATH = "findevil-grounding"
WEBHOOK_CREDENTIAL_NAME = "findevil-grounding-webhook-auth"
WEBHOOK_HEADER = "X-Findevil-Grounding-Token"
NET = "findevil-net"  # user-defined network so n8n resolves SearXNG by name
SEARXNG = "http://searxng:8080"  # container-name DNS on the shared net (open-web)
SEARXNG_IMAGE = os.environ.get(
    "FINDEVIL_SEARXNG_IMAGE",
    "searxng/searxng@sha256:"
    "e4fade70be2f6a985178de7158c96fdb98d897500c548b3afc6e2033cf1c11e3",
)
SEARXNG_NAME = "searxng"
SEARXNG_SETTINGS = TMP / "searxng" / "settings.yml"
CONTAINER_IMAGES = (SEARXNG_IMAGE,)
MAX_API_RESPONSE_BYTES = 1024 * 1024


def _require_pinned_images() -> None:
    for image in CONTAINER_IMAGES:
        name, separator, digest = image.rpartition("@sha256:")
        if not separator or not name or len(digest) != 64:
            raise ValueError(
                f"container image must be pinned by sha256 digest: {image}"
            )
        try:
            int(digest, 16)
        except ValueError as exc:
            raise ValueError(f"invalid container image digest: {image}") from exc


_require_pinned_images()

# Single async Code node. It accepts a tightly bounded body, fetches only the
# exact MITRE host with automatic redirects disabled, and treats SearXNG result
# URLs as inert metadata. Arbitrary search-result URLs are never rendered.
RESEARCH_JS = r"""
const MAX_BODY_BYTES = 65536;
const MAX_TECHNIQUES = 16;
const MAX_QUERIES = 4;
const MAX_QUERY_CHARS = 160;
const MAX_CLAIM_CHARS = 512;
const MAX_HTML_CHARS = 1048576;
const MAX_REDIRECTS = 2;
const envelope = $input.first().json;
const body = envelope && envelope.body ? envelope.body : envelope;
if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('invalid request body');
if (Buffer.byteLength(JSON.stringify(body), 'utf8') > MAX_BODY_BYTES) throw new Error('request body too large');
const caseId = String(body.case_id || '').trim();
if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(caseId)) throw new Error('invalid case_id');
if (!Array.isArray(body.techniques) || body.techniques.length > MAX_TECHNIQUES) throw new Error('too many techniques');
if (body.queries != null && (!Array.isArray(body.queries) || body.queries.length > MAX_QUERIES)) throw new Error('too many queries');

const blockedNames = new Set(['localhost', 'metadata', 'metadata.google.internal',
  'metadata.azure.internal', 'instance-data.ec2.internal']);
const blockedSuffixes = ['.localhost', '.local', '.internal', '.home', '.lan', '.test', '.invalid', '.example'];
function validatePublicUrl(raw, exactHost = null) {
  const text = String(raw || '');
  if (!text || text.length > 2048 || /[\u0000-\u0020\u007f]/.test(text)) throw new Error('invalid URL');
  const u = new URL(text);
  if (!['http:', 'https:'].includes(u.protocol)) throw new Error('URL scheme forbidden');
  if (u.username || u.password) throw new Error('URL credentials forbidden');
  const host = u.hostname.replace(/\.$/, '').toLowerCase();
  if (!host || blockedNames.has(host) || blockedSuffixes.some(s => host.endsWith(s))) throw new Error('internal URL forbidden');
  // URL canonicalization turns IPv4 integer/octal/hex spellings into dotted
  // form. Reject every literal IP; open-web URLs are metadata only and do not
  // need literal-address support.
  if (host.includes(':') || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) throw new Error('IP literal forbidden');
  if (exactHost && host !== exactHost) throw new Error('redirect host forbidden');
  u.hash = '';
  return u;
}

async function requestMitre(startUrl) {
  let current = validatePublicUrl(startUrl, 'attack.mitre.org');
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const r = await this.helpers.httpRequest({
      method: 'GET', url: current.toString(), returnFullResponse: true,
      timeout: 15000, maxRedirects: 0, ignoreHttpStatusErrors: true,
      maxContentLength: MAX_HTML_CHARS, maxBodyLength: MAX_HTML_CHARS,
      headers: { 'User-Agent': 'VERDICT-grounding/1' },
    });
    const status = Number(r && (r.statusCode || r.status) || 0);
    if (status >= 300 && status < 400) {
      const headers = (r && r.headers) || {};
      const location = headers.location || headers.Location;
      if (!location || hop === MAX_REDIRECTS) throw new Error('unsafe redirect');
      current = validatePublicUrl(new URL(String(location), current).toString(), 'attack.mitre.org');
      continue;
    }
    const html = String((r && r.body != null) ? r.body : '');
    if (html.length > MAX_HTML_CHARS) throw new Error('MITRE response too large');
    return { html, url: current.toString(), status };
  }
  throw new Error('redirect limit exceeded');
}

const decode = (s) => String(s || '')
  .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
  .replace(/&quot;/g, '"').replace(/&#0?39;/g, "'").replace(/&#x27;/gi, "'")
  .replace(/&nbsp;/g, ' ');
const research = [];
for (const t of body.techniques) {
  if (t == null || (typeof t !== 'string' && typeof t !== 'object') || Array.isArray(t)) throw new Error('invalid technique item');
  const id = String((t && t.id) ? t.id : t).trim().toUpperCase();
  const claimText = String((t && t.claim) || '').trim();
  if (claimText.length > MAX_CLAIM_CHARS) throw new Error('technique claim too long');
  const claim = claimText || null;
  if (!/^T\d{4}(\.\d{3})?$/.test(id)) {
    research.push({ technique_id: id.slice(0, 32), claim, found: false, mitre_name: null,
      excerpt: 'malformed technique id (not T#### / T####.###)', sources: [] });
    continue;
  }
  const parts = id.split('.');
  const requestedUrl = parts.length === 2
    ? `https://attack.mitre.org/techniques/${parts[0]}/${parts[1]}/`
    : `https://attack.mitre.org/techniques/${id}/`;
  let html = '';
  let finalUrl = requestedUrl;
  let error = null;
  try {
    const fetched = await requestMitre.call(this, requestedUrl);
    html = fetched.html;
    finalUrl = fetched.url;
  } catch (e) {
    error = 'fetch:' + String(e && (e.message || e)).slice(0, 120);
  }
  const titleMatch = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  const title = decode(titleMatch ? titleMatch[1].replace(/\s+/g, ' ').trim() : '');
  const notFound = /page not found/i.test(html) || /^404\b/.test(title);
  const servedMatch = title.match(/\b(T\d{4}(?:\.\d{3})?)\b/i);
  const servedId = servedMatch ? servedMatch[1].toUpperCase() : null;
  const found = !notFound && !!servedId;
  const idMatch = found && servedId === id;
  const name = found ? ((title.split(/,\s*(?:sub-?technique|technique)\b/i)[0] || '').trim() || null) : null;
  let desc = null;
  const md = html.match(/<meta\s+name=["']description["']\s+content=["']([^"']+)["']/i);
  if (md) desc = decode(md[1]);
  if (!desc) { const p = html.match(/<p[^>]*>([\s\S]{40,600}?)<\/p>/i); if (p) desc = decode(p[1]); }
  if (desc) desc = desc.replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ').replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ').trim().slice(0, 600);
  const entry = { technique_id: id, claim, found, id_match: idMatch, mitre_id: servedId,
    mitre_name: name, excerpt: desc,
    sources: [{ source: 'mitre_attack', url: finalUrl, retrieved_at: new Date().toISOString() }] };
  if (error) entry.error = error;
  research.push(entry);
}

// SearXNG receives only bounded search text. Returned URLs are validated and
// preserved as inert metadata; they are deliberately never fetched/rendered.
const queries = body.queries || [];
const openWeb = [];
for (const q of queries) {
  const term = String((q && q.query) ? q.query : q).trim();
  if (!term || term.length > MAX_QUERY_CHARS) throw new Error('invalid query');
  try {
    const sr = await this.helpers.httpRequest({
      method: 'GET',
      url: 'http://searxng:8080/search?format=json&categories=general&q=' + encodeURIComponent(term),
      returnFullResponse: true, timeout: 15000, maxRedirects: 0,
      maxContentLength: MAX_HTML_CHARS, maxBodyLength: MAX_HTML_CHARS,
    });
    const raw = (sr && sr.body != null) ? sr.body : {};
    const data = (typeof raw === 'object') ? raw : JSON.parse(String(raw || '{}'));
    const hits = Array.isArray(data.results) ? data.results.slice(0, 4) : [];
    const results = [];
    for (const hit of hits) {
      try {
        const safe = validatePublicUrl(hit && hit.url).toString();
        results.push({ url: safe, title: String(hit.title || '').slice(0, 200),
          snippet: String(hit.content || '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').slice(0, 400),
          source: 'open_web', rendered: false });
      } catch (_) { /* unsafe result is omitted, never requested */ }
    }
    openWeb.push({ query: term, results, retrieved_at: new Date().toISOString() });
  } catch (e) {
    openWeb.push({ query: term, results: [], error: 'searxng:' + String(e && (e.message || e)).slice(0, 120) });
  }
}

return [{ json: { case_id: caseId, generated_at: new Date().toISOString(),
  source: 'n8n findevil-grounding (operator aid; not evidence, not in audit chain)',
  technique_research: research, open_web_research: openWeb } }];
""".strip()


def build_workflow(credential_id: str) -> dict:
    nodes = [
        {
            "id": "wh",
            "name": "Grounding webhook",
            "type": "n8n-nodes-base.webhook",
            "typeVersion": 2,
            "position": [0, 0],
            "parameters": {
                "httpMethod": "POST",
                "path": WEBHOOK_PATH,
                "authentication": "headerAuth",
                "responseMode": "responseNode",
                "options": {},
            },
            "credentials": {
                "httpHeaderAuth": {
                    "id": credential_id,
                    "name": WEBHOOK_CREDENTIAL_NAME,
                }
            },
        },
        {
            "id": "research",
            "name": "Research techniques (bounded public fetches)",
            "type": "n8n-nodes-base.code",
            "typeVersion": 2,
            "position": [260, 0],
            "parameters": {"language": "javaScript", "jsCode": RESEARCH_JS},
        },
        {
            "id": "resp",
            "name": "Respond",
            "type": "n8n-nodes-base.respondToWebhook",
            "typeVersion": 1.1,
            "position": [520, 0],
            "parameters": {"respondWith": "json", "responseBody": "={{ $json }}"},
        },
    ]
    connections = {}
    for before, after in zip(nodes, nodes[1:]):
        connections[before["name"]] = {
            "main": [[{"node": after["name"], "type": "main", "index": 0}]]
        }
    return {
        "name": WF_NAME,
        "nodes": nodes,
        "connections": connections,
        "settings": {"executionOrder": "v1"},
    }


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_API_OPENER = urllib.request.build_opener(_NoRedirect)


def req(method, url, body=None, key: str | None = None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    if key:
        r.add_header("X-N8N-API-KEY", key)
    try:
        with _API_OPENER.open(r, timeout=20) as resp:
            raw = resp.read(MAX_API_RESPONSE_BYTES + 1)
            if len(raw) > MAX_API_RESPONSE_BYTES:
                return 0, {"error": "n8n API response exceeded 1 MiB"}
            raw = raw.decode()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        return e.code, {"error": e.read(501).decode(errors="replace")[:500]}


def _docker(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args], check=False, capture_output=True, text=True
    )


def _running(name: str) -> bool:
    out = _docker("ps", "--filter", f"name=^{name}$", "--format", "{{.Names}}").stdout
    return name in out.split()


def _assert_running_image(name: str, image: str) -> None:
    actual = _docker("inspect", "--format", "{{.Image}}", name).stdout.strip()
    expected = _docker("image", "inspect", "--format", "{{.Id}}", image).stdout.strip()
    if not expected:
        raise RuntimeError(
            f"cannot verify pinned image for running container {name}; pull {image} first"
        )
    if actual != expected:
        raise RuntimeError(
            f"running container {name} does not use the configured pinned image"
        )


def build_searxng_docker_command() -> list[str]:
    return [
        "run",
        "-d",
        "--name",
        SEARXNG_NAME,
        "--network",
        NET,
        "--security-opt",
        "no-new-privileges:true",
        "--cap-drop",
        "ALL",
        "--pids-limit",
        "128",
        "--memory",
        "512m",
        "--cpus",
        "1",
        "-v",
        f"{SEARXNG_SETTINGS}:/etc/searxng/settings.yml:ro",
        SEARXNG_IMAGE,
    ]


def _ensure_searxng() -> None:
    """Start a self-hosted SearXNG (open-web search) on the shared net.

    Public SERPs block headless browsers (anti-bot), so we run our own search
    engine: keyless, JSON output, no upstream blocking for low-volume grounding.
    Writes a settings.yml (JSON format on, limiter off, random secret) if absent.
    """
    if _running(SEARXNG_NAME):
        _assert_running_image(SEARXNG_NAME, SEARXNG_IMAGE)
        _docker("network", "connect", NET, SEARXNG_NAME)
        return
    if not SEARXNG_SETTINGS.is_file():
        import secrets

        SEARXNG_SETTINGS.parent.mkdir(parents=True, exist_ok=True)
        write_private_text(
            SEARXNG_SETTINGS,
            "use_default_settings: true\n"
            "server:\n"
            f'  secret_key: "{secrets.token_hex(24)}"\n'
            "  limiter: false\n"
            "  image_proxy: false\n"
            '  method: "GET"\n'
            "search:\n"
            "  safe_search: 0\n"
            "  formats:\n"
            "    - html\n"
            "    - json\n",
        )
    _docker("rm", "-f", SEARXNG_NAME)
    print(f"  starting {SEARXNG_NAME} on {NET}…")
    started = _docker(*build_searxng_docker_command())
    if started.returncode != 0:
        raise RuntimeError(f"failed to start SearXNG: {started.stderr.strip()[:300]}")


def ensure_infra() -> None:
    """Wire the shared Docker network so n8n can reach SearXNG by name.

    Idempotent and best-effort: creates `findevil-net`, starts SearXNG with a
    private-network-only search endpoint, and attaches a running n8n
    container. Browserless is intentionally not started: accepting arbitrary
    render URLs would reintroduce an SSRF service that this workflow does not need.
    """
    if not shutil.which("docker"):
        print(
            f"  WARN: docker not found — ensure SearXNG is reachable at {SEARXNG} "
            "from n8n before triggering the workflow."
        )
        return
    _docker("network", "create", NET)
    _ensure_searxng()
    if _running("n8n"):
        _docker("network", "connect", NET, "n8n")
    print(
        f"  infra ready: network {NET}, {SEARXNG_NAME} ({SEARXNG}); "
        "MITRE is fetched directly with redirect/size guards"
    )


def ensure_webhook_credential(key: str, secret: str) -> str:
    status, listed = req("GET", f"{API}/credentials?limit=250", key=key)
    if status != 200:
        raise RuntimeError(f"could not list n8n credentials (HTTP {status})")
    for credential in listed.get("data", []):
        if credential.get("name") == WEBHOOK_CREDENTIAL_NAME:
            deleted, _ = req("DELETE", f"{API}/credentials/{credential['id']}", key=key)
            if deleted not in (200, 204):
                raise RuntimeError(
                    f"could not replace webhook credential (HTTP {deleted})"
                )
    status, created = req(
        "POST",
        f"{API}/credentials",
        {
            "name": WEBHOOK_CREDENTIAL_NAME,
            "type": "httpHeaderAuth",
            "data": {"name": WEBHOOK_HEADER, "value": secret},
        },
        key=key,
    )
    credential_id = created.get("id") if isinstance(created, dict) else None
    if status not in (200, 201) or not credential_id:
        raise RuntimeError(f"could not create webhook credential (HTTP {status})")
    return str(credential_id)


def main() -> int:
    try:
        key = read_private_secret(KEY_FILE, minimum_bytes=20)
        secret = read_private_secret(WEBHOOK_SECRET_FILE, minimum_bytes=32)
    except (FileNotFoundError, PermissionError, ValueError, OSError) as exc:
        print(f"  SECURITY REFUSAL: {exc}")
        print("  run: N8N_AUTO_DOCKER=1 python3 scripts/setup-n8n.py")
        return 1
    try:
        ensure_infra()
        validate_public_http_url("https://attack.mitre.org/", resolve=True)
    except RuntimeError as exc:
        print(f"  INFRA FAILED: {exc}")
        return 1
    except ValueError as exc:
        print(f"  SOURCE VALIDATION FAILED: {exc}")
        return 1
    status, lst = req("GET", f"{API}/workflows", key=key)
    if status != 200:
        print(f"  WORKFLOW LIST FAILED: HTTP {status}")
        return 1
    for w in lst.get("data", []):
        if w.get("name") == WF_NAME:
            deleted, _ = req("DELETE", f"{API}/workflows/{w['id']}", key=key)
            if deleted not in (200, 204):
                print(f"  DELETE FAILED: HTTP {deleted}")
                return 1
            print(f"  removed prior {WF_NAME} ({w['id']})")
    try:
        credential_id = ensure_webhook_credential(key, secret)
    except RuntimeError as exc:
        print(f"  CREDENTIAL FAILED: {exc}")
        return 1
    status, created = req(
        "POST", f"{API}/workflows", build_workflow(credential_id), key=key
    )
    if status not in (200, 201):
        print("CREATE FAILED:", status, json.dumps(created)[:600])
        return 1
    wid = created["id"]
    activated, activation = req("POST", f"{API}/workflows/{wid}/activate", {}, key=key)
    if activated not in (200, 201):
        print("ACTIVATE FAILED:", activated, json.dumps(activation)[:600])
        return 1
    print(f"  deployed + activated {WF_NAME} ({wid})")
    print(f"  webhook: {BASE}/webhook/{WEBHOOK_PATH}")
    print(f"  auth: {WEBHOOK_HEADER} from {WEBHOOK_SECRET_FILE.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
