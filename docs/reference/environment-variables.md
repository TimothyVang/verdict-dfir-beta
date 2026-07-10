# Environment Variables — reference

> **Status: ACTIVE.** The full env-var surface for running VERDICT, grouped by purpose. Each
> row names the default and which script/component reads it. Defaults are what the code ships;
> when in doubt, grep the script.

## Credentials (Amendment A1 — one of three, priority order)

| Var | Default | Read by | Notes |
|---|---|---|---|
| `CLAUDE_CODE_OAUTH_TOKEN` | unset | `install.sh`, `doctor.sh` | Preferred non-interactive mode (`claude setup-token`) |
| *(interactive `~/.claude/`)* | — | `install.sh` | Dev default if a Claude Code login exists |
| `ANTHROPIC_API_KEY` | unset | `install.sh` | Fallback mode 3 — direct metered API |

## Run mode / dashboard

| Var | Default | Read by | Purpose |
|---|---|---|---|
| `FIND_EVIL_LOCAL` | unset | `scripts/verdict` (set internally) | Enables live dashboard streaming to :3000 + pins `case_id` so the dashboard can open before the run finishes |
| `FINDEVIL_REPO_ROOT` | repo root | dashboard (`apps/web`) | Lets the dashboard serve audit JSONL from any case dir |
| `FINDEVIL_DASHBOARD_EXTRA_ROOTS` | unset | dashboard | Additional allowed roots for case paths (e.g. `tmp/auto-runs`) |
| `PYTHONPATH` | prepended `services/agent` | `scripts/verdict` (local mode) | Resolves the agent package in `FIND_EVIL_LOCAL=1` |
| `FINDEVIL_L1_DOCKER` | unset | dashboard build | Disables some Next.js optimizations for CI Docker |
| `FIND_EVIL_FAULT_INJECT` | unset | `find_evil_auto.py` (verify stage) | Demo/showcase fault hook: `verifier_reject_once:<finding-id-fragment>` corrupts ONE verify replay's tool name on the first attempt so the verifier rejects and the re-dispatch loop recovers — live, on camera. Inert by default; never silent (audited `fault_injection` record + stderr banner) |
| `FIND_EVIL_REQUIRE_ASSERTED_VALUES` | unset (`1` to enable) | `events.Finding` validator | Fact-fidelity (R3) gate: when `1`, a CONFIRMED finding MUST declare `asserted_values` and an INFERRED finding MUST declare `asserted_values` or `derived_from`, so the verifier's entailment check can re-extract each value. Default-off until the finding emitters populate the field. |
| `FIND_EVIL_REQUIRE_COUNTER_HYPOTHESIS` | unset (`1` to enable) | `judge.judge_findings` | Counter-hypothesis gate: when `1`, a solo (single-pool, uncorroborated) CONFIRMED finding collapses to INFERRED unless cross-pool corroboration raises it back — a CONFIRMED claim must survive the other pool's challenge. Default-off; trades recall for a stricter corroboration bar (the verifier + ≥2-artifact-class gate already cover this in the default pipeline). |
| `FIND_EVIL_REQUIRE_ARTIFACT_REBIND` | unset (`1` to enable) | `verifier.reverify_finding` | Evidence re-binding gate: when `1`, the verifier re-derives the artifact from the cited tool_call's recorded `*_path` argument(s) and REJECTS (`drift_class=artifact_rebind_mismatch`) a finding whose claimed `artifact_path` does not match what the cited call read — hardens against a real `tool_call_id` glued to a fabricated artifact. A preflight (runs before replay); a call with no `*_path` argument is not gated. Default-off until finding emitters set `artifact_path` to the cited call's path. |
| `FIND_EVIL_REQUIRE_COUNTER_HYPOTHESIS_FINDING` | unset (`1` to enable) | `events.Finding` validator + `verifier.reverify_finding` | Anti-coherence "too clean" gate: when `1`, a CONFIRMED finding MUST carry a non-blank `counter_hypothesis` (the benign alternative it ruled out); the schema validator rejects construction and the verifier preflight rejects re-verify (`drift_class=counter_hypothesis_missing`). Binds only CONFIRMED (the strongest tier); lower tiers exempt. Complements the judge.py `FIND_EVIL_REQUIRE_COUNTER_HYPOTHESIS` discipline. Default-off until emitters populate the field. |

## SIFT VM (`--sift` mode)

| Var | Default | Read by | Purpose |
|---|---|---|---|
| `FIND_EVIL_GUEST_IP` / `SIFT_VM_IP` | `192.168.x.x` | `find-evil-sift`, `.mcp.json.sift` | SIFT VM IP (rewritten into `.mcp.json.sift`) |
| `FIND_EVIL_GUEST_USER` / `GUEST_USER` | `sansforensics` | `find-evil-sift` | SSH user on the VM |
| `FIND_EVIL_SSH_KEY` / `SIFT_SSH_KEY` | `~/.ssh/sift_key` | `find-evil-sift` | SSH private key |
| `FIND_EVIL_GUEST_REPO` / `GUEST_REPO_PATH` | `/home/sansforensics/find-evil` | `find-evil-sift` | Repo path inside the VM |
| `FIND_EVIL_GUEST_MOUNT_BIN` | unset | `find-evil-sift` | Passwordless-sudo mount wrapper on the VM (`disk_mount`, SIFT only) |
| `OVA_PATH` | repo-root `*.ova` | `sift-vm-bootstrap.sh` | Override SIFT OVA location |
| `FINDEVIL_SETUP_SIFT` | unset | `install.sh` | Non-interactive: build the SIFT VM without prompting |
| `FINDEVIL_SKIP_SIFT` | unset | `install.sh` | Skip SIFT VM setup |
| `FINDEVIL_SIGNER` | `ed25519` | `make_signer` (manifest sealing) | Signer tier: `ed25519` (real local signature, verifies offline with a trusted external fingerprint), `sigstore` (identity + transparency log; customer tier), `stub` (dev placeholder) |
| `FINDEVIL_SIGNING_KEY` | `${FINDEVIL_HOME}/signing.key` under project launchers | `LocalEd25519Signer` | Path to the local Ed25519 private key (auto-generated on first use, `0600`); never passed to the Docker parser runtime. |
| `FINDEVIL_ED25519_EXPECTED_FINGERPRINT` | unset (launcher injects the trusted local pin where needed) | manifest/dashboard verifiers | Out-of-band SHA-256 of the trusted Ed25519 public key. Verification fails closed when the Ed25519 tier has no explicit or environment pin; never populate this from the manifest under test. |

Existing custody directories must be owned by the current user and are kept at
`0700`; custody files are `0600`. Run `bash scripts/setup` after moving or
upgrading a checkout. An unsafe existing signing key is refused—not silently
chmodded—so inspect/rotate it or explicitly restore a verified key to `0600`.

## Docker DFIR backend (`--docker`)

| Var | Default | Purpose |
|---|---|---|
| `FINDEVIL_DFIR_IMAGE` | `findevil/dfir:local` | Reviewed local image name. |
| `FINDEVIL_DFIR_GHCR` | unset | Optional remote image; must be an immutable `image@sha256:<digest>` reference. |
| `FINDEVIL_DFIR_ALLOW_LOCAL_BUILD` | `0` | Set to `1` to explicitly approve a networked build of the pinned Dockerfile when no local image exists. |
| `FINDEVIL_DFIR_CONTAINER` | `findevil-dfir` | Base container name; `scripts/verdict` derives a case-scoped name from it. |
| `FINDEVIL_DFIR_ALLOW_MISSING` | `0` | Development-only escape hatch for a deliberately partial image; never use to suppress a failed production preflight. |
| `FINDEVIL_DFIR_PROBE_TIMEOUT` | `30` seconds | Per-parser preflight ceiling. |
| `FINDEVIL_DFIR_PREFLIGHT_TIMEOUT` | `120` seconds | Whole disposable preflight ceiling. |
| `FINDEVIL_DFIR_HEALTH_TIMEOUT` | `90` seconds | Mounted-runtime healthy-state deadline. |
| `FINDEVIL_DFIR_DOCKER_TIMEOUT` | `10` seconds | Short Docker control-plane operation ceiling. |
| `FINDEVIL_DFIR_MEMORY_LIMIT` / `FINDEVIL_DFIR_CPU_LIMIT` / `FINDEVIL_DFIR_PIDS_LIMIT` | `4g` / `2.0` / `512` | Evidence runtime cgroup ceilings. |
| `FINDEVIL_DFIR_PREFLIGHT_MEMORY_LIMIT` / `FINDEVIL_DFIR_PREFLIGHT_CPU_LIMIT` | `2g` / `2.0` | Disposable parser-probe ceilings (`pids=256` is fixed). |
| `FINDEVIL_DFIR_BUILD_MEMORY_LIMIT` / `FINDEVIL_DFIR_BUILD_CPU_LIMIT` / `FINDEVIL_DFIR_BUILD_PIDS_LIMIT` | `6g` / `4.0` / `512` | Dependency-fetch/offline-compile cgroup ceilings. |
| `FINDEVIL_DFIR_BUILD_FETCH_TIMEOUT` / `FINDEVIL_DFIR_BUILD_TIMEOUT` | `900` / `1800` seconds | Locked dependency-fetch and offline-compile deadlines. |
| `FINDEVIL_DFIR_BUILD_TMPFS_LIMIT` | `8g` | Hard ceiling for fresh Cargo home, registry, and target state. |
| `FINDEVIL_DFIR_BUILD_LOG_MAX_BYTES` / `FINDEVIL_DFIR_BUILD_BINARY_MAX_BYTES` | `8388608` / `268435456` | Hard streamed-output ceilings for each build log and the exported MCP binary. |
| `FINDEVIL_DFIR_PARSER_STATE_LIMIT` / `FINDEVIL_DFIR_RUST_STATE_LIMIT` | `2g` / `512m` | Hard tmpfs ceilings for case parser staging and Rust runtime state. |
| `FINDEVIL_DFIR_KEEP_RUNTIME_STATE` | `0` | `1` retains the bounded host handoff directory for debugging; the evidence container is still removed. |

The launcher rejects remote Docker daemons, mutable remote image tags, ambient
Docker proxy injection, and evidence that overlaps repository/custody state.
`FINDEVIL_DFIR_CASE_ID` is an internal reservation passed by `scripts/verdict`,
not an operator-facing override.

## Hostile-artifact resource ceilings

| Var | Default | Hard behavior |
|---|---|---|
| `FINDEVIL_BROWSER_DB_MAX_BYTES` | `2147483648` | Maximum browser SQLite file size. |
| `FINDEVIL_BROWSER_FIELD_MAX_BYTES` | `1048576` | SQLite value-length ceiling (also capped at `i32::MAX`). |
| `FINDEVIL_BROWSER_SQLITE_MAX_OPS` | `50000000` | Progress-handler operation budget. |
| `FINDEVIL_BROWSER_OUTPUT_MAX_BYTES` | `25165824` | Sanitized inner payload budget; hard-capped at 24 MiB so the doubly escaped JSON-RPC frame stays below 64 MiB. |
| `FINDEVIL_BROWSER_SQLITE_HEAP_MAX_BYTES` | `134217728` | Process-wide SQLite hard heap limit, clamped to 16 MiB–1 GiB. |
| `FINDEVIL_BROWSER_SCHEMA_MAX_ENTRIES` | `512` | Schema-enumeration limit, hard-capped at 4096. |
| `FINDEVIL_FLS_TIMEOUT_SECONDS` | `900` | Sleuth Kit listing wall-clock ceiling; invalid/zero values use the default and values above 1800 seconds are clamped. A timeout kills/reaps the isolated parser process tree. |
| `FINDEVIL_ICAT_TIMEOUT_SECONDS` | `300` | Per-artifact Sleuth Kit extraction ceiling; invalid/zero values use the default and values above 900 seconds are clamped. A timeout kills/reaps the process tree and removes the partial artifact. |
| `FINDEVIL_MMLS_TIMEOUT_SECONDS` | `60` | Sleuth Kit partition-probe ceiling; invalid/zero values use the default and values above 300 seconds are clamped. Output is bounded, and a timeout kills/reaps the isolated process tree. |
| `FINDEVIL_SIGSTORE_EXPECTED_IDENTITY` | unset | Exact trusted certificate identity required for offline Sigstore manifest verification. A Sigstore bundle cannot pass `overall` or the customer-release gate without this deployment policy. Custody process only; never forwarded to Rust parsers. |
| `FINDEVIL_SIGSTORE_EXPECTED_ISSUER` | unset | Required exact OIDC issuer paired with `FINDEVIL_SIGSTORE_EXPECTED_IDENTITY` for Sigstore verification. Missing either value fails closed. Custody process only; never forwarded to Rust parsers. |
| `FINDEVIL_VELOCIRAPTOR_ZIP_MAX_MEMBER_BYTES` | `536870912` | Per-member extracted-byte limit; cannot exceed 512 MiB. |
| `FINDEVIL_VELOCIRAPTOR_ZIP_MAX_TOTAL_BYTES` | `2147483648` | Aggregate extracted-byte limit; cannot exceed 4 GiB. |
| `FINDEVIL_VELOCIRAPTOR_ZIP_MAX_RATIO` | `200` | Per-member expansion-ratio limit; cannot exceed 1000. |
| `FINDEVIL_VELOCIRAPTOR_ZIP_MAX_ARCHIVE_MEMBERS` | `100000` | Member-count ceiling enforced from EOCD/ZIP64 metadata and an independent streaming central-directory count before Python allocates `ZipInfo` objects; cannot exceed 100000. |
| `FINDEVIL_VELOCIRAPTOR_ZIP_MAX_CENTRAL_DIRECTORY_BYTES` | `67108864` | Central-directory byte ceiling checked before `ZipFile` opens; cannot exceed 128 MiB. |
| `FINDEVIL_VELOCIRAPTOR_ZIP_MAX_ARCHIVE_BYTES` | `68719476736` | Whole collection-container size ceiling; cannot exceed 128 GiB. |

Invalid zip override values fall back to the default, and all values are
clamped to their compiled hard maximum. Limit hits are surfaced as incomplete
coverage rather than silently accepted as a complete parse.

## External DFIR tool binary overrides (Rust server resolves env-var first, then PATH)

| Var | Backs | Default resolution |
|---|---|---|
| `VOLATILITY_BIN` | `vol_pslist/psscan/psxview/malfind` | then `vol`/`vol.py`/`volatility3` on PATH |
| `HAYABUSA_BIN` | `hayabusa_scan` | then `hayabusa` on PATH |
| `HAYABUSA_RULES_BASE` | `hayabusa_scan` | installed Hayabusa base; caller-selected rules must resolve beneath `<base>/rules` |
| `FINDEVIL_HAYABUSA_RULE_SET` | `hayabusa_scan` | optional exact operator-authorized rule file/directory (must be visible in the selected local/SIFT/Docker namespace) |
| `TSHARK_BIN` / `ZEEK_BIN` | `pcap_triage` / `zeek_summary` | then `tshark` / `zeek` on PATH |
| `FINDEVIL_VOL_TIMEOUT_SECS` | all Volatility tools | default 1800 s; hard max 7200 s |
| `FINDEVIL_PCAP_TIMEOUT_SECS` | `pcap_triage` tshark/Zeek subprocess | default 600 s; hard max 3600 s |
| `FINDEVIL_SUBPROCESS_STDOUT_MAX_BYTES` | shared bounded subprocess capture | default 64 MiB; hard max 256 MiB |
| `FINDEVIL_SUBPROCESS_STDERR_MAX_BYTES` | shared bounded subprocess capture | default 4 MiB; hard max 16 MiB |
| `FINDEVIL_CLOUD_AUDIT_MAX_INPUT_BYTES` | `cloud_audit` source file | default 32 MiB; hard max 128 MiB |
| `FINDEVIL_CLOUD_AUDIT_MAX_RECORD_BYTES` | `cloud_audit` canonical raw record | default 1 MiB; hard max 8 MiB |
| `FINDEVIL_CLOUD_AUDIT_MAX_OUTPUT_BYTES` | `cloud_audit` serialized event body | default 16 MiB; hard max 64 MiB |
| `FINDEVIL_FLS_BIN` / `FINDEVIL_ICAT_BIN` | `disk_extract_artifacts` (Sleuth Kit enumerate/extract) | then `fls` / `icat` on PATH |
| `FIND_EVIL_MEMORY_YARA_RULES` | `yara_scan` (memory) | optional rule-file override |
| `FIND_EVIL_DISK_YARA_RULES` | `yara_scan` (disk) | optional rule-file override |
| `FINDEVIL_YARA_RULES_ROOT` | `yara_scan` | optional operator-authorized root for caller-selected rule files |

## Setup / install toggles

| Var | Default | Read by | Purpose |
|---|---|---|---|
| `FINDEVIL_SKIP_BROWSER` | unset | `install.sh` | Skip Playwright/Puppeteer install |
| `FINDEVIL_SKIP_N8N` | unset | `install.sh` | Skip optional n8n automation setup |
| `FINDEVIL_DOWNLOAD_DIR` | `~/Downloads` | `setup` / browser MCP | Gated-asset download dir (set to `tmp/gated-downloads` to keep the OVA in-project) |
| `HAYABUSA_VERSION` / `CHAINSAW_VERSION` / `VOLATILITY_VERSION` / `PANDOC_VERSION` | see [`dependencies.md`](dependencies.md) | `install-dfir-tools.sh` | Override external-tool pins |
| `FINDEVIL_LAUNCHER_SMOKE_BASH_TIMEOUT_SECONDS` | platform | launcher smoke | Windows Git Bash slow-start workaround |

## n8n automation (operator-runtime, optional)

| Var | Default | Read by | Purpose |
|---|---|---|---|
| `N8N_API_URL` | `http://localhost:5678` | `n8n-mcp`, `setup-n8n.py` | n8n base URL; if unreachable, n8n setup auto-skips |
| `N8N_API_KEY` | unset | `n8n-mcp` | REST key (provisioned by `setup-n8n.py` if omitted) |
| `MCP_MODE` | `stdio` | `n8n-mcp` | Required transport mode (set by `install.sh`) |
| `DISABLE_CONSOLE_OUTPUT` | `true` | `n8n-mcp` | Quiets pre-fetch output |

## QMD memory sidecar (operator-local, optional)

| Var | Default | Read by | Purpose |
|---|---|---|---|
| `FINDEVIL_ENABLE_QMD` | `0` | `scripts/run-mcp-qmd.sh` | Explicit opt-in for the local operator memory sidecar. |
| `INDEX_PATH` | `~/.cache/qmd/<index>.sqlite` | local `qmd-mcp.mjs` | Forces the QMD SQLite store when an operator supplies a local `obsidian-mind/` vault. |

The public release does not ship an operator memory vault. `scripts/run-mcp-qmd.sh`
exits cleanly unless `FINDEVIL_ENABLE_QMD=1` is set and
`obsidian-mind/.claude/scripts/qmd-mcp.mjs` is present as a real local file.
