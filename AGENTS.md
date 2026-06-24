# AGENTS.md

Agent instructions for **VERDICT DFIR**. This file is for Codex, OpenCode, and other coding agents that follow the `AGENTS.md` convention. Claude Code also reads `CLAUDE.md`; for Claude-specific runtime behavior, `CLAUDE.md` is authoritative.

## Start Here

- Work from the repository root.
- Install or verify prerequisites with `bash scripts/setup`; use `bash scripts/doctor.sh` for a preflight summary.
- The canonical product run is `scripts/verdict <evidence>`.
- In Claude Code, the equivalent operator shortcut is `/verdict <evidence>` or `investigate <path>`.
- Do not create or revive a separate Product CLI. `scripts/verdict`, `scripts/find-evil`, and Claude Code are the supported entry points.
- Before changing investigation behavior, read `CLAUDE.md` and the runtime files in `agent-config/`.

## Application Contract

VERDICT is a DFIR agent. It opens a Case, drives a narrow typed MCP tool surface, verifies Findings, and emits a signed Verdict plus report.

Verdict words are scoped:

- `SUSPICIOUS` - reportable evidence was found.
- `INDETERMINATE` - leads or limited coverage prevent a scoped clearance.
- `NO_EVIL` - no reportable Finding in the artifacts actually examined; never a broad clean bill of health.

## Required Guardrails

- Evidence is read-only. Never mutate source evidence, mounted evidence, or original case files.
- Derived whole-case staging, including `_xartifact`, must be written under the run/output directory, never under the source evidence or case root.
- Every Finding must cite a current-case `tool_call_id`; uncited Findings are invalid.
- Run `verify_finding` for each Finding and record each verifier decision with `pool_handoff` before `judge_findings` consumes the Findings.
- `report_qa` must be audited before `manifest_finalize`; a failed or missing report QA gate blocks customer-ready output and requires expert review.
- Self-correction must be organic and committed to the audit chain: a real tool or verifier failure that drives a named `course_correction`, or a confidence-tier flip committed as `verdict_revision` (offline-verifiable via `manifest_verify`). Never stage a correction; `fault_injection` is demo-only and never counts as organic recovery evidence.
- Do not assert attribution, actor identity, legal breach status, or business impact.
- Do not call limited coverage clean, cleared, disproven, absent, no compromise, or proof of no evil.
- Execution claims require at least two current-case artifact classes; Amcache, ShimCache, memory-only process evidence, YARA, Hayabusa, or malfind alone is not enough.
- Exfiltration claims require collection/staging evidence plus network, tool, or data-movement evidence.
- Disk auto mode is custody-only unless `disk_mount` / `disk_extract_artifacts` produce supported parsed artifacts, either locally through Sleuth Kit/libewf or under SIFT.
- Keep `vol_pslist`, `vol_psscan`, and `vol_psxview` separate; divergence is a signal, not automatic proof.
- Optional automation, grounding, browser tools, dashboard views, and memory sidecars are not evidence and never create Findings.
- Keep timestamps UTC ISO-8601 with trailing `Z`; prefer SHA-256.

## MCP And Tool Boundaries

- `.mcp.json` registers six servers total: two audit-chain product servers (`findevil-mcp`, `findevil-agent-mcp`) plus four non-product operator convenience servers (`n8n-mcp`, `playwright`, `puppeteer`, `qmd`).
- The four non-product servers do not touch evidence, do not emit Findings, and are not in the audit chain.
- Do not add a product-default broad filesystem, shell, Docker, Kubernetes, GitHub, fetch, browser, or raw-command MCP.
- Do not add an `execute_shell` tool. DFIR subprocess behavior must stay behind allow-listed typed tools.
- Both product servers neutralize attacker-controlled evidence text at the MCP output boundary before it reaches the model (`services/mcp/src/sanitize.rs`, `services/agent_mcp/findevil_agent_mcp/sanitize.py`): chat/role control tokens become an inert `[neutralized:<id>]` marker and Trojan-Source invisible Unicode (BIDI overrides/isolates, zero-width) is stripped. Only JSON string values are touched, so metadata is never mangled; the transform is deterministic so `verify_finding` replay reproduces the same `output_sha256`. Keep the two mirrors in sync and never route evidence text around this boundary.

## Brand And Visual Surface

- The v2 brand bible is `VERDICT_DFIR_SVG_Assets_v2/verdict-brand-board-reconstructed.png`; supporting production assets and rules live in `VERDICT_DFIR_SVG_Assets_v2/` and `docs/brand.md`.
- Use the v2 palette for dashboard, report, README, GitHub, and Remotion/video surfaces: Midnight Ink `#101426`, Electric Cobalt `#4D5DFF`, Soft Lilac `#B8A8FF`, Paper Cream `#F5F1E8`, Seafoam `#73D9C2`, Signal Coral `#FF6257`, Butter Yellow `#FFD76A`, Near Black `#12131A`.
- Canonical voice lines are “Show Me the Evidence,” “Evidence over assumption,” “Don't trust the model. Reproduce the finding,” and “Trace it. Test it. Trust it.”
- Visuals are presentation only. They never create Findings, upgrade confidence, or soften scoped verdict wording.

## Running VERDICT

Install and verify:

```bash
bash scripts/setup
bash scripts/doctor.sh
```

Run a Case:

```bash
scripts/verdict <path-to-evidence>
scripts/verdict --sift <path-to-evidence>
scripts/verdict --watch
```

Agent mode (opt-in): `scripts/verdict --agent --acknowledge-evidence-egress <evidence>` runs Pool A / Pool B as a provider-agnostic LLM agent loop instead of the deterministic engine (which stays the default). Findings still route through the default-on fact-fidelity gate, `verify_finding`, judge, correlator, and signed manifest. Backend defaults to Claude (`--agent-provider claude_cli`, no API key); `--agent-provider {anthropic,openai,openrouter,local,dgx}` + `--agent-model <id>` (+ `FINDEVIL_AGENT_BASE_URL` for `local`/`dgx`) target any OpenAI-compatible endpoint (`local`/`dgx` on-prem, no egress ack). Live-verified on single-artifact evidence at report-QA parity with the deterministic engine; `claude_cli` does not yet scale to disk.

Outputs land in `tmp/auto-runs/<case-id>/`. A valid completed run has:

- `verdict.json` with a scoped Verdict.
- `manifest_verify.json` with `overall: true`.
- Audited report QA state before manifest finalization.
- Findings, if any, with valid `tool_call_id` citations.
- `audit.jsonl` carrying the hash-chained record, including named recovery records (`course_correction`, `verdict_revision`, `heartbeat_failure` / `heartbeat_terminated`); a rejected or errored tool call is still logged.
- `REPORT.html` or `REPORT.pdf` for analyst review; committed `verdict_revision` flips render as a Self-Correction section.

## Development Commands

Focused checks:

```bash
cargo check --workspace --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all --check

uv run --directory services/agent pytest
uv run --directory services/agent_mcp pytest
ruff check .
ruff format --check .

pnpm install --frozen-lockfile
pnpm --filter @findevil/web lint
pnpm --filter @findevil/web typecheck
pnpm --filter @findevil/web build
pnpm --filter @findevil/web test

python scripts/verdict-policy-smoke.py
python scripts/report-policy-smoke.py
python scripts/path-existence-smoke.py
bash scripts/run-all-smokes.sh
```

The real done gate is a live run:

```bash
scripts/verdict <supported-evidence-path>
```

Smokes are CI predictors. They are not a substitute for a real investigation.

## Code Boundaries

- Rust MCP code lives under `services/mcp/`.
- Python domain logic lives under `services/agent/`.
- Python MCP protocol shims live under `services/agent_mcp/`.
- The web dashboard lives under `apps/web/` and uses SSE at `/api/audit`.
- Runtime DFIR behavior and role prompts live under `agent-config/`.

**Path-agnostic always.** Scripts and code must run regardless of the caller's CWD or machine. Derive the repo root at runtime — bash: `REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"`; Python: `Path(__file__).resolve().parent.parent`. Use `$HOME`/`~` (never a hard-coded `/home/<user>`), and make environment-specific paths env-overridable defaults (`${VAR:-default}`). Never assume the CWD is the repo root.

Do not restore removed orchestrator code under `services/agent/` such as `graph.py`, `api.py`, `cli.py`, `supervisor.py`, `specialists/`, FastAPI, or LangGraph Product runtime files. Claude Code is the investigation orchestrator.

## Release Hygiene

Open changes as pull requests against the `develop` branch for review first; never push directly to `main` (the published release line). Publish to a release line only after review and explicit approval — releases are cut with `git ship` (push + tag + GitHub Release; no CI runners). See [docs/contribution-model.md](docs/contribution-model.md).

Do not commit or copy private/bulky evidence into public release snapshots:

- `tmp/`
- `evidence/`
- `*.E01`
- `*.dd`
- `*.mem`
- `*.evtx` unless explicitly documented as a public fixture
- VM images and OVA files
- SQLite state
- local corpora
- `.env*`, credentials, tokens, browser profiles, or session files

Public release instructions should stay application-focused: install, run, guardrails, verification, and scoped limitations.
