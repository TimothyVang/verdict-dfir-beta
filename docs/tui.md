# VERDICT TUI — read-only terminal case viewer

`verdict-tui` (crate: `apps/tui`) is a terminal viewer for a finished VERDICT
**case directory**. It renders the scoped verdict, the Findings, and the custody
state a completed run already produced — a lightweight alternative to opening the
web dashboard or the HTML report.

```bash
scripts/verdict <evidence>            # produce a case under tmp/auto-runs/<case-id>
cargo run -p verdict-tui -- tmp/auto-runs/<case-id>
cargo run -p verdict-tui              # newest case under the allow-listed roots

# Phase 2 — live monitoring
cargo run -p verdict-tui -- --drive <evidence>          # launch scripts/verdict, tail it live
cargo run -p verdict-tui -- --follow tmp/auto-runs/<id> # tail an already-running case dir
```

Drive mode launches the repo's own `scripts/verdict` and live-tails the case
directory it writes — a streaming view of the audit chain and the `status.json`
heartbeat — then hands off to the finalized viewer above when the run seals a
`verdict.json`.

## Doctrine: presentation only, never a Finding source

The TUI sits on the **presentation** side of the trust boundary, with the
dashboard, the HTML/PDF report, and the brand/video surfaces. Per the VERDICT
guardrails, "optional automation, grounding, browser tools, dashboards, and
memory sidecars are never evidence and never create Findings" — the TUI is one of
those presentation surfaces, and this is enforced structurally, not just by
policy:

- **Not an MCP client.** It reads only the JSON files a run writes into the case
  directory (`verdict.json`, and optionally `coverage_manifest.json`,
  `run.manifest.json`, `manifest_verify.json`; a streamed `audit.jsonl` +
  `status.json` while a run is live). It registers no MCP server and drives no
  tool surface.
- **Drive mode is a pure launcher, not an engine.** `--drive <evidence>` spawns
  the repo's own `scripts/verdict` launcher — the *only* subprocess the crate
  ever starts (all of it in `apps/tui/src/case/runner.rs`). It re-implements none
  of the investigation: it forwards the operator-supplied evidence path to the
  launcher as an opaque argument (the launcher, engine, and typed MCP tools do
  the forensics) and then only *reads* the case directory the run writes. The
  evidence path is never opened by the TUI itself.
- **Never opens evidence.** It does not resolve or open the run's evidence-path
  field. It cannot read, mount, or modify source evidence, so it cannot violate
  the read-only evidence boundary.
- **Never emits or changes a Finding.** It renders the verdict word, the Findings,
  the confidence tiers, and — live — the streamed audit records exactly as the
  case recorded them. It never creates a Finding, never upgrades or downgrades a
  confidence tier, and never softens the scoped verdict language. Colour is
  styling, not a claim. The live stream shows only structural fields (kind, tool,
  `tool_call_id`, confidence tier, row counts); it never surfaces an evidence
  path or free-text so it stays evidence-agnostic.
- **Absent is absent.** A missing optional file renders literally as
  "not produced by this run" (finalized) or "absent" (live) — never a fabricated
  custody, coverage, or verdict value.

Because the TUI opens no evidence, calls no tool, and spawns nothing but the
`scripts/verdict` launcher, it cannot — by construction — emit a Finding or a
citation. This is locked by `scripts/tui-smoke.py` (wired into
`scripts/run-all-smokes.sh`): a static source check (no evidence-path read, no
network client), a **launcher-isolation** check (the single `Command::new` lives
only in `case/runner.rs`, spawns exactly once, is pinned to the `scripts/verdict`
launcher constant, and opens no shell/raw-exec escape hatch), a rejection of the
headless-plus-drive combination, and a headless render that asserts the run
writes nothing under `evidence/`.

## What it shows

- **Verdict header:** verdict word, confidence tally, `manifest_verify.overall`
  custody light + signature, and coverage artifact classes.
- **Findings list:** id, confidence (coloured by tier), MITRE technique, one-line
  description.
- **Finding detail (custody strip):** `tool_call_id` → replay expected-vs-actual
  SHA-256 (mismatch highlighted red) → asserted values → counter-hypothesis →
  `derived_from`.
- **Live monitor (Phase 2):** the run phase (LAUNCHING / LIVE / COMPLETE /
  FAILED), the `status.json` stage and counters (`tool_calls`,
  `findings_so_far`), a per-kind tally, and a streaming, auto-following list of
  audit records as they are appended to `audit.jsonl`. On seal it hands off to
  the finalized viewer above.

Keys: `q` quit, arrows / `j` `k` navigate, `Enter` drill in, `Esc` back, `?`
help. Full reference and crate layout: [`apps/tui/README.md`](../apps/tui/README.md).

## Scope

- **v1 — finalized viewer:** a read-only viewer over a single sealed case
  directory, pinned by snapshot tests against the committed `docs/sample-run/`
  fixtures.
- **Phase 2 — live monitoring:** an incremental `audit.jsonl` tail (buffering a
  partial trailing line across appends, the way the web dashboard's
  `apps/web/lib/audit-tail.ts` does — re-implemented in Rust, not ported) plus a
  `status.json` heartbeat, surfaced in a Live view; and `--drive`, which launches
  `scripts/verdict` as a pure launcher and tails the resulting run. Correctness
  of the tail is poll-based (a fixed tick re-reads the growing file); the
  `notify` watcher only lowers latency, so a missed/debounced event never drops a
  record.

Custody verification remains the job of `manifest_verify` /
`manifest-verify-offline.py`; the TUI only displays its result. Fleet-grid
monitoring and Autopsy-parity browsing remain future phases (see
`docs/internal/tui-plan-2026-07-04.md`).
