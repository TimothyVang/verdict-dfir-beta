# VERDICT TUI — read-only terminal case viewer

`verdict-tui` (crate: `apps/tui`) is a terminal viewer for a finished VERDICT
**case directory**. It renders the scoped verdict, the Findings, and the custody
state a completed run already produced — a lightweight alternative to opening the
web dashboard or the HTML report.

```bash
scripts/verdict <evidence>            # produce a case under tmp/auto-runs/<case-id>
cargo run -p verdict-tui -- tmp/auto-runs/<case-id>
cargo run -p verdict-tui              # newest case under the allow-listed roots
```

## Doctrine: presentation only, never a Finding source

The TUI sits on the **presentation** side of the trust boundary, with the
dashboard, the HTML/PDF report, and the brand/video surfaces. Per the VERDICT
guardrails, "optional automation, grounding, browser tools, dashboards, and
memory sidecars are never evidence and never create Findings" — the TUI is one of
those presentation surfaces, and this is enforced structurally, not just by
policy:

- **Not an MCP client.** v1 reads only the JSON files a finished run wrote into
  the case directory (`verdict.json`, and optionally `coverage_manifest.json`,
  `run.manifest.json`, `manifest_verify.json`). It registers no MCP server and
  drives no tool surface.
- **Never opens evidence.** It does not resolve or open the run's
  `evidence_path`. It cannot read, mount, or modify source evidence, so it cannot
  violate the read-only evidence boundary.
- **Never emits or changes a Finding.** It renders the verdict word, the Findings,
  and the confidence tiers exactly as the case recorded them. It never creates a
  Finding, never upgrades or downgrades a confidence tier, and never softens the
  scoped verdict language. Colour is styling, not a claim.
- **Absent is absent.** A missing optional file renders literally as
  "not produced by this run" — never a fabricated custody, coverage, or verdict
  value.

Because it opens no evidence and calls no tool, the viewer cannot — by
construction — emit a Finding or a citation. This is locked by
`scripts/tui-smoke.py` (wired into `scripts/run-all-smokes.sh`): a static source
check (no `evidence_path` read, no subprocess, no network client) plus a headless
render that asserts the run writes nothing under `evidence/`.

## What it shows

- **Verdict header:** verdict word, confidence tally, `manifest_verify.overall`
  custody light + signature, and coverage artifact classes.
- **Findings list:** id, confidence (coloured by tier), MITRE technique, one-line
  description.
- **Finding detail (custody strip):** `tool_call_id` → replay expected-vs-actual
  SHA-256 (mismatch highlighted red) → asserted values → counter-hypothesis →
  `derived_from`.

Keys: `q` quit, arrows / `j` `k` navigate, `Enter` drill in, `Esc` back, `?`
help. Full reference and crate layout: [`apps/tui/README.md`](../apps/tui/README.md).

## Scope (v1)

v1 is the first vertical slice: a read-only viewer over a single case directory,
pinned by snapshot tests against the committed `docs/sample-run/` fixtures. It
does not tail a live run, drive fleet cases, or interact with the audit chain
beyond reading the JSON the run already sealed. Custody verification remains the
job of `manifest_verify` / `manifest-verify-offline.py`; the TUI only displays
its result.
