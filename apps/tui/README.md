# verdict-tui

A read-only terminal viewer **and live monitor** for a VERDICT **case
directory**. Point it at a completed run and it renders the scoped verdict, the
Findings, and the custody state; point it at a live run (or launch one) and it
streams the audit chain as it is written — in the terminal, with no browser.

```bash
cargo run -p verdict-tui -- <case-dir>     # e.g. tmp/auto-runs/<case-id>
cargo run -p verdict-tui                    # newest case under the allow-listed roots

# Phase 2 — live monitoring
cargo run -p verdict-tui -- --drive <evidence>            # launch scripts/verdict, tail it live
cargo run -p verdict-tui -- --follow tmp/auto-runs/<id>   # tail an already-running case dir
```

## Read-only by construction — it cannot create a Finding

This viewer is deliberately **not** an MCP client and **not** part of the
investigation flow. It reads only the JSON a run writes into the case directory:

- `verdict.json` (required for the finalized viewer)
- `coverage_manifest.json` / `run.manifest.json` / `manifest_verify.json` (each optional)
- `audit.jsonl` + `status.json` (streamed, while a run is live)

It **never** opens evidence, **never** resolves the run's evidence-path field,
**never** calls a forensic tool, and **never** emits, upgrades, or downgrades a
Finding or a confidence tier. It is presentation only.

**Drive mode is a pure launcher.** `--drive <evidence>` spawns the repo's own
`scripts/verdict` launcher — the only subprocess this crate ever starts, isolated
in `src/case/runner.rs` — and then only *reads* the case directory the run
writes. It re-implements none of the investigation and forwards the evidence path
to the launcher as an opaque argument; the TUI itself never opens evidence.

Because it opens no evidence and drives no tool surface, it cannot — by
construction — violate the read-only evidence boundary or fabricate a citation.
Colour styling never changes what the case asserts; a missing optional file
renders literally as "not produced by this run" / "absent", never a fabricated
value. This contract is locked by `scripts/tui-smoke.py` (a static source check,
a launcher-isolation check that the single `Command::new` lives only in
`case/runner.rs` and is pinned to the `scripts/verdict` launcher with no shell
escape, and a headless render that asserts nothing is written under `evidence/`).

See [`docs/tui.md`](../../docs/tui.md) for the doctrine in the wider VERDICT
documentation map.

## Panes and keys

Three panes, driven from the case JSON:

1. **Verdict header** — the verdict word, the confidence tally
   (CONFIRMED / INFERRED / HYPOTHESIS), the offline custody light
   (`manifest_verify.overall` + signature), and coverage classes.
2. **Findings list** — one row per Finding: id, confidence (coloured by tier),
   MITRE technique, and a one-line description.
3. **Finding detail** — the custody strip: `tool_call_id` → replay
   expected-vs-actual SHA-256 (a mismatch is highlighted red) → asserted values →
   counter-hypothesis → `derived_from`.

| Key | Action |
|-----|--------|
| `q` / `Ctrl-C` | quit |
| `Up` / `k`, `Down` / `j` | move (list) or scroll (detail) |
| `Enter` / `l` | open the selected Finding |
| `Esc` / `h` | back to the list (or close help) |
| `?` | toggle help |

## Live monitoring (Phase 2)

`--drive <evidence>` launches `scripts/verdict` and `--follow <case-dir>` attaches
to a run already in flight. Both open a **Live** view:

- a header with the run phase (LAUNCHING / LIVE / COMPLETE / FAILED), the
  `status.json` stage and counters (`tool_calls`, `findings_so_far`), and a
  per-kind tally;
- an auto-following stream of audit records as they land in `audit.jsonl`,
  showing only structural fields (kind, tool, `tool_call_id`, confidence tier,
  row counts) — never an evidence path or free text.

The tail buffers a partial trailing line across appends (re-implementing the
behaviour of the web dashboard's `apps/web/lib/audit-tail.ts`, in Rust, at the
byte level). Correctness is poll-based — a fixed tick re-reads the growing file —
so a missed or debounced `notify` event never drops a record; `notify` only
lowers latency. When the run seals its `verdict.json`, the Live view hands off to
the finalized viewer above in the same terminal session. `q` quits.

## Non-interactive mode

`--print` renders one frame to stdout via ratatui's headless `TestBackend` and
exits — used by the smoke test and handy for piping:

```bash
verdict-tui --print --width 100 --height 40 docs/sample-run/nitroba
verdict-tui --print --detail docs/sample-run/attack-samples-evtx
```

## Case discovery

With no `CASE_DIR`, the viewer opens the newest case (by `verdict.json` mtime)
under the allow-listed roots, mirroring the dashboard's
`apps/web/lib/audit-tail.ts`: `goldens/`, `tmp/auto-runs/`, `tmp/smoke/`,
`test-forensics/`, and `docs/sample-run/`. Extra roots can be appended with
`FINDEVIL_DASHBOARD_EXTRA_ROOTS` (path-delimiter-separated); the repo root can be
pinned with `FINDEVIL_REPO_ROOT`.

## Layout

```text
apps/tui/
├── src/
│   ├── main.rs              # binary entry: parse args, hand off
│   ├── lib.rs              # orchestration (resolve → load → print/interactive/live)
│   ├── cli.rs              # hand-rolled arg parsing (no clap)
│   ├── discovery.rs        # allow-listed roots + newest-case discovery
│   ├── app.rs              # App state + the action reducer
│   ├── keymap.rs           # key → Action
│   ├── runtime.rs          # interactive crossterm loop (init/restore/event_loop)
│   ├── case/
│   │   ├── loader.rs       # load the case directory (verdict.json required)
│   │   ├── model.rs        # typed accessors over loose serde_json::Value
│   │   ├── audit_tail.rs   # incremental audit.jsonl tail (partial-line buffering)
│   │   ├── status.rs       # status.json heartbeat projection
│   │   └── runner.rs       # the pure scripts/verdict launcher (only Command::new)
│   ├── live/
│   │   ├── state.rs        # LiveState: bounded record ring + phase (pure)
│   │   ├── ui.rs           # Live view render + headless render_to_string
│   │   └── driver.rs       # interactive live loop + notify watcher (TTY code)
│   └── ui/
│       ├── mod.rs          # frame composition + headless render_to_string
│       ├── theme.rs        # tier / verdict / custody / audit-kind colours (pure fns)
│       ├── verdict_header.rs
│       ├── findings_list.rs
│       ├── finding_detail.rs
│       └── help.rs
└── tests/
    ├── snapshot_tests.rs   # TestBackend golden-frame snapshots (finalized + Live)
    ├── audit_tail_growth.rs # follow a growing audit.jsonl with mid-record flushes
    ├── live_handoff.rs     # live-tail → finalized hand-off composes (no TTY)
    └── snapshots/          # committed *.txt frames
```

## Tests

```bash
cargo test -p verdict-tui
UPDATE_SNAPSHOTS=1 cargo test -p verdict-tui   # regenerate golden frames after a UI change
```

Snapshots are pinned to the committed `docs/sample-run/nitroba` (INDETERMINATE,
all non-CONFIRMED, wrapped coverage — the degrade path) and
`docs/sample-run/attack-samples-evtx` (a CONFIRMED finding — tier colouring +
custody strip) case directories, plus a synthetic Live frame (`live-tailing.txt`).
The partial-line buffering is unit-tested in `case/audit_tail.rs` and against a
real growing file in `tests/audit_tail_growth.rs`. The interactive `runtime.rs`
and `live/driver.rs` loops drive a real TTY (and, for the driver, a `notify`
watcher) and are exercised by manual/smoke runs rather than snapshots; the tested
logic lives in the pure tail, state, and render paths.
