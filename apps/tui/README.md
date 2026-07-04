# verdict-tui

A read-only terminal viewer for a finished VERDICT **case directory**. Point it
at the output of a completed run and it renders the scoped verdict, the Findings,
and the custody state — in the terminal, with no browser.

```bash
cargo run -p verdict-tui -- <case-dir>     # e.g. tmp/auto-runs/<case-id>
cargo run -p verdict-tui                    # newest case under the allow-listed roots
```

## Read-only by construction — it cannot create a Finding

This viewer is deliberately **not** an MCP client and **not** part of the
investigation flow. v1 reads only the JSON a completed run already wrote:

- `verdict.json` (required)
- `coverage_manifest.json` / `run.manifest.json` / `manifest_verify.json` (each optional)

It **never** opens evidence, **never** resolves the run's `evidence_path`, **never**
calls a forensic tool, and **never** emits, upgrades, or downgrades a Finding or a
confidence tier. It is presentation only. Because it opens no evidence and drives
no tool surface, it cannot — by construction — violate the read-only evidence
boundary or fabricate a citation. Colour styling never changes what the case
asserts; a missing optional file renders literally as "not produced by this run",
never a fabricated value. This contract is locked by `scripts/tui-smoke.py`
(a static source check plus a headless render that asserts nothing is written
under `evidence/`).

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
│   ├── lib.rs              # orchestration (resolve → load → print/interactive)
│   ├── cli.rs              # hand-rolled arg parsing (no clap)
│   ├── discovery.rs        # allow-listed roots + newest-case discovery
│   ├── app.rs              # App state + the action reducer
│   ├── keymap.rs           # key → Action
│   ├── runtime.rs          # interactive crossterm loop (the only TTY code)
│   ├── case/
│   │   ├── loader.rs       # load the case directory (verdict.json required)
│   │   └── model.rs        # typed accessors over loose serde_json::Value
│   └── ui/
│       ├── mod.rs          # frame composition + headless render_to_string
│       ├── theme.rs        # tier / verdict / custody colours (pure fns)
│       ├── verdict_header.rs
│       ├── findings_list.rs
│       ├── finding_detail.rs
│       └── help.rs
└── tests/
    ├── snapshot_tests.rs   # TestBackend golden-frame snapshots
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
custody strip) case directories. The interactive `runtime.rs` loop drives a real
TTY and is exercised by manual/smoke runs rather than snapshots; the tested logic
lives in the pure render path.
