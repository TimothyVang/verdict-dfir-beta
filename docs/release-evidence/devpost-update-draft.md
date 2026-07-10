# Devpost Update Draft

Use this if Devpost edits are still open or if an update comment is allowed.

## Replace Tool Count Sentence

Replace the outdated sentence that says the product has thirty-two
schema-validated tools.

With:

> 57 schema-validated product tools (43 Rust DFIR + 14 Python crypto/ACH/memory/ACP/expert tools). The GitHub repo also registers four non-product convenience MCP servers; they do not emit Findings or enter the audit chain.

## Replace Try-It-Out Sample Link

Prefer this link:

`https://github.com/TimothyVang/verdict-dfir/tree/master/docs/release-evidence`

If the existing Devpost link cannot be edited, `docs/sample-run/README.md` now points readers to the current release-evidence packet and fresh-run commands.

## Accuracy Wording

Use this text:

> Current public evidence is intentionally scoped: the compact EVTX packet proves finding-to-tool-call traceability; on the local-runnable corpus 9 of 9 cases pass (aggregate recall 24/27 = 89%); Nitroba records 5/5 recall; the 2026-07-09 live NIST Hacking Case re-carve records 11/14 = 79% recall, above its 71% bar. Its three remaining gaps (empty USBSTOR, empty/unsatisfiable XP logon `.evt`, and absent `Thumbs.db`) are published instead of hidden; the immutable committed NIST packet remains historical at 10/14.

## Video Review Note

Use this text:

> Demo video: https://youtu.be/4RQnVden6L8. If a reviewer cannot inspect the video directly, confirm that the primary terminal capture is a clean live run with no fault injection. Any verifier re-dispatch/self-correction clip is optional harness/demo evidence only and must not be counted as organic self-correction.

## Evidence Map

- `57` product tools: `docs/reference/mcp-and-tools.md`.
- Nitroba `5/5` and live NIST `11/14 = 79%` (9/9 local corpus, 24/27 = 89% aggregate): `docs/DATASET.md`, `docs/benchmark/RESULTS.md`, and `docs/accuracy-report.md`.
- EVTX trace packet: `docs/release-evidence/evtx-security-log-clear-trace.jsonl` and `docs/release-evidence/evtx-security-log-clear-trace-summary.json`.
