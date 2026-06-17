# Contributing here

This repo is the **community hub** for VERDICT — it's where discussion, ideas, and "I want to help
with X" happen. The **code** lives in the project repo, and that's where build/test mechanics and
code review live.

## How to engage

1. **Browse the open problems** in the [README](README.md#where-you-can-help-open-problems).
2. **Open an issue** — [choose a template](../../issues/new/choose):
   - **Pick an open problem** — claim one of the listed areas or propose a new one.
   - **Question / discussion** — anything else.
   Use issues to agree on the approach *before* writing code, so nobody burns a weekend on a PR that
   gets blocked by a project invariant.
3. **Then write code in the project repo.** Its `CONTRIBUTING.md` is the source of truth for the
   toolchain (Rust 1.88 / Python 3.11 + uv / Node 20 + pnpm), the CI tiers, conventional commits,
   the DFIR vocabulary, and the live-run "done" gate. Don't duplicate that here — link to it.

## Invariants that won't change (so your work isn't wasted)

A PR that violates one of these gets blocked no matter how good it is:

- **No `execute_shell` MCP tool.** The narrow typed tool surface *is* the product.
- **Every Finding cites a `tool_call_id`;** evidence is read-only; the audit log is append-only and
  hash-chained.
- **Claude Code is the orchestrator** — don't reintroduce a standalone agent runtime.
- **AGPL/GPL DFIR tools stay subprocess-only, never linked** (keeps the tree Apache-2.0).

## Conduct & security

- Be decent — see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- **Security issues do not go in public issues.** See [SECURITY.md](SECURITY.md) for private
  reporting.
