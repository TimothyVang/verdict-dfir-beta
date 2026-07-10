# Bundled YARA rules

`disk-triage.yar` is a **minimal, evidence-agnostic** default used when
`FIND_EVIL_DISK_YARA_RULES` is unset. It exists so disk `yara_scan` is not a
no-op on a fresh clone.

Production operators should replace or override with a curated ruleset
(e.g. YARA-Forge core):

```bash
export FIND_EVIL_DISK_YARA_RULES=/path/to/rules.yar
scripts/verdict --docker evidence/host.E01
```

These bundled rules are **leads only** — every match still requires multi-class
corroboration before CONFIRMED execution claims.
