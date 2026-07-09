# VERDICT Benchmark — local-corpus result (updated 2026-07-09)

Engine commit: develop tip with #189 bulk-email matcher. Cases runnable with LOCAL
evidence only. **9/9 pass**; aggregate recall **24/27 = 89%** when NIST is scored
from a live SCHARDT auto-run (other rows unchanged from the 2026-07-01 packet).
manifest_verify overall:true on the live NIST re-carve (`auto-f3f7a2e2-…`).

| case | recall | floor | result | run verdict |
|------|-------:|------:|--------|-------------|
| nist-hacking-case | **11/14 (79%)** live re-carve 2026-07-09 | 71 | PASS | SUSPICIOUS |
| nitroba | 5/5 (100%) | 80 | PASS | INDETERMINATE |
| evtx-attack-samples | 3/3 (100%) | 100 | PASS | SUSPICIOUS |
| synthetic-benign | 0/0 (100%) | 100 | PASS | INDETERMINATE |
| synthetic-decoy | 0/0 (100%) | 100 | PASS | INDETERMINATE |
| security-log-cleared | 1/1 (100%) | 100 | PASS | INDETERMINATE |
| win-lateral-movement | 2/2 (100%) | 100 | PASS | INDETERMINATE |
| wmi-execution | 1/1 (100%) | 100 | PASS | INDETERMINATE |
| service-install-spoolfool | 1/1 (100%) | 100 | PASS | INDETERMINATE |

Live NIST scorer quote (`scripts/nhc003-golden-check` on
`tmp/auto-runs/auto-f3f7a2e2-ff6a-403c-b2ab-1540a2b5b33c`):

```
recall: 11/14 = 79%
nhc-003: MATCHED - Recovered deleted email discussing the intrusion plan matched_run_finding_id=f-B-bulk-deleted-email-bcaaa39b
STATUS=SCORED
```

Committed `docs/sample-run/nist-hacking-case` remains historical:

```
recall: 10/14 = 71%
nhc-003: MISSED - Recovered deleted email discussing the intrusion plan
STATUS=SCORED
```

## Not run — need evidence you'd provide (19 goldens)
alihadi-01/07/09, dfrws-2008-linux, dfrws-2011-android, digitalcorpora-lonewolf, m57-jean, memlabs-lab1/2/3, nist-data-leakage, otrf-apt3-mordor, sans-starter, synthetic-toolless, volatility-cridex. Drop the image in `evidence/` (or via SIFT fixtures) and re-run to add it to the measured set.

## Honest notes
- Several single-finding EVTX cases score recall 100% but issue an INDETERMINATE verdict — the engine correctly stays cautious on single-artifact-class evidence (recall matched; verdict conservative).
- NIST live re-carve is **11/14 (79%)** with **nhc-003 MATCHED** under the #189 bulk free-space carve matcher; remaining misses are nhc-002 (USBSTOR empty on this image), nhc-012 (empty logon `.evt`), nhc-013 (no `Thumbs.db`).
- nist-sift + the 2 self-correction demo runs remain stale (SIFT VM / narrative-preserving regen).
