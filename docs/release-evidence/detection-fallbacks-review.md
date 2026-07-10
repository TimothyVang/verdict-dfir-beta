# Detection Fallbacks Review

Review note for fallback, degraded, unsupported, or partial-coverage paths that can prevent VERDICT from finding more malicious activity. This is not a product claim by itself; each item points at existing code or documentation that should be checked before we claim broader coverage.

## Progress (2026-07-10)

Closed or substantially reduced in the docker-backend / gap-closure branch:

| Was | Now |
|---|---|
| SRUM/BITS/WMI/email tools registered but not auto-driven | Engine calls them after extract (`srum_parse`, `bits_parse`, `wmi_persist_parse`, `email_parse`/`pst_parse`) |
| Single EVTX skips Hayabusa | Auto-engine stages lone `.evtx` files into a case-local dir for `hayabusa_scan` |
| Disk YARA only when env set + profile paths | Bundled `assets/yara/disk-triage.yar` default; System32/drivers PE paths are yara-targets |
| Disk+memory fusion only analyst-driven | Default-on fusion + `FIND_EVIL_CROSS_ARTIFACT_PID` default-on |
| VSS unused | `vss_list` after every successful `disk_mount` |
| Extract limit silent | Limitation when extract hits `limit` |
| Container missing bulk/esedb/vshadow | Dockerfile installs `bulk-extractor`, `libesedb-utils`, `libvshadow-utils` (rebuild image to pick up) |
| Container could silently lose Plaso/EZ/Hayabusa lanes | Docker content-pins all seven unversioned EZ archives and pins the Hayabusa rule commit; a timed, networkless/read-only/no-capability preflight executes both Plaso stages and every allow-listed EZ parser before host mounts attach; runtime health verifies the Plaso Python runtime/package payload, every EZ managed assembly, and the full Hayabusa rule corpus and must reach `healthy`. Missing/broken/timed-out parsers block readiness unless `FINDEVIL_DFIR_ALLOW_MISSING=1` explicitly selects a partial image. |
| USB secondary source (setupapi) | Typed `setupapi_parse` + extract class `setupapi_log`; MountPoints2 queried on NTUSER |
| EXIF not auto-driven | Engine calls `exif_parse` on extracted `image_exif` class; GPS/software → HYPOTHESIS |
| Hard-coded tool timeouts only | `FIND_EVIL_TOOL_TIMEOUT` env sets default MCP call timeout (30–7200s) |

Still open (honest): macOS container/fixture, mobile, multimodal UI, private held-out golden program (CORPUS `held_out_program.status=none_yet`), full cpulimit sandbox, and reproducible Plaso/EZ availability on every non-container host.

## Summary

- Raw scan found 191 fallback, limitation, missing, skipped, or degraded-coverage terms across Markdown, JSON, JSONL, and text artifacts.
- Roughly 21 categories appear detection-impacting after removing report/UI/release-only fallbacks.
- The recommended Docker backend now fail-closed gates Plaso and all seven EZ parsers before host mounts attach, then monitors the sealed Plaso Python payload, every EZ managed assembly, and the pinned Hayabusa rules. The highest-value remaining fixes are local-host Plaso/EZ portability, legacy IE/XP coverage, macOS, fleet+docker multi-host, and held-out evaluation.

## Highest Priority Gaps

| Gap / fallback | Why it can miss evil | Evidence |
|---|---|---|
| Plaso unavailable outside the recommended container | Docker now gates both Plaso stages, but local/partial backends can still miss legacy timelines, XP `.evt`, IE `index.dat`, Recycle Bin, task, and other Plaso-normalized artifacts. | `docker/dfir.Dockerfile`; `scripts/run-dfir-container.sh`; `docs/release-evidence/stage-two-evidence.md:40` |
| Raw disk custody-only | If `disk_mount` / `disk_extract_artifacts` fails or yields no supported artifacts, disk contents are not examined. | `agent-config/PLAYBOOK.md:113-119`; `docs/DATASET.md:260-264` |
| Missing external DFIR binaries | The recommended container gates its core + Plaso/EZ contract, but local/partial backends can still lose Velociraptor, Zeek, mac_apt, journalctl, last, ausearch, nfdump, Suricata, INDXParse, or other install-first lanes. | `docs/analyst/tool-playbooks.md:139`; `scripts/doctor.sh:243-270` |
| Disk extraction caps | Large or noisy disks can lose tail artifacts due to default artifact byte and count limits (now loud when at limit). | `services/mcp/src/tools/disk.rs`; extract limit limitation in `find_evil_auto.py` |
| Failed file extraction skips artifacts | Individual `icat` extraction failures are skipped, so downstream parsers never see those artifacts. | `services/mcp/src/tools/disk.rs` |
| Deleted / non-file disk coverage partial | Metadata-intact deleted regular files are recovered under `__deleted__/<inode>/` with reallocated/unreadable counters; non-regular entries, overwritten content, and broader slack recovery remain limited. | `services/mcp/src/tools/disk.rs`; `services/mcp/tests/tool_smoke.rs` |
| Disk YARA default = extract targets only | Default remains extract yara-targets; **opt-in** whole-mount recursive via `FIND_EVIL_DISK_YARA_WHOLE_MOUNT=1` (typed `yara_scan` recursive on `fs_root`, timeout/limit env). | `find_evil_auto.py` `_run_disk_yara_whole_mount`; `agent-config/PLAYBOOK.md` |
| Single EVTX Sigma | Mitigated by case-local staging for hayabusa; still not a native single-file hayabusa CLI. | `find_evil_auto.py` `_hayabusa_stage_single_files` |
| Memory translation failures | `malfind=0` or empty active-list results can mean not analyzable, not clean. | `agent-config/MEMORY.md:21`; `docs/troubleshooting.md:36-45` |
| Parser / result caps | Volatility, Hayabusa, and PCAP outputs can truncate high-volume cases or top lists. | `services/mcp/src/tools/hayabusa_scan.rs`; `pcap_triage.rs` |
| PCAP/network scope is triage | Interactive packet reconstruction and broad payload carving are outside current automated scope. | `agent-config/PLAYBOOK.md`; `docs/artifact-semantics.md` |
| Same-host disk+memory fusion | Default-on fusion leads exist; further PID-level fusion remains HYPOTHESIS and optional noise-tunable. | `find_evil_auto.py` `_fuse_disk_memory_execution`, `_emit_cross_artifact_pid_findings` |
| Conservative corroboration suppresses thin signals | Real but single-source signals may remain `HYPOTHESIS` if only one artifact class supports them. | `docs/accuracy-report.md:181-187`; `docs/red-team-challenge.md:27-31` |
| Cloud provider allow-list | Cloud/SaaS evidence outside supported providers is not parsed by the `cloud_audit` lane. | `services/mcp/src/tools/cloud_audit.rs:29-38`; `agent-config/EXPERT.md:70-74` |
| Long-tail tools not real-run proven | Some typed tools are unit-tested but not exercised broadly on committed real evidence. | `docs/reference/mcp-and-tools.md:70-75`; `agent-config/TOOLS.md:24-29` |

## Known Misses Already Written Up

The clearest public list is the NIST Hacking Case recall gap: the 2026-07-09 live re-carve matches 11 of 14 expected findings (79%); the immutable committed sample-run remains historical at 10 of 14 (71%). The three live misses are valuable because they distinguish unavailable source content from parser/playbook gaps.

| Remaining live miss | Why it matters / current evidence |
|---|---|
| USB history | May reveal removable-media staging or exfil paths; `USBSTOR` is queried but empty on this image. |
| XP logon `.evt` | May reveal legacy Windows logon evidence; the golden's `SecEvent.Evt` is empty, so this claim is unsatisfiable from the supplied artifact. |
| Thumbcache | May reveal viewed files after deletion; this image contains no `Thumbs.db`. |

Evidence: `docs/benchmark/RESULTS.md`; `docs/accuracy-report.md`; `docs/DATASET.md`.

## More Detection-Impacting Fallbacks To Review

| Area | Current behavior / concern | Evidence |
|---|---|---|
| Unsupported artifact classes | If no parser/tool extracts an artifact class, VERDICT cannot reason over it. | `docs/red-team-challenge.md:17-25`; `README.md:45-48` |
| SIFT setup fallback | SIFT setup can fall back to local mode; VirtualBox path is stubbed, so full disk-image parity may not be available. | `QUICKSTART.md:38-57`; `README.md:211-215` |
| Memory/Volatility failures | Memory runs can become empty or partial and still seal honestly as `INDETERMINATE`. | `docs/troubleshooting.md:36-45`; `docs/troubleshooting.md:58-69` |
| EVTX XPath | XPath is accepted for forward compatibility but not applied by the shipped Rust tool. | `agent-config/TOOLS.md:36-39`; `services/mcp/src/tools/evtx_query.rs:9-11` |
| Remote ZIP / collection extraction | Unsupported ZIP members and sample-limited summaries can underrepresent unsupported artifact volume. | `scripts/find_evil_auto.py:880-903`; `scripts/find_evil_auto.py:1111-1124` |
| Exfil without network | Staging alone remains unsupported or `HYPOTHESIS` without movement telemetry. | `docs/red-team-challenge.md:30`; `agent-config/EXPERT.md:55-74` |
| Malware capability without reverse engineering | Malfind/YARA/process evidence does not prove full malware capability. | `agent-config/EXPERT.md:55-74`; `agent-config/EXPERT.md:81-89` |
| Unsupported cloud/SaaS, mobile, OT/ICS | These are partial/escalation-only where dedicated typed parsers are absent. | `agent-config/EXPERT.md:70-74` |

## MemProcFS Note

No current product support was found for MemProcFS. Search hits were unrelated `memfs` package-lock entries, not MemProcFS tooling. Treat MemProcFS as a future capability candidate unless a typed MCP wrapper is added and documented.

Potential value if added later:

- Better memory/filesystem fusion workflows.
- Process, handle, module, and registry views through a mounted memory filesystem.
- Possible bridge for same-host disk+memory discrepancy analysis.

Do not claim MemProcFS support until it exists as a typed, allow-listed product tool.

## Suggested Priority Order

1. Extend the Docker Plaso/EZ guarantee to a reproducible local-host install path without weakening typed `BinaryNotFound` degradation.
2. Close the remaining live NIST gaps: the empty/unsatisfiable XP `.evt` fixture, the empty USBSTOR fixture, and absent `Thumbs.db` input; keep deleted-email recovery covered by real-run receipts.
3. Improve disk extraction visibility: count skipped `icat` files, cap hits, extra partitions, and unsupported artifact classes prominently in `coverage_manifest` and reports.
4. Harden the shipped default-on same-host disk+memory fusion with additional real-case precision/recall receipts and noise tuning.
5. Decide whether MemProcFS deserves a new typed wrapper seed.
6. Revisit result caps for high-volume cases so truncation is visible and tunable.
7. Add tests or committed runs for long-tail tools currently described as unit-tested but not real-run proven.

## Review Questions

- Which of these should become Seeds issues first?
- Should Plaso be installable by `scripts/install-dfir-tools.sh`, or only documented as install-first?
- Should MemProcFS be a real typed product tool, or remain a future research note?
- Do we want to prioritize NIST recall fixes or same-host disk+memory fusion first?
- Which fallback categories should be surfaced in the public README versus kept in analyst/runbook docs?
