# DFIR container backend — the SIFT-VM replacement

The DFIR container is a reproducible, rebuildable Docker image that carries the
full forensic toolchain VERDICT invokes. It is the recommended replacement for
the SIFT VM as the disk/memory/network tool backend.

## Why it replaces the SIFT VM

The SIFT VM worked, but it was a bottleneck for structural reasons:

- **It drifted.** Tools could be missing with no clean way to notice — a live
  run found `tshark` simply absent, so the whole PCAP lane read 0 packets.
- **It was network-isolated**, so a missing tool could not be installed in place.
- **Its shared folder (hgfs) was slow and flaky** for large evidence; tools
  reading an 11 GiB image or a 198 MB pcap over FUSE under-produced.
- **It was heavy** — a full VM, SSH routing, per-tool round-trips.

The container fixes each of these by construction:

| SIFT-VM problem | Container |
|---|---|
| Silent missing tools | Toolchain is declared in `docker/dfir.Dockerfile`; downloaded parser payloads and the Rust compiler archive are content-pinned, and Hayabusa rules are commit-pinned. Before any host mount is attached, `scripts/run-dfir-container.sh` executes all 28 parser probes in a disposable container with no network, writable root, mounts, or Linux capabilities. Each probe and the overall preflight have hard timeouts. The mounted runtime `HEALTHCHECK` verifies a sealed SHA-256 manifest over parser executables, managed payloads, and rules without executing parser code; bring-up polls until Docker reports `healthy`. |
| Can't update in place | Rebuild explicitly after reviewing the Dockerfile and third-party payload pins. |
| Slow hgfs reads | Evidence is a bind mount — native disk speed. |
| Heavy VM + SSH | A container driven over `docker exec -i` (the same stdio pipe `ssh -T` gives the VM). |

The image pins Volatility 3, Hayabusa (**with its Sigma rules baked in**, so
scans are never silently empty), Chainsaw, Velociraptor, Sleuth Kit, libewf,
`tshark`, Suricata, `nfdump`, the Eric Zimmerman tools (`ez_parse`, via a pinned
.NET 10 LTS runtime the .NET 9 builds roll forward onto) and plaso /
`log2timeline` (`plaso_parse`, from the GIFT stable PPA), plus the content-pinned
Rust 1.91 build environment.

## Select a reviewed image (recommended) or explicitly build

For a published image, use its immutable release digest. Mutable tags such as
`:latest` are deliberately refused by the backend launcher:

```bash
FINDEVIL_DFIR_GHCR='ghcr.io/<owner>/verdict-dfir-toolkit@sha256:<reviewed-digest>' \
  scripts/verdict --docker <path-to-evidence>
```

An explicitly supplied digest always wins over a same-named local tag. With no
digest, the launcher reuses an existing local `findevil/dfir:local` image. It
never pulls a mutable remote tag and never performs a networked Dockerfile build
implicitly.

To build locally after reviewing the build inputs, approve that trust decision
on the run:

```bash
FINDEVIL_DFIR_ALLOW_LOCAL_BUILD=1 \
  scripts/verdict --docker <path-to-evidence>
```

The opt-in remains intentional: a local networked image build is a supply-chain
trust decision even though downloaded non-APT payloads are content-pinned and
the resulting parser payload is sealed.

**Maintainers** publish a new image with `scripts/publish-dfir-image.sh <tag>`
(needs a `write:packages` token in `GHCR_TOKEN`); CI also builds + pushes it on
release. The pull target is overridable with `FINDEVIL_DFIR_GHCR`.

## Bring up

`run-dfir-container.sh` selects the image, resolves its immutable local
`sha256:` image ID once, and uses that same ID for preflight, build, and runtime
so a concurrent retag cannot swap parser code after approval. It then starts
one unprivileged Rust builder that can read only the
Cargo manifests and `services/mcp`: `cargo fetch --locked` runs while a temporary
Docker network is attached, Docker disconnects every network and verifies the
zero-network state, and only then can `cargo build --frozen --offline` execute
dependency build scripts. Build stdin is closed; time, memory, CPU, process,
tmpfs, log, and exported-binary sizes are bounded, and an EXIT/signal trap
removes a partially running builder. Ambient Docker proxy values
are explicitly blanked so proxy credentials cannot leak into the image,
preflight, builder, or runtime.

The case-scoped `findevil-dfir` runtime has no network, a read-only root, no
capabilities/devices/sudo path, exact read-only binds for the Rust binary, YARA
rule, and selected evidence, plus two hard-sized private tmpfs mounts for parser
state. It cannot see the repository, other cases, the signing key, or signed
case output. The launcher removes the runtime and its bounded build/runtime
handoff state on every normal or error exit when invoked by `scripts/verdict`,
which owns the case lifecycle and cleanup trap. A deliberately direct invocation
of the internal bring-up helper leaves its runtime available until an explicit
case-scoped `--down`.

Python custody/signing runs on the host through a frozen/no-sync launcher.
`verify_finding` uses a fixed server-side `docker exec` route to replay the cited
Rust tool in the container; callers cannot supply process argv or environment.
Raw `.dd`/`.001` uses direct Sleuth Kit. Compressed EWF (`.E01`) is refused in
Docker because FUSE/kernel mounting would reintroduce a root parser boundary;
use local/SIFT or `ewfexport` it to raw first.

## One command: `scripts/verdict --docker`

`scripts/verdict --docker <evidence>` folds the bring-up and the transport swap
into one step — the container analog of `--sift`:

```bash
scripts/verdict --docker <path-to-evidence>
```

It:

- brings the container up via `scripts/run-dfir-container.sh` (select a reviewed
  image, build the Rust parser before evidence attachment, mount evidence read-only);
- skips the host `cargo build` — the MCP is built in the container;
- swaps in the docker MCP transport (`.mcp.json.docker` over `.mcp.json`, backed
  up and restored on exit, exactly as `--sift` swaps `.mcp.json.sift`);
- hands the run the in-container evidence path (`/evidence`, where the evidence
  is bind-mounted read-only), since the tools run in the container and see it
  there;
- removes the case-scoped container and transient parser/build state on exit.

`--sift` and `--docker` are mutually exclusive (each picks where the DFIR tools
run), and `--docker` is single-host — a multi-host case folder is refused. If a
host crash or force-kill prevents the exit trap, remove that exact case-scoped
container with the name printed by the launcher, or use the internal helper
with the same `FINDEVIL_DFIR_CONTAINER` value:

```bash
FINDEVIL_DFIR_CONTAINER="<printed-case-container>" \
  scripts/run-dfir-container.sh --down
```

## Transport boundary

Use `scripts/verdict --docker`; it reserves the marked host case and private
parser state before invoking the internal bring-up helper. `.mcp.json.docker`
routes only `findevil-mcp` through `docker exec`; `findevil-agent-mcp` remains a
host process for custody/signing. This split is a security boundary, not an
implementation detail to collapse for convenience.

Normal `scripts/verdict --docker` runs tear down automatically. Set
`FINDEVIL_DFIR_KEEP_RUNTIME_STATE=1` only for deliberate local debugging; it
retains the bounded runtime handoff directory, never the evidence container.

## Evidence safety

The read-only contract is layered. Directory evidence is rejected if it is the
repository, contains the repository, or overlaps `.project-local`, `.git`, case
output, signing/memory/ledger state, SSH keys, or Docker certificate state.
Symlinks, hard-linked files, sockets, devices, and FIFOs are refused; a second
scope/identity check runs immediately before mounting. The runtime sees no
repo-root or repo-wide `tmp` bind—only the exact Rust binary/YARA rule and
selected evidence. It has no outbound network, capabilities, devices, or
custody key. The host-only Python MCP owns audit, manifest, Verdict, and report
output.

Host custody directories are owner-only (`0700`) and custody files/keys are
`0600`. Run `bash scripts/setup` after cloning, moving, or upgrading an older
checkout to migrate safe project-local state. An existing signing key with an
unsafe owner, mode, symlink, or hard link is refused rather than silently
re-permissioned; inspect and rotate it, or explicitly set a verified key to
`0600`, before retrying.

## Known limitations (honest scope)

- **Long-tail DFIR tools degrade, never crash.** Every subprocess tool the image
  omits returns a typed `BinaryNotFound` the engine pivots on, rather than
  crashing. The Eric Zimmerman tools (`ez_parse`: `AmcacheParser`, `JLECmd`,
  `RBCmd`, `LECmd`, `AppCompatCacheParser`, `SBECmd`, `WxTCmd`) and plaso
  (`plaso_parse`: `log2timeline.py` / `psort.py`) are now **baked into the
  image** — the EZ .NET 9 builds run on a pinned .NET 10 LTS runtime via
  `DOTNET_ROLL_FORWARD=Major`, and plaso comes from the GIFT stable PPA. Both
  families are invoked by the isolated pre-mount gate, while mounted-runtime
  health verifies their sealed executable hashes without invoking them — so a
  disk case runs `case_open` → `disk_mount` → `disk_extract_artifacts` →
  `evtx_query` / `registry_query` / `mft_timeline` / `usnjrnl_query` /
  `hayabusa_scan` **and** `ez_parse` (Amcache/ShimCache/LNK/JumpList/RecycleBin/
  shellbags) and `plaso_parse` (super timeline). `ez_parse` still depends on
  `disk_extract_artifacts` having carved the target artifact. Remaining SIFT-only
  long-tail lanes (e.g. `mac_triage` / mac_apt) are not in the image and still
  degrade to `BinaryNotFound`. Prefer `--sift` when you need one of those lanes.
- **Compressed EWF is not mounted in Docker.** The image still carries pinned
  libewf inspection/export tools, but the runtime refuses `.E01` rather than
  grant FUSE/root parser authority. Use local/SIFT, or `ewfexport` the set to a
  raw `.dd` and point Docker VERDICT at that file.
- **The EWF tools are RPATH-isolated.** `/opt/libewf/lib` is deliberately kept out
  of `ld.so.conf` so plaso's `python3-libewf` bindings keep loading the GIFT
  shared library they were compiled against (`pyewf` still reports `20140816`).
  Do not "simplify" this by running `ldconfig` over the prefix.
- **The Rust MCP server is built at bring-up, not baked into the image**, so the
  image stays decoupled from a single repo snapshot. Only locked dependency
  retrieval is networked; compilation and all dependency build scripts run
  after Docker proves the builder has zero attached networks. Python custody
  uses the host's already-synced frozen/no-sync environment and is never built
  by the Docker parser builder.

## See also

- `docker/dfir.Dockerfile` — the pinned toolchain.
- `scripts/run-dfir-container.sh` — bring-up / teardown.
- `.mcp.json.docker` — the Docker MCP transport variant.
- [running-verdict.md](running-verdict.md) — the local and `--sift` run modes.
