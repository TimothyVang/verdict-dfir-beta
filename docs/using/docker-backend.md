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
| Silent missing tools | Toolchain is declared in `docker/dfir.Dockerfile`; the image `HEALTHCHECK` fails if `tshark`/`fls`/`ewfexport`/`vol`/`hayabusa` are not invocable. |
| Can't update in place | Add a line, `docker build` — network is available at build time. |
| Slow hgfs reads | Evidence is a bind mount — native disk speed. |
| Heavy VM + SSH | A container driven over `docker exec -i` (the same stdio pipe `ssh -T` gives the VM). |

The image pins Volatility 3, Hayabusa (**with its Sigma rules baked in**, so
scans are never silently empty), Chainsaw, Velociraptor, Sleuth Kit, libewf,
`tshark`, Suricata, `nfdump`, plus the Rust 1.88 + `uv` build environment.

## Download (recommended) or build

The image is published to GHCR, so most users can just pull it (~2.3 GB) instead
of building the toolchain locally:

```bash
docker pull ghcr.io/<owner>/verdict-dfir-toolkit:latest
```

`scripts/run-dfir-container.sh` does this automatically — it uses a local image if
present, else **pulls the published one**, else builds from the Dockerfile. So the
common path is simply:

```bash
scripts/run-dfir-container.sh <path-to-evidence>
```

To build locally instead (offline, or to modify the toolchain):

```bash
docker build -f docker/dfir.Dockerfile -t findevil/dfir:local .
```

**Maintainers** publish a new image with `scripts/publish-dfir-image.sh <tag>`
(needs a `write:packages` token in `GHCR_TOKEN`); CI also builds + pushes it on
release. The pull target is overridable with `FINDEVIL_DFIR_GHCR`.

## Bring up

`run-dfir-container.sh` gets the image (per above), starts a long-lived
`findevil-dfir` container with the repo bind-mounted read-write at `/workspace`
and evidence read-only at `/evidence`, builds the MCP server inside it (mirroring
how `sift-vm-bootstrap` builds it in the VM), and prints a toolchain check.

Disk-image mounting needs FUSE, so the container runs with
`--cap-add SYS_ADMIN --device /dev/fuse`; every other lane (memory, pcap, evtx,
registry, artifact parsing) runs unprivileged.

## Point VERDICT at the container

Activate the Docker MCP transport (the container analog of `.mcp.json.sift`):

```bash
cp .mcp.json.docker .mcp.json     # route the MCP over `docker exec -i`
```

Both product MCP servers now run **inside** the container. Evidence paths are the
in-container mount, e.g. `/evidence/<case>`. Revert with `git checkout .mcp.json`
(or `cp .mcp.json` from your local backend variant) to return to local/`--sift`.

Tear down when finished:

```bash
scripts/run-dfir-container.sh --down
```

## Evidence safety

The read-only contract is unchanged. Evidence is mounted `:ro`, so the container
cannot modify source evidence even if a tool tried. Only the two product MCP
servers run in the container; the operator-convenience servers are not part of
this image.

## Known limitations (honest scope)

- **`--docker` flag on `scripts/verdict` is not wired yet.** Today you bring the
  container up and swap `.mcp.json.docker` manually (above). A first-class
  `scripts/verdict --docker <evidence>` branch — mirroring `--sift` (start
  container, bind-mount evidence, swap transport, hand off) — is the next step.
- **Multi-segment E01.** The image ships Ubuntu 22.04's `libewf` (`ewfmount
  20140807`), the same era as the SIFT VM. A truncated multi-segment E01 read
  seen on the VM may persist. Workaround until a newer `libewf` is pinned:
  `ewfexport` the segmented `.E01`/`.E02` to a single raw `.dd` first, then point
  VERDICT at the `.dd`.
- **The MCP server is built at bring-up, not baked into the image**, so the image
  stays decoupled from any single repo snapshot. First bring-up compiles
  `findevil-mcp` inside the container; subsequent starts reuse it.

## See also

- `docker/dfir.Dockerfile` — the pinned toolchain.
- `scripts/run-dfir-container.sh` — bring-up / teardown.
- `.mcp.json.docker` — the Docker MCP transport variant.
- [running-verdict.md](running-verdict.md) — the local and `--sift` run modes.
