#!/usr/bin/env python3
"""Lock the fail-closed parser contract for the recommended Docker backend."""

from __future__ import annotations

import csv
import io
import os
import json
import re
import shlex
import socket
import subprocess
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = REPO_ROOT / "docker" / "dfir.Dockerfile"
RUNNER = REPO_ROOT / "scripts" / "run-dfir-container.sh"
VERDICT_RUNNER = REPO_ROOT / "scripts" / "verdict"
DOCKER_MCP_CONFIG = REPO_ROOT / ".mcp.json.docker"
PREFLIGHT = REPO_ROOT / "scripts" / "lib" / "dfir-container-preflight.sh"
SMOKE_RUNNER = REPO_ROOT / "scripts" / "run-all-smokes.sh"
PYTHON_LAUNCHER = REPO_ROOT / "scripts" / "run-mcp-python.sh"
PYTHON_DOCKER_WRAPPER = REPO_ROOT / "scripts" / "run-mcp-python-docker.sh"
MOUNT_SPEC_HELPER = REPO_ROOT / "scripts" / "lib" / "docker-mount-spec.py"
BOUNDED_COPY_HELPER = REPO_ROOT / "scripts" / "lib" / "bounded-stream-copy.py"

REQUIRED_PARSER_PROBES = {
    "TShark": "tshark --version",
    "Sleuth Kit fls": "fls -V",
    "Sleuth Kit icat": "icat -V",
    "libewf export": "ewfexport -V",
    "libewf mount": "ewfmount -V",
    "Sleuth Kit mmls": "mmls -V",
    "Volatility": "vol -h",
    "Hayabusa": "hayabusa help",
    "Plaso log2timeline": "log2timeline.py --version",
    "Plaso psort": "psort.py --version",
    "EZ LECmd": "/opt/eztools/LECmd --help",
    "EZ JLECmd": "/opt/eztools/JLECmd --help",
    "EZ AmcacheParser": "/opt/eztools/AmcacheParser --help",
    "EZ AppCompatCacheParser": "/opt/eztools/AppCompatCacheParser --help",
    "EZ RBCmd": "/opt/eztools/RBCmd --help",
    "EZ SBECmd": "/opt/eztools/SBECmd --help",
    "EZ WxTCmd": "/opt/eztools/WxTCmd --help",
    "bulk_extractor": "bulk_extractor -V",
    "Chainsaw": "chainsaw --version",
    "Velociraptor": "velociraptor version",
    "Pandoc": "pandoc --version",
    "INDXParse": "INDXParse.py -h",
    "libesedb": "esedbexport -h",
    "libvshadow": "vshadowinfo -h",
    "Suricata": "suricata --build-info",
    "nfdump": "nfdump -V",
    "ausearch": "ausearch --version",
    "YARA": "yara --version",
}
REQUIRED_ISOLATION_FLAGS = (
    "--pull never",
    "--network none",
    "--no-healthcheck",
    "--read-only",
    "--cap-drop ALL",
    "--security-opt no-new-privileges:true",
    "--user analyst",
)
REQUIRED_PROXY_ENV_NAMES = (
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "FTP_PROXY",
    "ftp_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
)
REQUIRED_EZ_ARCHIVE_HASH_ARGS = (
    "EZ_LECMD_SHA256",
    "EZ_JLECMD_SHA256",
    "EZ_AMCACHEPARSER_SHA256",
    "EZ_APPCOMPATCACHEPARSER_SHA256",
    "EZ_RBCMD_SHA256",
    "EZ_SBECMD_SHA256",
    "EZ_WXTCMD_SHA256",
)
REQUIRED_DFIR_PAYLOAD_HASH_ARGS = (
    "BULK_EXTRACTOR_SHA256",
    "HAYABUSA_SHA256",
    "HAYABUSA_RULES_SHA256",
    "CHAINSAW_SHA256",
    "VELOCIRAPTOR_SHA256",
    "PANDOC_SHA256",
    "INDXPARSE_SHA256",
    "LIBESEDB_SHA256",
    "LIBVSHADOW_SHA256",
    "RUST_TOOLCHAIN_SHA256",
)


def _directive_block(text: str, directive: str, next_directive: str) -> str:
    start = re.search(rf"^{re.escape(directive)}\b", text, flags=re.MULTILINE)
    if start is None:
        raise AssertionError(f"missing {directive} directive")
    end = re.search(
        rf"^{re.escape(next_directive)}\b",
        text[start.end() :],
        flags=re.MULTILINE,
    )
    if end is None:
        raise AssertionError(f"missing {next_directive} after {directive}")
    return text[start.start() : start.end() + end.start()]


def _assert_healthcheck_is_integrity_only(surface: str) -> None:
    invoked = [
        label for label, probe in REQUIRED_PARSER_PROBES.items() if probe in surface
    ]
    if invoked:
        joined = ", ".join(invoked)
        raise AssertionError(
            "mounted-runtime HEALTHCHECK executes third-party parsers: " + joined
        )
    if (
        "/usr/bin/sha256sum --check --status "
        "/opt/verdict/dfir-toolchain.sha256" not in surface
    ):
        raise AssertionError(
            "HEALTHCHECK does not verify the sealed toolchain manifest"
        )
    if "|| true" in surface:
        raise AssertionError("HEALTHCHECK can suppress integrity failures")


def _assert_preflight_probes(surface: str) -> None:
    lines = {line.strip() for line in surface.splitlines()}
    missing = [
        label
        for label, probe in REQUIRED_PARSER_PROBES.items()
        if f'probe "{probe}" {probe}' not in lines
    ]
    if missing:
        joined = ", ".join(missing)
        raise AssertionError(f"isolated preflight does not invoke parsers: {joined}")
    if "--foreground --kill-after=" not in surface:
        raise AssertionError("preflight probes are not bounded by a hard timeout")
    if (
        'probe "sealed toolchain manifest" /usr/bin/sha256sum --check --status '
        "/opt/verdict/dfir-toolchain.sha256" not in surface
    ):
        raise AssertionError(
            "preflight does not validate the sealed toolchain manifest"
        )


def _assert_ez_archives_are_content_pinned(dockerfile: str) -> None:
    missing = [
        name
        for name in REQUIRED_EZ_ARCHIVE_HASH_ARGS
        if re.search(rf"^ARG {name}=[0-9a-f]{{64}}$", dockerfile, re.MULTILINE) is None
    ]
    if missing:
        raise AssertionError("unpinned EZ archives: " + ", ".join(missing))

    ez_start = dockerfile.find("ARG EZ_LECMD_SHA256=")
    ez_end = dockerfile.find("# plaso / log2timeline", ez_start)
    if ez_start < 0 or ez_end < 0:
        raise AssertionError("EZ install block not found")
    ez_block = dockerfile[ez_start:ez_end]
    if "RUN set -eu;" not in ez_block:
        raise AssertionError("EZ archive install loop is not fail-closed")
    if "/usr/bin/sha256sum -c -" not in ez_block:
        raise AssertionError("EZ archive digests are declared but never verified")
    if ez_block.count("|| exit 1") < 7:
        raise AssertionError("EZ loop can continue after a download or digest failure")

    with tempfile.TemporaryDirectory(prefix="verdict-ez-digest-") as temp_dir:
        archive = Path(temp_dir) / "LECmd.zip"
        reached = Path(temp_dir) / "checksum-was-ignored"
        verifier = Path(temp_dir) / "verify_digest.py"
        archive.write_bytes(b"controlled archive mutation")
        verifier.write_text(
            """import hashlib
import pathlib
import sys

actual = hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest()
if actual != sys.argv[2]:
    print("checksum mismatch", file=sys.stderr)
    raise SystemExit(1)
""",
            encoding="utf-8",
        )
        wrong_digest = "0" * 64
        verify_command = " ".join(
            shlex.quote(value)
            for value in (sys.executable, str(verifier), str(archive), wrong_digest)
        )
        result = subprocess.run(
            ["/bin/sh"],
            input=(
                "set -eu\n" f"{verify_command}\n" f": > {shlex.quote(str(reached))}\n"
            ),
            text=True,
            capture_output=True,
            check=False,
        )
        if (
            result.returncode != 1
            or "checksum mismatch" not in result.stderr
            or reached.exists()
        ):
            raise AssertionError(
                "wrong EZ archive digest did not fail with a verified mismatch"
            )


def _assert_non_apt_payloads_are_content_pinned(dockerfile: str) -> None:
    if (
        re.search(r"^FROM ubuntu:22\.04@sha256:[0-9a-f]{64}$", dockerfile, re.MULTILINE)
        is None
    ):
        raise AssertionError("Docker base image is tag-only")
    missing = [
        name
        for name in REQUIRED_DFIR_PAYLOAD_HASH_ARGS
        if re.search(rf"^ARG {name}=[0-9a-f]{{64}}$", dockerfile, re.MULTILINE) is None
    ]
    if missing:
        raise AssertionError("unpinned non-APT payloads: " + ", ".join(missing))
    unverified = [
        name for name in REQUIRED_DFIR_PAYLOAD_HASH_ARGS if dockerfile.count(name) < 2
    ]
    if unverified:
        raise AssertionError(
            "declared non-APT digests are unused: " + ", ".join(unverified)
        )
    if (
        re.search(r"^ARG DOTNET_SHA512=[0-9a-f]{128}$", dockerfile, re.MULTILINE)
        is None
    ):
        raise AssertionError(".NET runtime is not SHA-512 pinned")
    forbidden = {
        "curl-pipe-shell": re.compile(r"curl[^\n]*\|\s*(?:env\s+[^\n]*\s+)?sh\b"),
        "mutable dotnet installer": re.compile(r"dotnet-install\.sh"),
        "mutable INDXParse VCS install": re.compile(
            r"git\+https://github\.com/williballenthin/INDXParse"
        ),
        "networked Hayabusa rule updater": re.compile(r"hayabusa\s+update-rules"),
        "rustup network installer": re.compile(r"rustup-init|default-toolchain"),
    }
    present = [
        name for name, pattern in forbidden.items() if pattern.search(dockerfile)
    ]
    if present:
        raise AssertionError(
            "unverified executable downloads remain: " + ", ".join(present)
        )
    if dockerfile.count("/usr/bin/sha256sum -c -") < 12:
        raise AssertionError("declared non-APT SHA-256 pins are not all verified")
    if "/usr/bin/sha512sum -c -" not in dockerfile:
        raise AssertionError(".NET SHA-512 pin is declared but not verified")
    if "rust-${RUST_VERSION}-x86_64-unknown-linux-gnu.tar.xz" not in dockerfile:
        raise AssertionError(
            "Rust compiler is not installed from the pinned combined archive"
        )
    if 'test "${gift_actual_fpr}" = "${GIFT_PPA_FPR}"' not in dockerfile:
        raise AssertionError("GIFT signing key fingerprint is not verified")
    if 'test "${gift_primary_count}" = "1"' not in dockerfile:
        raise AssertionError("GIFT keyring may trust extra primary keys")
    if "NOPASSWD:" in dockerfile or "/etc/sudoers.d" in dockerfile:
        raise AssertionError("evidence parser image retains passwordless root commands")


def _assert_integrity_binary_cannot_be_shadowed(
    dockerfile: str, runner: str, preflight: str
) -> None:
    for name, surface in (
        ("Dockerfile", dockerfile),
        ("runner", runner),
        ("preflight", preflight),
    ):
        unsafe_lines = [
            line.strip()
            for line in surface.splitlines()
            if "sha256sum" in line
            and not line.lstrip().startswith("#")
            and "/usr/bin/sha256sum" not in line
        ]
        if unsafe_lines:
            raise AssertionError(
                f"{name} resolves integrity command through mutable PATH: "
                + "; ".join(unsafe_lines)
            )
    if "chmod 1777 /opt/rust/cargo" not in dockerfile:
        raise AssertionError("Cargo home lacks sticky-directory replacement protection")
    if "chmod -R go-w /opt/rust/toolchain/bin" not in dockerfile:
        raise AssertionError("trusted PATH directory remains group/world-writable")


def _assert_every_parser_dependency_is_sealed(dockerfile: str) -> None:
    marker_start = dockerfile.find("# Seal the exact executables")
    marker_end = dockerfile.find("\nHEALTHCHECK ", marker_start)
    if marker_start < 0 or marker_end < 0:
        raise AssertionError("toolchain manifest build block not found")
    marker = dockerfile[marker_start:marker_end]
    ez_tools = (
        "LECmd",
        "JLECmd",
        "AmcacheParser",
        "AppCompatCacheParser",
        "RBCmd",
        "SBECmd",
        "WxTCmd",
    )
    missing_ez = [
        tool
        for tool in ez_tools
        if f"/opt/eztools/{tool}" not in marker
        or f"/opt/eztools-net9/{tool}" not in marker
    ]
    if missing_ez:
        raise AssertionError(
            "unsealed EZ parser dependencies: " + ", ".join(missing_ez)
        )

    for plaso_dependency in (
        "/usr/bin/python3.10",
        "/usr/lib/python3.10",
        "/usr/lib/python3/dist-packages",
        "/usr/share/plaso",
        "/usr/share/artifacts",
    ):
        if plaso_dependency not in marker:
            raise AssertionError(
                f"unsealed Plaso runtime dependency: {plaso_dependency}"
            )
    for evidence_tool in (
        "/usr/local/bin/bulk_extractor",
        "/usr/local/bin/chainsaw",
        "/usr/local/bin/velociraptor",
        "/usr/local/bin/pandoc",
        "/usr/local/bin/INDXParse.py",
        "/usr/local/bin/esedbexport",
        "/usr/local/bin/vshadowinfo",
        "/usr/bin/suricata",
        "/usr/bin/nfdump",
        "/usr/sbin/ausearch",
        "/usr/bin/yara",
        "/usr/local/lib/python3.11/dist-packages",
    ):
        if evidence_tool not in marker:
            raise AssertionError(f"unsealed evidence-facing payload: {evidence_tool}")

    rules_match = re.search(
        r"^ARG HAYABUSA_RULES_COMMIT=([0-9a-f]{40})$", dockerfile, re.MULTILINE
    )
    if rules_match is None:
        raise AssertionError("Hayabusa rules are not pinned to a commit")
    hayabusa_start = dockerfile.find("# Hayabusa (subprocess only)")
    hayabusa_end = dockerfile.find("# Chainsaw", hayabusa_start)
    hayabusa = dockerfile[hayabusa_start:hayabusa_end]
    if "hayabusa-rules/archive/${HAYABUSA_RULES_COMMIT}.tar.gz" not in hayabusa:
        raise AssertionError(
            "Hayabusa rules do not come from the pinned commit archive"
        )
    if "${HAYABUSA_RULES_SHA256}  /tmp/hayabusa-rules.tgz" not in hayabusa:
        raise AssertionError("Hayabusa rule archive digest is not enforced")
    for rules_dir in ("config", "hayabusa", "sigma"):
        if f"/opt/hayabusa-mcp/rules/{rules_dir}" not in marker:
            raise AssertionError(f"Hayabusa {rules_dir} corpus is not sealed")


def _assert_preflight_fails_closed(surface: str) -> None:
    if '"$@" </dev/null >/dev/null 2>&1' not in surface:
        raise AssertionError(
            "a parser readiness probe can consume and skip the remaining preflight script"
        )
    replacement_index = 0

    def controlled_probe(_match: re.Match[str]) -> str:
        nonlocal replacement_index
        replacement_index += 1
        if replacement_index == 1:
            return 'probe "controlled timeout" sleep 5'
        return 'probe "controlled failure" false'

    controlled, replacements = re.subn(
        r'^probe "[^\n]+$',
        controlled_probe,
        surface,
        flags=re.MULTILINE,
    )
    if replacements < len(REQUIRED_PARSER_PROBES):
        raise AssertionError("could not isolate the preflight probe calls for testing")
    with tempfile.TemporaryDirectory(prefix="verdict-timeout-shim-") as temp_dir:
        timeout_shim = Path(temp_dir) / "timeout"
        timeout_shim.write_text(
            """#!/usr/bin/env python3
import subprocess
import sys

args = sys.argv[1:]
while args and args[0].startswith("-"):
    option = args.pop(0)
    if option != "--foreground" and not option.startswith("--kill-after="):
        raise SystemExit(125)
if len(args) < 2 or not args[0].endswith("s"):
    raise SystemExit(125)
seconds = float(args.pop(0)[:-1])
try:
    raise SystemExit(subprocess.run(args, timeout=seconds, check=False).returncode)
except subprocess.TimeoutExpired:
    raise SystemExit(124)
""",
            encoding="utf-8",
        )
        timeout_shim.chmod(0o755)
        result = subprocess.run(
            ["bash"],
            input=controlled,
            text=True,
            capture_output=True,
            check=False,
            env={
                **os.environ,
                "PATH": f"{temp_dir}{os.pathsep}{os.environ.get('PATH', '')}",
                "FINDEVIL_DFIR_PROBE_TIMEOUT": "1",
                "FINDEVIL_TIMEOUT_BIN": "timeout",
            },
            timeout=10,
        )
    if result.returncode == 0:
        raise AssertionError("controlled failing probes did not fail the preflight")
    if "MISS controlled failure" not in result.stdout:
        raise AssertionError("controlled probe failure was not reported")
    if "MISS controlled timeout (timed out after 1s)" not in result.stdout:
        raise AssertionError("controlled hung probe was not terminated and reported")


def _assert_isolated_before_mounts(runner: str) -> None:
    preflight_start = runner.find("docker run --rm -i")
    mount_start = runner.find("BUILD_MOUNTS=(")
    if preflight_start < 0 or mount_start < 0 or preflight_start >= mount_start:
        raise AssertionError(
            "isolated image preflight must run before host mounts attach"
        )
    preflight_block = runner[preflight_start:mount_start]
    missing = [flag for flag in REQUIRED_ISOLATION_FLAGS if flag not in preflight_block]
    if missing:
        raise AssertionError("preflight isolation flags missing: " + ", ".join(missing))
    if '"${mounts[@]}"' in preflight_block or "--volume" in preflight_block:
        raise AssertionError("isolated image preflight attaches a host mount")
    forbidden = ("--mount", "--device", "--cap-add", "apparmor=unconfined")
    present = [flag for flag in forbidden if flag in preflight_block]
    if present:
        raise AssertionError(
            "preflight contains privileged flags: " + ", ".join(present)
        )
    if '< "${PREFLIGHT_SCRIPT}"' not in preflight_block:
        raise AssertionError("runner does not execute the reviewed preflight script")
    for resource_flag in (
        '--memory "${PREFLIGHT_MEMORY_LIMIT}"',
        '--cpus "${PREFLIGHT_CPU_LIMIT}"',
        "--pids-limit 256",
    ):
        if resource_flag not in preflight_block:
            raise AssertionError("preflight lacks resource ceiling: " + resource_flag)
    if (
        'fail "DFIR image failed its isolated toolchain preflight'
        not in preflight_block
    ):
        raise AssertionError("default preflight failure does not block bring-up")


def _assert_health_wait_fails_closed(runner: str) -> None:
    start = runner.find("wait_for_healthy()")
    end = runner.find("# 5.", start)
    if start < 0 or end < 0:
        raise AssertionError("bounded health-wait function not found")
    surface = runner[start:end]
    if "healthy) return 0" not in surface:
        raise AssertionError("health wait does not require Docker's healthy state")
    if not re.search(r"starting\).*sleep", surface, flags=re.DOTALL):
        raise AssertionError("Docker's starting state is not polled")
    if "FINDEVIL_DFIR_HEALTH_TIMEOUT" not in runner:
        raise AssertionError("health wait has no bounded timeout")
    if "docker_bounded inspect" not in surface:
        raise AssertionError("Docker health inspection is not bounded")
    if "{{.State.Running}}" not in surface:
        raise AssertionError("health wait does not reject a stopped container")
    if re.search(r"(?:starting|none)\)\s+return 0", surface):
        raise AssertionError("non-healthy Docker state is accepted as ready")
    if 'docker_bounded rm -f "${CTR}"' not in surface:
        raise AssertionError("failed readiness leaves evidence attached")
    if "gtimeout" not in runner or "FINDEVIL_TIMEOUT_BIN" not in runner:
        raise AssertionError("runner does not resolve GNU timeout portably")
    if (
        "--health-cmd "
        "'/usr/bin/sha256sum --check --status "
        "/opt/verdict/dfir-toolchain.sha256'" not in runner
    ):
        raise AssertionError(
            "mounted runtime does not override health with integrity-only check"
        )


def _assert_pinned_pull_and_offline_runtime(runner: str) -> None:
    if 'GHCR_IMAGE="${FINDEVIL_DFIR_GHCR:-}"' not in runner:
        raise AssertionError("remote DFIR image pull is enabled by default")
    if "@sha256:[0-9a-f]{64}" not in runner:
        raise AssertionError("remote DFIR image reference is not digest-gated")
    if "verdict-dfir-toolkit:latest" in runner:
        raise AssertionError("mutable latest tag remains in privileged runner")

    pinned_branch = runner.find('if [[ -n "${GHCR_IMAGE}" ]]; then')
    local_branch = runner.find('elif docker image inspect "${IMAGE}"')
    if pinned_branch < 0 or local_branch < 0 or pinned_branch >= local_branch:
        raise AssertionError(
            "an explicitly pinned image does not outrank the local tag"
        )
    if 'ALLOW_LOCAL_BUILD="${FINDEVIL_DFIR_ALLOW_LOCAL_BUILD:-0}"' not in runner:
        raise AssertionError("networked local Dockerfile build is not explicit opt-in")
    if 'docker build -f "${DOCKERFILE}" -t "${IMAGE}" "${REPO_ROOT}"' in runner:
        raise AssertionError(
            "local image build sends the complete repository as context"
        )
    if '"${EMPTY_BUILD_CONTEXT}"' not in runner:
        raise AssertionError("local image build does not use an empty context")
    if '"${CLEAR_PROXY_BUILD_ARGS[@]}"' not in runner:
        raise AssertionError(
            "local Dockerfile build can inherit ambient proxy credentials"
        )
    identity_at = runner.find('IMAGE_ID="$(docker_bounded image inspect')
    preflight_at = runner.find('log "isolated toolchain preflight')
    if identity_at < 0 or preflight_at < 0 or identity_at >= preflight_at:
        raise AssertionError(
            "selected Docker image is not pinned before parser preflight"
        )
    if '[[ "${IMAGE_ID}" =~ ^sha256:[0-9a-f]{64}$ ]]' not in runner:
        raise AssertionError("resolved Docker image ID is not fail-closed validated")
    if runner.count('"${IMAGE_ID}"') < 4:
        raise AssertionError(
            "preflight, builder, and evidence runtime do not share one immutable image ID"
        )

    build_start = runner.find('BUILD_CTR="${CTR:0:100}-build-$$"')
    mount_start = runner.find("RUNTIME_MOUNTS=(")
    if build_start < 0 or mount_start < 0 or build_start >= mount_start:
        raise AssertionError("MCP build/sync does not finish before evidence mounting")
    build_block = runner[build_start:mount_start]
    fetch_at = build_block.find("cargo fetch --locked")
    disconnect_at = build_block.find(
        'docker_bounded network disconnect bridge "${BUILD_CTR}"'
    )
    offline_at = build_block.find(
        "cargo build --release -p findevil-mcp --frozen --offline"
    )
    if min(fetch_at, disconnect_at, offline_at) < 0:
        raise AssertionError(
            "builder does not split locked retrieval from offline Rust compilation"
        )
    if not fetch_at < disconnect_at < offline_at:
        raise AssertionError(
            "builder network is not disconnected before dependency build scripts execute"
        )
    if '"{{len .NetworkSettings.Networks}}"' not in build_block:
        raise AssertionError("builder does not prove all Docker networks are detached")
    if "CARGO_NET_OFFLINE=true" not in build_block:
        raise AssertionError(
            "offline compile does not fail closed on Cargo network access"
        )
    if "--network bridge" not in build_block:
        raise AssertionError("dependency retrieval does not name its temporary network")
    if re.search(r"docker run\s+[^\n]*\s-i(?:\s|$)", build_block):
        raise AssertionError("builder inherits an interactive stdin channel")
    if "uv sync" in build_block or "services/agent" in build_block:
        raise AssertionError(
            "networked parser builder can modify the host custody environment"
        )
    if "${EVIDENCE_ABS}" in build_block or ":/evidence" in build_block:
        raise AssertionError("pre-evidence builder can access evidence")
    if "--cap-add" in build_block or "apparmor=unconfined" in build_block:
        raise AssertionError("pre-evidence builder has runtime mount privileges")
    if (
        '-v "${REPO_ROOT}:/workspace"' in build_block
        or "src=${REPO_ROOT},dst=/workspace" in build_block
    ):
        raise AssertionError("networked builder can read or mutate the complete repo")
    required_build_mounts = (
        "${REPO_ROOT}/Cargo.toml",
        "${REPO_ROOT}/Cargo.lock",
        "${REPO_ROOT}/rust-toolchain.toml",
        "${REPO_ROOT}/services/mcp",
    )
    missing_build_mounts = [
        path for path in required_build_mounts if path not in build_block
    ]
    if missing_build_mounts:
        raise AssertionError(
            "networked builder mount allow-list incomplete: "
            + ", ".join(missing_build_mounts)
        )
    required_build_bounds = (
        '--memory "${BUILD_MEMORY_LIMIT}"',
        '--cpus "${BUILD_CPU_LIMIT}"',
        '--pids-limit "${BUILD_PIDS_LIMIT}"',
        'run_bounded_builder_phase "${BUILD_TIMEOUT_SECONDS}"',
        'run_bounded_builder_phase "${BUILD_FETCH_TIMEOUT_SECONDS}"',
        '"/verdict-build:rw,nosuid,nodev,exec,size=${BUILD_TMPFS_LIMIT},mode=1777"',
        "/bin/bash --noprofile --norc -c",
        'python3 "${BOUNDED_COPY_HELPER}"',
        '"${BUILD_LOG_MAX_BYTES}"',
        'BUILD_OUTPUT_DIR="${REPO_ROOT}/.project-local/tmp/dfir-build-output/${CASE_ID}"',
    )
    missing_build_bounds = [
        value for value in required_build_bounds if value not in build_block
    ]
    if missing_build_bounds:
        raise AssertionError(
            "networked builder resource/freshness bounds incomplete: "
            + ", ".join(missing_build_bounds)
        )
    if "dst=/verdict-build" in build_block:
        raise AssertionError(
            "networked builder retains an unquotaed writable host bind"
        )
    if '"${CLEAR_PROXY_ENV_ARGS[@]}"' not in build_block:
        raise AssertionError("builder PID 1 can inherit ambient proxy credentials")
    trap_at = build_block.find("trap cleanup_builder_on_exit EXIT")
    start_at = build_block.find('docker_bounded run -d --name "${BUILD_CTR}"')
    clear_at = build_block.find("trap - EXIT HUP INT TERM")
    if min(trap_at, start_at, clear_at) < 0 or not trap_at < start_at < clear_at:
        raise AssertionError("interrupted Rust builder is not guarded by an EXIT trap")
    if 'BUILD_CTR_ACTIVE="1"' not in build_block:
        raise AssertionError(
            "builder cleanup trap cannot identify a partial live start"
        )

    runtime_start = runner.find("docker run -d --name")
    runtime_end = runner.find("# 4. Require Docker", runtime_start)
    if runtime_start < 0 or runtime_end < 0:
        raise AssertionError("runtime docker invocation not found")
    runtime_block = runner[runtime_start:runtime_end]
    if "--pull never" not in runtime_block:
        raise AssertionError(
            "evidence runtime can pull a mutable image after preflight"
        )
    if "--network none" not in runtime_block:
        raise AssertionError("evidence-processing runtime retains outbound network")
    if '"${RUNTIME_SECURITY_ARGS[@]}"' not in runtime_block:
        raise AssertionError("runtime does not apply evidence-aware least privilege")
    if '--memory "${MEMORY_LIMIT}"' not in runtime_block:
        raise AssertionError("runtime has no hard container memory ceiling")
    if '--cpus "${CPU_LIMIT}"' not in runtime_block:
        raise AssertionError("runtime has no hard container CPU ceiling")
    if '"${CLEAR_PROXY_ENV_ARGS[@]}"' not in runtime_block:
        raise AssertionError("evidence runtime can inherit ambient proxy credentials")

    post_runtime = runner[runtime_end:]
    if (
        "cargo build --release -p findevil-mcp" in post_runtime
        or "uv sync" in post_runtime
    ):
        raise AssertionError(
            "runtime still needs networked build/sync after evidence attachment"
        )


def _assert_ambient_proxy_credentials_are_cleared(runner: str) -> None:
    proxy_array_start = runner.find("CLEAR_PROXY_ENV_ARGS=(")
    proxy_array_end = runner.find("\n)", proxy_array_start)
    build_array_start = runner.find("CLEAR_PROXY_BUILD_ARGS=(")
    build_array_end = runner.find("\n)", build_array_start)
    if min(proxy_array_start, proxy_array_end, build_array_start, build_array_end) < 0:
        raise AssertionError("Docker proxy scrub arrays are missing")
    proxy_array = runner[proxy_array_start:proxy_array_end]
    build_array = runner[build_array_start:build_array_end]
    missing_runtime = [
        name for name in REQUIRED_PROXY_ENV_NAMES if f'"{name}="' not in proxy_array
    ]
    missing_build = [
        name for name in REQUIRED_PROXY_ENV_NAMES if f'"{name}="' not in build_array
    ]
    if missing_runtime or missing_build:
        raise AssertionError(
            "Docker proxy scrub is incomplete: "
            + ", ".join(sorted(set(missing_runtime + missing_build)))
        )
    preflight_start = runner.find('log "isolated toolchain preflight')
    preflight_end = runner.find("# 3. Compile", preflight_start)
    if '"${CLEAR_PROXY_ENV_ARGS[@]}"' not in runner[preflight_start:preflight_end]:
        raise AssertionError("isolated preflight can inherit ambient proxy credentials")


def _assert_runtime_host_mount_boundary(runner: str) -> None:
    mounts_start = runner.find("RUNTIME_MOUNTS=(")
    runtime_start = runner.find("docker run -d --name")
    runtime_end = runner.find("# 4. Require Docker", runtime_start)
    if mounts_start < 0 or runtime_start < 0 or runtime_end < 0:
        raise AssertionError("runtime docker invocation not found")
    runtime_block = runner[runtime_start:runtime_end]
    mount_block = runner[mounts_start:runtime_start]
    broad_mounts = (
        '-v "${REPO_ROOT}:/workspace',
        '-v "${REPO_ROOT}/tmp:/workspace/tmp',
        "src=${REPO_ROOT},dst=/workspace",
        "src=${REPO_ROOT}/tmp,dst=/workspace/tmp",
    )
    present = [
        mount
        for mount in broad_mounts
        if mount in mount_block or mount in runtime_block
    ]
    if present:
        raise AssertionError(
            "runtime exposes repo-wide host state: " + ", ".join(present)
        )
    required_runtime_mounts = (
        "${RUST_MCP_BINARY}",
        "${REPO_ROOT}/assets/yara/disk-triage.yar",
    )
    missing_runtime_mounts = [
        path for path in required_runtime_mounts if path not in mount_block
    ]
    if missing_runtime_mounts:
        raise AssertionError(
            "runtime mount allow-list incomplete: " + ", ".join(missing_runtime_mounts)
        )
    if 'CASE_ID="${FINDEVIL_DFIR_CASE_ID:-' not in runner:
        raise AssertionError("runtime output mount is not pinned to one case id")
    if 'CASE_ID="${FINDEVIL_DFIR_CASE_ID:-}"' not in runner:
        raise AssertionError("runner silently invents an unreserved case id")
    if 'require_repo_file "${CASE_DIR}/.verdict-case-marker"' not in runner:
        raise AssertionError("runtime does not require verdict-owned case reservation")
    if '"${RUNTIME_MOUNTS[@]}"' not in runtime_block:
        raise AssertionError("runtime does not attach the reviewed mount allow-list")
    if "FINDEVIL_HOME=/verdict-runtime/findevil" not in runtime_block:
        raise AssertionError("runtime case store is not isolated from repo state")
    for bounded_tmpfs in (
        '"${CONTAINER_CASE_DIR}:rw,nosuid,nodev,size=${PARSER_STATE_TMPFS_LIMIT},mode=1777"',
        '"/verdict-runtime:rw,nosuid,nodev,size=${RUST_STATE_TMPFS_LIMIT},mode=1777"',
    ):
        if bounded_tmpfs not in runtime_block:
            raise AssertionError(
                "parser writable state is not hard-sized: " + bounded_tmpfs
            )
    if not re.search(
        r'docker_mount_spec type=bind "src=\$\{REPO_ROOT\}/services/mcp" '
        r"dst=/workspace/services/mcp readonly bind-recursive=readonly "
        r"bind-propagation=rprivate",
        runner,
    ):
        raise AssertionError(
            "networked builder source does not force Docker-compatible recursive read-only"
        )
    if (
        "dst=/evidence readonly bind-recursive=readonly "
        "bind-propagation=rprivate" not in mount_block
    ):
        raise AssertionError(
            "directory evidence does not force Docker-compatible recursive read-only"
        )
    if "src=${PARSER_STATE_DIR}" in runner or "src=${RUST_STATE_DIR}" in runner:
        raise AssertionError("parser writable state still uses unquotaed host binds")
    forbidden_runtime_sources = (
        "${CASE_DIR},dst=${CONTAINER_CASE_DIR}",
        "${REPO_ROOT}/services/agent",
        "${REPO_ROOT}/services/agent_mcp",
        "${REPO_ROOT}/.project-local,dst=",
    )
    leaked_sources = [item for item in forbidden_runtime_sources if item in mount_block]
    if leaked_sources:
        raise AssertionError(
            "parser can access custody code/output or broad private state: "
            + ", ".join(leaked_sources)
        )
    if (
        "RUNTIME_SECURITY_ARGS=(--cap-drop ALL --security-opt no-new-privileges:true)"
        not in runner
    ):
        raise AssertionError("non-disk evidence runtime is not capability-free")
    forbidden_privilege = (
        "--cap-add",
        "apparmor=unconfined",
        "--device",
        "/dev/fuse",
        "/dev/loop-control",
    )
    present_privilege = [item for item in forbidden_privilege if item in runner]
    if present_privilege:
        raise AssertionError(
            "runtime retains an evidence-parser privilege path: "
            + ", ".join(present_privilege)
        )
    if "compressed EWF mounting is disabled in the Docker backend" not in runner:
        raise AssertionError("Docker EWF input is not rejected with safe guidance")
    if "src=${parent},dst=/evidence" in runner:
        raise AssertionError(
            "single-file evidence can expose its host parent directory"
        )
    if (
        "require_no_symlink_components" not in runner
        or '".." in raw.parts' not in runner
    ):
        raise AssertionError(
            "evidence bind path does not reject symlink/traversal components"
        )


def _assert_mount_specs_are_csv_encoded(runner: str) -> None:
    raw_specs = re.findall(r'--mount\s+"type=bind,', runner)
    if raw_specs:
        raise AssertionError("runner still interpolates a raw Docker mount CSV string")
    mount_calls = re.findall(r'--mount\s+"\$\(docker_mount_spec\b', runner)
    if len(mount_calls) != 8:
        raise AssertionError(
            f"expected every one of 8 bind specs to use the encoder, got {len(mount_calls)}"
        )
    hostile_source = '/drop/evidence,src=/,dst=/stolen"quote'
    result = subprocess.run(
        [
            sys.executable,
            str(MOUNT_SPEC_HELPER),
            "type=bind",
            f"src={hostile_source}",
            "dst=/evidence",
            "readonly",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"mount encoder rejected a valid hostile path: {result.stderr}"
        )
    fields = next(csv.reader(io.StringIO(result.stdout), strict=True))
    if fields != ["type=bind", f"src={hostile_source}", "dst=/evidence", "readonly"]:
        raise AssertionError(f"mount CSV fields were injected or corrupted: {fields!r}")
    newline = subprocess.run(
        [sys.executable, str(MOUNT_SPEC_HELPER), "type=bind", "src=/tmp/a\nb"],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    if newline.returncode == 0:
        raise AssertionError("mount encoder accepts audit-hostile newline paths")


def _assert_build_artifact_copy_is_bounded(runner: str) -> None:
    if '[[ -r "${BOUNDED_COPY_HELPER}" ]]' not in runner:
        raise AssertionError("runner does not require the bounded build copier")
    with tempfile.TemporaryDirectory(prefix="verdict-bounded-copy-") as temp_dir:
        temp = Path(temp_dir)
        exact = temp / "exact.bin"
        exact_result = subprocess.run(
            [sys.executable, str(BOUNDED_COPY_HELPER), str(exact), "16"],
            input=b"x" * 16,
            capture_output=True,
            check=False,
            timeout=10,
        )
        if exact_result.returncode != 0 or exact.read_bytes() != b"x" * 16:
            raise AssertionError("bounded build copier rejected exact-limit input")
        overflow = temp / "overflow.bin"
        overflow_result = subprocess.run(
            [sys.executable, str(BOUNDED_COPY_HELPER), str(overflow), "15"],
            input=b"x" * 16,
            capture_output=True,
            check=False,
            timeout=10,
        )
        if overflow_result.returncode == 0 or overflow.exists():
            raise AssertionError("bounded build copier retained oversized output")


def _assert_case_scoped_runtime_handoff(runner: str, verdict: str) -> None:
    old_global = ".project-local/tmp/dfir-container-evidence-path"
    if old_global in runner or old_global in verdict:
        raise AssertionError("Docker evidence handoff is still process-global")
    required_runner = (
        'EVIDENCE_PATH_FILE="${RUNTIME_STATE_DIR}/evidence-path"',
        '"${RUNTIME_STATE_DIR}/.verdict-runtime-marker"',
    )
    if missing := [value for value in required_runner if value not in runner]:
        raise AssertionError(
            "runner lacks case-scoped handoff state: " + ", ".join(missing)
        )
    required_verdict = (
        "docker_case_token=",
        'DOCKER_RUNTIME_CONTAINER="${docker_container_base:0:100}-${docker_case_token}"',
        'FINDEVIL_DFIR_CONTAINER="${DOCKER_RUNTIME_CONTAINER}"',
        'export FIND_EVIL_DOCKER_CONTAINER="${DOCKER_RUNTIME_CONTAINER}"',
        'bash "${REPO_ROOT}/scripts/run-dfir-container.sh" --down',
        'DOCKER_RUNTIME_STATE_DIR="${REPO_ROOT}/.project-local/tmp/dfir-runtime/${CASE_ID}"',
        'DOCKER_BUILD_OUTPUT_DIR="${REPO_ROOT}/.project-local/tmp/dfir-build-output/${CASE_ID}"',
        ".verdict-runtime-marker",
        ".verdict-build-marker",
    )
    if missing := [value for value in required_verdict if value not in verdict]:
        raise AssertionError(
            "verdict lacks case-scoped runtime lifecycle: " + ", ".join(missing)
        )
    post_bringup = verdict[verdict.find("# 3c. Docker backend bring-up") :]
    if '[[ -d "${ORIGINAL_EVIDENCE}" ]]' in post_bringup:
        raise AssertionError("verdict re-stats mutable evidence after Docker bring-up")


def _assert_local_docker_daemon_only(runner: str) -> None:
    if "require_local_docker_daemon" not in runner:
        raise AssertionError("runner does not verify where bind sources resolve")
    if "unix://*|npipe://*" not in runner:
        raise AssertionError("runner does not restrict Docker to local transports")
    daemon_call = runner.find("\nrequire_local_docker_daemon\n")
    down_branch = runner.find('if [[ "${1:-}" == "--down" ]]')
    if daemon_call < 0 or down_branch < 0 or daemon_call >= down_branch:
        raise AssertionError("remote Docker gate does not run before Docker actions")

    with tempfile.TemporaryDirectory(prefix="verdict-local-docker-") as temp_dir:
        temp = Path(temp_dir)
        docker_probe = temp / "docker"
        docker_probe.write_text(
            "#!/bin/sh\n"
            'if [ "$1" = context ] && [ "$2" = inspect ]; then\n'
            "  expected='{{(index .Endpoints \"docker\").Host}}'\n"
            '  [ "$3" = --format ] && [ "$4" = "$expected" ] '
            "|| exit 64\n"
            "  printf '%s\\n' 'unix:///var/run/docker.sock'\n"
            "  exit 0\n"
            "fi\n"
            'if [ "$1" = rm ] && [ "$2" = -f ]; then exit 0; fi\n'
            "exit 64\n",
            encoding="utf-8",
        )
        docker_probe.chmod(0o755)
        environment = {
            **os.environ,
            "PATH": f"{temp}{os.pathsep}{os.environ.get('PATH', '')}",
            "DOCKER_CONTEXT": "local-review",
            "FINDEVIL_TIMEOUT_BIN": "timeout",
        }
        environment.pop("DOCKER_HOST", None)
        result = subprocess.run(
            ["bash", str(RUNNER), "--down"],
            cwd=REPO_ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        if result.returncode != 0:
            raise AssertionError(
                "valid local Docker context template was rejected: "
                f"{result.stderr.strip()}"
            )

    with tempfile.TemporaryDirectory(prefix="verdict-remote-docker-") as temp_dir:
        temp = Path(temp_dir)
        docker_probe = temp / "docker"
        remote_action = temp / "remote-action"
        docker_probe.write_text(
            "#!/bin/sh\n"
            'if [ "$1" = context ] && [ "$2" = inspect ]; then\n'
            "  printf '%s\\n' 'ssh://forensics.example.invalid'\n"
            "  exit 0\n"
            "fi\n"
            f": > {shlex.quote(str(remote_action))}\n",
            encoding="utf-8",
        )
        docker_probe.chmod(0o755)
        environment = {
            **os.environ,
            "PATH": f"{temp}{os.pathsep}{os.environ.get('PATH', '')}",
            "DOCKER_CONTEXT": "remote-review",
            "FINDEVIL_TIMEOUT_BIN": "timeout",
        }
        environment.pop("DOCKER_HOST", None)
        result = subprocess.run(
            ["bash", str(RUNNER), "--down"],
            cwd=REPO_ROOT,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        if (
            result.returncode == 0
            or "refusing non-local Docker daemon" not in result.stderr
        ):
            raise AssertionError("remote Docker context did not fail closed")
        if remote_action.exists():
            raise AssertionError(
                "runner acted on a remote Docker daemon before refusal"
            )


def _assert_sensitive_evidence_scope_rejected(runner: str) -> None:
    validate_at = runner.find('validate_evidence_scope "${EVIDENCE_ABS}"')
    image_at = runner.find("# 1. Get the image")
    if validate_at < 0 or image_at < 0 or validate_at >= image_at:
        raise AssertionError(
            "sensitive evidence scope is not rejected before image/build work"
        )
    required = (
        "FINDEVIL_SIGNING_KEY",
        "FINDEVIL_MEMORY_STORE",
        "FINDEVIL_EXPERT_MISS_LEDGER",
        "FINDEVIL_INJECTION_LEDGER",
        "DOCKER_CERT_PATH",
        "FIND_EVIL_SSH_KEY",
        "metadata.st_nlink != 1",
        "socket/device/FIFO",
    )
    if missing := [value for value in required if value not in runner]:
        raise AssertionError(
            "evidence scope checks are incomplete: " + ", ".join(missing)
        )
    if runner.count('validate_evidence_scope "${EVIDENCE_ABS}"') < 2:
        raise AssertionError(
            "directory special-file scope is not rechecked after build"
        )

    with tempfile.TemporaryDirectory(prefix="verdict-scope-probe-") as temp_dir:
        temp = Path(temp_dir)
        docker_probe = temp / "docker"
        docker_action = temp / "unexpected-docker-action"
        docker_probe.write_text(
            "#!/bin/sh\n"
            'if [ "$1" = context ] && [ "$2" = inspect ]; then\n'
            "  printf '%s\\n' 'unix:///var/run/docker.sock'\n"
            "  exit 0\n"
            "fi\n"
            f": > {shlex.quote(str(docker_action))}\n",
            encoding="utf-8",
        )
        docker_probe.chmod(0o755)
        environment = {
            **os.environ,
            "PATH": f"{temp}{os.pathsep}{os.environ.get('PATH', '')}",
            "DOCKER_CONTEXT": "local-review",
            "FINDEVIL_TIMEOUT_BIN": "timeout",
            "FINDEVIL_DFIR_CASE_ID": "scope-contract-case",
        }
        environment.pop("DOCKER_HOST", None)

        signing_key = temp / "signing.key"
        signing_key.write_bytes(b"private signing material")
        environment["FINDEVIL_SIGNING_KEY"] = str(signing_key)
        hardlink_dir = temp / "hardlink-evidence"
        hardlink_dir.mkdir()
        os.link(signing_key, hardlink_dir / "innocent.bin")

        unsafe_paths = [
            REPO_ROOT,
            REPO_ROOT.parent,
            REPO_ROOT / ".project-local",
            REPO_ROOT / "tmp" / "auto-runs",
            signing_key,
            hardlink_dir,
        ]
        socket_dir = temp / "s"
        socket_dir.mkdir()
        socket_path = socket_dir / "x"
        bound_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        bound_socket.bind(str(socket_path))
        unsafe_paths.append(socket_dir)
        try:
            for unsafe in unsafe_paths:
                result = subprocess.run(
                    ["bash", str(RUNNER), str(unsafe)],
                    cwd=REPO_ROOT,
                    env=environment,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=15,
                )
                if (
                    result.returncode == 0
                    or "unsafe Docker evidence path" not in result.stderr
                ):
                    raise AssertionError(
                        f"unsafe evidence scope was accepted: {unsafe}"
                    )
                if docker_action.exists():
                    raise AssertionError(
                        "Docker work began before unsafe scope refusal"
                    )
        finally:
            bound_socket.close()


def _assert_runtime_python_is_host_custody(
    config_text: str, launcher: str, docker_wrapper: str
) -> None:
    config = json.loads(config_text)
    server = config["mcpServers"]["findevil-agent-mcp"]
    if server.get("command") != "bash" or server.get("args") != [
        "scripts/run-mcp-python-docker.sh"
    ]:
        raise AssertionError(
            "Docker Python custody MCP still executes in parser container"
        )
    if "--frozen" not in launcher or "--no-sync" not in launcher:
        raise AssertionError(
            "Docker Python MCP can mutate or re-resolve its lock at runtime"
        )
    if (
        "FINDEVIL_REPLAY_TRANSPORT=docker" not in docker_wrapper
        or "FINDEVIL_REPLAY_DOCKER_CONTAINER" not in docker_wrapper
    ):
        raise AssertionError("host custody wrapper lacks its fixed Docker replay route")
    if "FINDEVIL_CUSTODY_BOUNDARY=reserved_case" not in docker_wrapper:
        raise AssertionError("host custody wrapper does not force reserved-case policy")
    for name in (
        "FINDEVIL_ACTIVE_CASE_DIR",
        "FINDEVIL_ACTIVE_CASE_ID",
        "FINDEVIL_ACTIVE_RUN_ID",
        "FINDEVIL_ACTIVE_STARTED_AT",
        "FINDEVIL_ACTIVE_SIGNER",
    ):
        if f"${{{name}:?" not in docker_wrapper:
            raise AssertionError(f"host custody wrapper does not require {name}")


def main() -> None:
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    runner = RUNNER.read_text(encoding="utf-8")
    verdict = VERDICT_RUNNER.read_text(encoding="utf-8")
    docker_mcp_config = DOCKER_MCP_CONFIG.read_text(encoding="utf-8")
    python_launcher = PYTHON_LAUNCHER.read_text(encoding="utf-8")
    python_docker_wrapper = PYTHON_DOCKER_WRAPPER.read_text(encoding="utf-8")
    try:
        preflight = PREFLIGHT.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise AssertionError(f"missing isolated preflight: {PREFLIGHT}") from exc
    smoke_runner = SMOKE_RUNNER.read_text(encoding="utf-8")

    healthcheck = _directive_block(dockerfile, "HEALTHCHECK", "USER")
    _assert_healthcheck_is_integrity_only(healthcheck)
    _assert_ez_archives_are_content_pinned(dockerfile)
    _assert_non_apt_payloads_are_content_pinned(dockerfile)
    _assert_integrity_binary_cannot_be_shadowed(dockerfile, runner, preflight)
    _assert_every_parser_dependency_is_sealed(dockerfile)
    _assert_preflight_probes(preflight)
    _assert_preflight_fails_closed(preflight)
    _assert_isolated_before_mounts(runner)
    _assert_health_wait_fails_closed(runner)
    _assert_pinned_pull_and_offline_runtime(runner)
    _assert_ambient_proxy_credentials_are_cleared(runner)
    _assert_runtime_host_mount_boundary(runner)
    _assert_mount_specs_are_csv_encoded(runner)
    _assert_build_artifact_copy_is_bounded(runner)
    _assert_case_scoped_runtime_handoff(runner, verdict)
    _assert_local_docker_daemon_only(runner)
    _assert_sensitive_evidence_scope_rejected(runner)
    _assert_runtime_python_is_host_custody(
        docker_mcp_config, python_launcher, python_docker_wrapper
    )
    if "python3 scripts/dfir-container-contract-smoke.py" not in smoke_runner:
        raise AssertionError(
            "Docker capability contract is not wired into run-all-smokes.sh"
        )

    print(
        "dfir-container-contract-smoke: OK "
        f"({len(REQUIRED_PARSER_PROBES)} parser probes; isolated + timed + fail-closed)"
    )


if __name__ == "__main__":
    main()
