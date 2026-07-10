#!/usr/bin/env bash
# Bring up the VERDICT DFIR container as the tool backend — the container analog
# of sift-vm-bootstrap.sh. Builds docker/dfir.Dockerfile if needed, starts a
# case-scoped 'findevil-dfir' container with only the reviewed MCP runtime files
# mounted read-only, two hard-sized private parser tmpfs areas, and (optional)
# evidence read-only at /evidence. Signed case output and the Python custody
# service remain host-only. After this,
# `scripts/verdict --docker` (or copying
# .mcp.json.docker over .mcp.json) routes the MCP over `docker exec -i`.
#
# Usage:
#   scripts/run-dfir-container.sh [evidence-path]
#   scripts/run-dfir-container.sh --down        # stop + remove the container
#
# The evidence runtime is always unprivileged; compressed EWF mounting is refused.
set -euo pipefail
umask 077

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${FINDEVIL_DFIR_IMAGE:-findevil/dfir:local}"
CTR="${FINDEVIL_DFIR_CONTAINER:-findevil-dfir}"
# Escape hatch for a deliberately partial image (e.g. a slimmed CI variant).
# Never set this to paper over a broken build.
ALLOW_MISSING="${FINDEVIL_DFIR_ALLOW_MISSING:-0}"
PROBE_TIMEOUT_SECONDS="${FINDEVIL_DFIR_PROBE_TIMEOUT:-30}"
PREFLIGHT_TIMEOUT_SECONDS="${FINDEVIL_DFIR_PREFLIGHT_TIMEOUT:-120}"
HEALTH_TIMEOUT_SECONDS="${FINDEVIL_DFIR_HEALTH_TIMEOUT:-90}"
DOCKER_TIMEOUT_SECONDS="${FINDEVIL_DFIR_DOCKER_TIMEOUT:-10}"
MEMORY_LIMIT="${FINDEVIL_DFIR_MEMORY_LIMIT:-4g}"
PIDS_LIMIT="${FINDEVIL_DFIR_PIDS_LIMIT:-512}"
CPU_LIMIT="${FINDEVIL_DFIR_CPU_LIMIT:-2.0}"
PREFLIGHT_MEMORY_LIMIT="${FINDEVIL_DFIR_PREFLIGHT_MEMORY_LIMIT:-2g}"
PREFLIGHT_CPU_LIMIT="${FINDEVIL_DFIR_PREFLIGHT_CPU_LIMIT:-2.0}"
BUILD_MEMORY_LIMIT="${FINDEVIL_DFIR_BUILD_MEMORY_LIMIT:-6g}"
BUILD_PIDS_LIMIT="${FINDEVIL_DFIR_BUILD_PIDS_LIMIT:-512}"
BUILD_CPU_LIMIT="${FINDEVIL_DFIR_BUILD_CPU_LIMIT:-4.0}"
BUILD_TIMEOUT_SECONDS="${FINDEVIL_DFIR_BUILD_TIMEOUT:-1800}"
BUILD_FETCH_TIMEOUT_SECONDS="${FINDEVIL_DFIR_BUILD_FETCH_TIMEOUT:-900}"
BUILD_TMPFS_LIMIT="${FINDEVIL_DFIR_BUILD_TMPFS_LIMIT:-8g}"
BUILD_BINARY_MAX_BYTES="${FINDEVIL_DFIR_BUILD_BINARY_MAX_BYTES:-268435456}"
BUILD_LOG_MAX_BYTES="${FINDEVIL_DFIR_BUILD_LOG_MAX_BYTES:-8388608}"
PARSER_STATE_TMPFS_LIMIT="${FINDEVIL_DFIR_PARSER_STATE_LIMIT:-2g}"
RUST_STATE_TMPFS_LIMIT="${FINDEVIL_DFIR_RUST_STATE_LIMIT:-512m}"
ALLOW_LOCAL_BUILD="${FINDEVIL_DFIR_ALLOW_LOCAL_BUILD:-0}"

if [[ "${#IMAGE}" -gt 255 || ! "${IMAGE}" =~ ^[[:alnum:]][[:alnum:]./_:@+-]*$ ]]; then
  printf '\n[run-dfir-container] ERROR: FINDEVIL_DFIR_IMAGE is not a safe Docker image reference\n\n' >&2
  exit 1
fi
if [[ "${#CTR}" -gt 128 || ! "${CTR}" =~ ^[[:alnum:]][[:alnum:]_.-]*$ ]]; then
  printf '\n[run-dfir-container] ERROR: FINDEVIL_DFIR_CONTAINER is not a safe Docker container name\n\n' >&2
  exit 1
fi

fail() { printf '\n[run-dfir-container] ERROR: %s\n\n' "$*" >&2; exit 1; }
DOCKERFILE="${REPO_ROOT}/docker/dfir.Dockerfile"
# Remote pulls are opt-in and must name an immutable reviewed digest. The
# default is a local Dockerfile build; a mutable privileged image tag is never
# fetched automatically.
GHCR_IMAGE="${FINDEVIL_DFIR_GHCR:-}"
PREFLIGHT_SCRIPT="${REPO_ROOT}/scripts/lib/dfir-container-preflight.sh"
MOUNT_SPEC_HELPER="${REPO_ROOT}/scripts/lib/docker-mount-spec.py"
BOUNDED_COPY_HELPER="${REPO_ROOT}/scripts/lib/bounded-stream-copy.py"

# Docker can auto-inject proxy values from the operator's client config into
# containers and builds. Those URLs may contain reusable credentials or reveal
# internal topology. Every execution boundary starts with explicit empty proxy
# variables; an operator who needs a proxy should use a reviewed prebuilt image
# or a deliberately scoped fetch mechanism instead of ambient Docker state.
CLEAR_PROXY_ENV_ARGS=(
  --env "HTTP_PROXY="
  --env "http_proxy="
  --env "HTTPS_PROXY="
  --env "https_proxy="
  --env "FTP_PROXY="
  --env "ftp_proxy="
  --env "ALL_PROXY="
  --env "all_proxy="
  --env "NO_PROXY="
  --env "no_proxy="
)
CLEAR_PROXY_BUILD_ARGS=(
  --build-arg "HTTP_PROXY="
  --build-arg "http_proxy="
  --build-arg "HTTPS_PROXY="
  --build-arg "https_proxy="
  --build-arg "FTP_PROXY="
  --build-arg "ftp_proxy="
  --build-arg "ALL_PROXY="
  --build-arg "all_proxy="
  --build-arg "NO_PROXY="
  --build-arg "no_proxy="
)

log() { printf '[dfir-container] %s\n' "$*"; }
TIMEOUT_BIN=""
docker_bounded() {
  "${TIMEOUT_BIN}" --foreground --kill-after=2s "${DOCKER_TIMEOUT_SECONDS}s" docker "$@"
}

docker_mount_spec() {
  python3 "${MOUNT_SPEC_HELPER}" "$@" \
    || fail "could not safely encode Docker bind mount"
}

resolve_timeout_bin() {
  local candidate path
  local candidates=(timeout gtimeout)
  if [[ -n "${FINDEVIL_TIMEOUT_BIN:-}" ]]; then
    candidates=("${FINDEVIL_TIMEOUT_BIN}")
  fi
  for candidate in "${candidates[@]}"; do
    path="$(command -v "${candidate}" 2>/dev/null || true)"
    [[ -n "${path}" ]] || continue
    if "${path}" --foreground --kill-after=1s 1s true >/dev/null 2>&1; then
      printf '%s\n' "${path}"
      return 0
    fi
  done
  return 1
}

require_local_docker_daemon() {
  local context_name endpoint
  if [[ -n "${DOCKER_HOST:-}" ]]; then
    endpoint="${DOCKER_HOST}"
  else
    context_name="${DOCKER_CONTEXT:-}"
    if [[ -z "${context_name}" ]]; then
      context_name="$(docker_bounded context show 2>/dev/null)" \
        || fail "could not resolve the active Docker context"
    fi
    if [[ "${#context_name}" -gt 128 || ! "${context_name}" =~ ^[[:alnum:]][[:alnum:]_.-]*$ ]]; then
      fail "active Docker context has an unsafe name"
    fi
    endpoint="$(docker_bounded context inspect \
      --format '{{(index .Endpoints "docker").Host}}' "${context_name}" 2>/dev/null)" \
      || fail "could not inspect Docker context ${context_name}"
  fi
  case "${endpoint}" in
    unix://*|npipe://*) ;;
    *)
      fail "refusing non-local Docker daemon endpoint ${endpoint@Q}. Bind sources must resolve on this evidence host; select a local unix:// or npipe:// Docker context"
      ;;
  esac
}

EVIDENCE="${1:-}"

command -v docker >/dev/null || { log "docker not found on PATH"; exit 1; }
TIMEOUT_BIN="$(resolve_timeout_bin)" || fail \
  "GNU coreutils timeout not found (install coreutils on macOS, or set FINDEVIL_TIMEOUT_BIN)"
require_local_docker_daemon

validate_byte_limit() {
  local name="$1" value="$2"
  [[ "${value}" =~ ^[1-9][0-9]*([bBkKmMgG])?$ ]] \
    || fail "${name} must be a Docker byte value such as 4096m or 4g"
}

validate_cpu_limit() {
  local name="$1" value="$2"
  python3 - "${name}" "${value}" <<'PY' || fail "${name} must be between 0.1 and 64 CPUs"
from decimal import Decimal, InvalidOperation
import sys

try:
    value = Decimal(sys.argv[2])
except InvalidOperation:
    raise SystemExit(1)
if not Decimal("0.1") <= value <= Decimal("64"):
    raise SystemExit(1)
PY
}

for byte_limit in \
  "MEMORY_LIMIT:${MEMORY_LIMIT}" \
  "PREFLIGHT_MEMORY_LIMIT:${PREFLIGHT_MEMORY_LIMIT}" \
  "BUILD_MEMORY_LIMIT:${BUILD_MEMORY_LIMIT}" \
  "BUILD_TMPFS_LIMIT:${BUILD_TMPFS_LIMIT}" \
  "PARSER_STATE_TMPFS_LIMIT:${PARSER_STATE_TMPFS_LIMIT}" \
  "RUST_STATE_TMPFS_LIMIT:${RUST_STATE_TMPFS_LIMIT}"; do
  validate_byte_limit "${byte_limit%%:*}" "${byte_limit#*:}"
done
for cpu_limit in \
  "CPU_LIMIT:${CPU_LIMIT}" \
  "PREFLIGHT_CPU_LIMIT:${PREFLIGHT_CPU_LIMIT}" \
  "BUILD_CPU_LIMIT:${BUILD_CPU_LIMIT}"; do
  validate_cpu_limit "${cpu_limit%%:*}" "${cpu_limit#*:}"
done
for integer_limit in \
  "PIDS_LIMIT:${PIDS_LIMIT}:32:32768" \
  "BUILD_PIDS_LIMIT:${BUILD_PIDS_LIMIT}:32:32768" \
  "BUILD_TIMEOUT_SECONDS:${BUILD_TIMEOUT_SECONDS}:60:7200" \
  "BUILD_FETCH_TIMEOUT_SECONDS:${BUILD_FETCH_TIMEOUT_SECONDS}:30:3600" \
  "BUILD_BINARY_MAX_BYTES:${BUILD_BINARY_MAX_BYTES}:1048576:536870912" \
  "BUILD_LOG_MAX_BYTES:${BUILD_LOG_MAX_BYTES}:65536:67108864"; do
  IFS=: read -r integer_name integer_value integer_min integer_max <<< "${integer_limit}"
  case "${integer_value}" in
    ''|*[!0-9]*) fail "${integer_name} must be an integer" ;;
  esac
  (( 10#${integer_value} >= integer_min && 10#${integer_value} <= integer_max )) \
    || fail "${integer_name} must be between ${integer_min} and ${integer_max}"
done
PIDS_LIMIT="$((10#${PIDS_LIMIT}))"
BUILD_PIDS_LIMIT="$((10#${BUILD_PIDS_LIMIT}))"
BUILD_TIMEOUT_SECONDS="$((10#${BUILD_TIMEOUT_SECONDS}))"
BUILD_FETCH_TIMEOUT_SECONDS="$((10#${BUILD_FETCH_TIMEOUT_SECONDS}))"
BUILD_BINARY_MAX_BYTES="$((10#${BUILD_BINARY_MAX_BYTES}))"
BUILD_LOG_MAX_BYTES="$((10#${BUILD_LOG_MAX_BYTES}))"

if [[ "${1:-}" == "--down" ]]; then
  if docker_bounded rm -f "${CTR}" >/dev/null 2>&1; then
    log "removed ${CTR}"
  else
    log "${CTR} not running or removal timed out"
  fi
  exit 0
fi

# scripts/verdict reserves this id and its marked output directory before
# bring-up. Requiring that reservation prevents a direct helper invocation from
# mounting an arbitrary or pre-existing host directory as custody output.
CASE_ID="${FINDEVIL_DFIR_CASE_ID:-}"
if [[ "${#CASE_ID}" -gt 128 || ! "${CASE_ID}" =~ ^[[:alnum:]_][[:alnum:]_.+-]*$ ]]; then
  fail "FINDEVIL_DFIR_CASE_ID must name the reserved scripts/verdict case (1-128 safe characters)"
fi
REPO_REAL="$(realpath -e -- "${REPO_ROOT}")"

# Create a directory below the real repo without following an existing symlink
# component. These directories are the only writable host paths Docker sees.
ensure_repo_dir() {
  local requested="$1" relative current part resolved
  case "${requested}" in
    "${REPO_ROOT}"/*) relative="${requested#"${REPO_ROOT}"/}" ;;
    *) fail "refusing to create container state outside the repository: ${requested}" ;;
  esac
  current="${REPO_ROOT}"
  IFS='/' read -r -a parts <<< "${relative}"
  for part in "${parts[@]}"; do
    [[ -n "${part}" && "${part}" != "." && "${part}" != ".." ]] \
      || fail "unsafe container state path: ${requested}"
    current="${current}/${part}"
    [[ ! -L "${current}" ]] \
      || fail "container state path contains a symlink: ${current}"
    if [[ ! -e "${current}" ]]; then
      mkdir -- "${current}" || fail "could not create container state directory: ${current}"
    fi
    [[ -d "${current}" ]] \
      || fail "container state path is not a directory: ${current}"
  done
  resolved="$(realpath -e -- "${requested}")"
  case "${resolved}" in
    "${REPO_REAL}"/*) ;;
    *) fail "container state path escaped the repository: ${requested}" ;;
  esac
}

require_repo_file() {
  local requested="$1" resolved
  [[ -f "${requested}" && ! -L "${requested}" ]] \
    || fail "required container build input is not a regular file: ${requested}"
  resolved="$(realpath -e -- "${requested}")"
  case "${resolved}" in
    "${REPO_REAL}"/*) ;;
    *) fail "container build input escaped the repository: ${requested}" ;;
  esac
}

require_repo_dir() {
  local requested="$1" resolved
  [[ -d "${requested}" && ! -L "${requested}" ]] \
    || fail "required container build input is not a directory: ${requested}"
  resolved="$(realpath -e -- "${requested}")"
  case "${resolved}" in
    "${REPO_REAL}"/*) ;;
    *) fail "container build input escaped the repository: ${requested}" ;;
  esac
}

require_no_symlink_components() {
  local requested="$1" error
  if ! error="$(python3 - "${requested}" <<'PY'
import os
import stat
import sys
from pathlib import Path

raw = Path(sys.argv[1])
if ".." in raw.parts:
    print("parent traversal component refused")
    raise SystemExit(1)
path = raw if raw.is_absolute() else Path.cwd() / raw
current = Path(path.anchor)
for part in path.parts[1:]:
    current /= part
    try:
        mode = os.lstat(current).st_mode
    except OSError as exc:
        print(f"cannot lstat {current}: {exc}")
        raise SystemExit(1)
    if stat.S_ISLNK(mode):
        print(f"symlink component refused: {current}")
        raise SystemExit(1)
PY
  )"; then
    fail "unsafe evidence path ${requested}: ${error}"
  fi
}

validate_evidence_scope() {
  local evidence_path="$1" error
  local sensitive_paths=(
    "${REPO_ROOT}/.project-local"
    "${REPO_ROOT}/tmp/auto-runs"
    "${REPO_ROOT}/.git"
  )
  for optional_path in \
    "${FINDEVIL_HOME:-}" \
    "${FINDEVIL_SIGNING_KEY:-}" \
    "${FINDEVIL_MEMORY_STORE:-}" \
    "${FINDEVIL_EXPERT_MISS_LEDGER:-}" \
    "${FINDEVIL_INJECTION_LEDGER:-}" \
    "${DOCKER_CERT_PATH:-}" \
    "${FIND_EVIL_SSH_KEY:-}"; do
    [[ -n "${optional_path}" ]] && sensitive_paths+=("${optional_path}")
  done
  if ! error="$(python3 - "${evidence_path}" "${REPO_REAL}" "${sensitive_paths[@]}" <<'PY'
import os
import stat
import sys
from pathlib import Path

evidence = Path(sys.argv[1]).resolve(strict=True)
repo = Path(sys.argv[2]).resolve(strict=True)
sensitive = [Path(value).resolve(strict=False) for value in sys.argv[3:]]


def contains(parent: Path, child: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


evidence_metadata = os.lstat(evidence)
if stat.S_ISDIR(evidence_metadata.st_mode):
    if contains(evidence, repo):
        print(f"directory evidence contains the repository/trusted state: {evidence}")
        raise SystemExit(1)
    for trusted in sensitive:
        if contains(evidence, trusted) or contains(trusted, evidence):
            print(f"directory evidence overlaps trusted custody state: {trusted}")
            raise SystemExit(1)
else:
    if not stat.S_ISREG(evidence_metadata.st_mode) or evidence_metadata.st_nlink != 1:
        print("single-file evidence must be one non-hard-linked regular file")
        raise SystemExit(1)
    for trusted in sensitive:
        if contains(trusted, evidence) or evidence == trusted:
            print(f"single-file evidence overlaps trusted custody state: {trusted}")
            raise SystemExit(1)
        try:
            trusted_metadata = os.stat(trusted, follow_symlinks=False)
        except OSError:
            continue
        if (
            evidence_metadata.st_dev == trusted_metadata.st_dev
            and evidence_metadata.st_ino == trusted_metadata.st_ino
        ):
            print(f"single-file evidence aliases trusted custody state: {trusted}")
            raise SystemExit(1)
    raise SystemExit(0)

pending = [evidence]
seen = 0
while pending:
    directory = pending.pop()
    try:
        entries = os.scandir(directory)
    except OSError as exc:
        print(f"cannot inspect evidence directory {directory}: {exc}")
        raise SystemExit(1)
    with entries:
        for entry in entries:
            seen += 1
            if seen > 1_000_000:
                print("directory evidence exceeds the 1000000-entry safety preflight")
                raise SystemExit(1)
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as exc:
                print(f"cannot lstat evidence entry {entry.path}: {exc}")
                raise SystemExit(1)
            mode = metadata.st_mode
            if stat.S_ISLNK(mode):
                print(f"directory evidence contains a symlink: {entry.path}")
                raise SystemExit(1)
            if stat.S_ISDIR(mode):
                pending.append(Path(entry.path))
            elif not stat.S_ISREG(mode):
                print(f"directory evidence contains a socket/device/FIFO: {entry.path}")
                raise SystemExit(1)
            elif metadata.st_nlink != 1:
                print(f"directory evidence contains a hard-linked file: {entry.path}")
                raise SystemExit(1)
PY
  )"; then
    fail "unsafe Docker evidence path ${evidence_path}: ${error}"
  fi
}

evidence_root_identity() {
  python3 - "$1" <<'PY'
import os
import sys

metadata = os.stat(sys.argv[1], follow_symlinks=False)
print(f"{metadata.st_dev}:{metadata.st_ino}:{metadata.st_mode}")
PY
}

EVIDENCE_ABS=""
EVIDENCE_ROOT_IDENTITY=""
if [[ -n "${EVIDENCE}" ]]; then
  require_no_symlink_components "${EVIDENCE}"
  EVIDENCE_ABS="$(realpath -e -- "${EVIDENCE}")"
  validate_evidence_scope "${EVIDENCE_ABS}"
  if [[ -d "${EVIDENCE_ABS}" ]]; then
    :
  elif [[ -f "${EVIDENCE_ABS}" ]]; then
    case "$(basename "${EVIDENCE_ABS}")" in
      *.[eE]01)
        fail "compressed EWF mounting is disabled in the Docker backend because it requires a root/FUSE parser boundary. Use local/SIFT, or extract supported artifacts first: ${EVIDENCE_ABS}"
        ;;
    esac
  else
    fail "evidence path is neither a regular file nor a directory: ${EVIDENCE_ABS}"
  fi
  EVIDENCE_ROOT_IDENTITY="$(evidence_root_identity "${EVIDENCE_ABS}")"
fi

# 1. Get the image: use a local build, an explicitly digest-pinned published
#    image, or build from the reviewed Dockerfile.
if [[ -n "${GHCR_IMAGE}" ]] && ! [[ "${GHCR_IMAGE}" =~ @sha256:[0-9a-f]{64}$ ]]; then
  fail "FINDEVIL_DFIR_GHCR must use an immutable digest (image@sha256:<64 lowercase hex>); mutable tags are refused"
fi
if [[ -n "${GHCR_IMAGE}" ]]; then
  docker pull "${GHCR_IMAGE}" >/dev/null || fail "could not pull pinned DFIR image ${GHCR_IMAGE}"
  log "pulled published image ${GHCR_IMAGE}"
  docker tag "${GHCR_IMAGE}" "${IMAGE}"
elif docker image inspect "${IMAGE}" >/dev/null 2>&1; then
  log "image ${IMAGE} present"
elif [[ "${ALLOW_LOCAL_BUILD}" == "1" ]]; then
  log "no local image — explicitly approved local build of ${IMAGE} from the reviewed Dockerfile..."
  EMPTY_BUILD_CONTEXT="${REPO_ROOT}/.project-local/tmp/dfir-empty-context"
  ensure_repo_dir "${EMPTY_BUILD_CONTEXT}"
  docker build "${CLEAR_PROXY_BUILD_ARGS[@]}" \
    -f "${DOCKERFILE}" -t "${IMAGE}" "${EMPTY_BUILD_CONTEXT}"
else
  fail "no reviewed local DFIR image is present. Choose one explicit trust path:
  FINDEVIL_DFIR_GHCR=ghcr.io/owner/image@sha256:<digest> $0 ${EVIDENCE}
  FINDEVIL_DFIR_ALLOW_LOCAL_BUILD=1 $0 ${EVIDENCE}
The local Dockerfile build is opt-in until every non-APT payload is independently content-authenticated."
fi

# A tag is a mutable local pointer. Resolve it once and use only the immutable
# image content ID for preflight, dependency fetch/offline compile, and the
# evidence runtime. A concurrent rebuild/retag can then only make a later start
# fail; it cannot swap in code that skipped this case's parser preflight.
IMAGE_ID="$(docker_bounded image inspect --format '{{.Id}}' "${IMAGE}")" \
  || fail "could not resolve immutable image identity for ${IMAGE}"
[[ "${IMAGE_ID}" =~ ^sha256:[0-9a-f]{64}$ ]] \
  || fail "Docker returned an invalid image identity for ${IMAGE}: ${IMAGE_ID@Q}"
log "pinned image identity ${IMAGE_ID}"

# 2. Prove invocability before any host path is attached. Parser archives are
# third-party inputs, so repeatedly executing them from HEALTHCHECK after the
# parser/evidence mounts are present would turn a readiness check into
# unnecessary host-impacting code execution. This
# disposable preflight has no network, mounts, writable root, or capabilities;
# every probe and the overall container run are bounded by hard timeouts.
for timeout_value in \
  "${PROBE_TIMEOUT_SECONDS}" \
  "${PREFLIGHT_TIMEOUT_SECONDS}" \
  "${HEALTH_TIMEOUT_SECONDS}" \
  "${DOCKER_TIMEOUT_SECONDS}"; do
  case "${timeout_value}" in
    ''|*[!0-9]*) fail "DFIR container timeout values must be positive integers" ;;
  esac
  (( 10#${timeout_value} >= 1 && 10#${timeout_value} <= 600 )) || \
    fail "DFIR container timeout values must be between 1 and 600 seconds"
done
PROBE_TIMEOUT_SECONDS="$((10#${PROBE_TIMEOUT_SECONDS}))"
PREFLIGHT_TIMEOUT_SECONDS="$((10#${PREFLIGHT_TIMEOUT_SECONDS}))"
HEALTH_TIMEOUT_SECONDS="$((10#${HEALTH_TIMEOUT_SECONDS}))"
DOCKER_TIMEOUT_SECONDS="$((10#${DOCKER_TIMEOUT_SECONDS}))"
[[ -r "${PREFLIGHT_SCRIPT}" ]] || fail "missing preflight script: ${PREFLIGHT_SCRIPT}"
[[ -r "${MOUNT_SPEC_HELPER}" ]] || fail "missing Docker mount encoder: ${MOUNT_SPEC_HELPER}"
[[ -r "${BOUNDED_COPY_HELPER}" ]] || fail "missing bounded build artifact copier: ${BOUNDED_COPY_HELPER}"

log "isolated toolchain preflight (no network/host mounts/capabilities; read-only root):"
PREFLIGHT_CTR="${CTR:0:96}-preflight-$$"
preflight_ok=0
if "${TIMEOUT_BIN}" --foreground --kill-after=5s "${PREFLIGHT_TIMEOUT_SECONDS}s" \
  docker run --rm -i --name "${PREFLIGHT_CTR}" \
    --pull never \
    --network none \
    --no-healthcheck \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --user analyst \
    --memory "${PREFLIGHT_MEMORY_LIMIT}" --memory-swap "${PREFLIGHT_MEMORY_LIMIT}" \
    --cpus "${PREFLIGHT_CPU_LIMIT}" \
    --pids-limit 256 \
    --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m \
    "${CLEAR_PROXY_ENV_ARGS[@]}" \
    --env HOME=/tmp/home \
    --env DOTNET_CLI_HOME=/tmp/dotnet \
    --env "FINDEVIL_DFIR_PROBE_TIMEOUT=${PROBE_TIMEOUT_SECONDS}" \
    --entrypoint /bin/bash \
    "${IMAGE_ID}" -s < "${PREFLIGHT_SCRIPT}"; then
  preflight_ok=1
fi
# An outer timeout can sever the Docker client before --rm completes.
docker_bounded rm -f "${PREFLIGHT_CTR}" >/dev/null 2>&1 || true
if [[ "${preflight_ok}" != "1" ]]; then
  if [[ "${ALLOW_MISSING}" == "1" ]]; then
    log "WARNING: isolated toolchain preflight failed; continuing because FINDEVIL_DFIR_ALLOW_MISSING=1"
  else
    fail "DFIR image failed its isolated toolchain preflight. The image is broken
  or a required tool exceeded its timeout — do not attach evidence to it.
  Rebuild with:
    docker build -f docker/dfir.Dockerfile -t ${IMAGE} ${REPO_ROOT}
  Override only for a deliberately partial image: FINDEVIL_DFIR_ALLOW_MISSING=1"
  fi
fi

# 3. Compile the Rust parser with no evidence mount or elevated capability.
# The builder gets a temporary network only for `cargo fetch`, which cannot run
# dependency build scripts. Docker then detaches every network and proves that
# state before `cargo build --frozen --offline` can execute any build.rs code.
# The builder can see only the reviewed Rust source/manifests below; it cannot
# read `.env`, `.git`, Python custody code/venv, unrelated tmp output, or any
# evidence. Source mounts are read-only. HOME, Cargo registry, and target state
# live in a hard-sized fresh tmpfs. Logs and the final single binary cross back
# only through hard-bounded streams into a fresh case-scoped output directory.
BUILD_CTR="${CTR:0:100}-build-$$"
BUILD_OUTPUT_DIR="${REPO_ROOT}/.project-local/tmp/dfir-build-output/${CASE_ID}"
if [[ -e "${BUILD_OUTPUT_DIR}" || -L "${BUILD_OUTPUT_DIR}" ]]; then
  fail "refusing to reuse Docker build output for case ${CASE_ID}: ${BUILD_OUTPUT_DIR}"
fi
ensure_repo_dir "${BUILD_OUTPUT_DIR}"
printf '%s\n' "${CASE_ID}" > "${BUILD_OUTPUT_DIR}/.verdict-build-marker"
BUILD_BINARY_TMP="${BUILD_OUTPUT_DIR}/findevil-mcp.tmp"
RUST_MCP_BINARY="${BUILD_OUTPUT_DIR}/findevil-mcp"
BUILD_FETCH_LOG="${BUILD_OUTPUT_DIR}/cargo-fetch.log"
BUILD_COMPILE_LOG="${BUILD_OUTPUT_DIR}/cargo-build.log"
for build_file in Cargo.toml Cargo.lock rust-toolchain.toml; do
  require_repo_file "${REPO_ROOT}/${build_file}"
done
for build_dir in services/mcp; do
  require_repo_dir "${REPO_ROOT}/${build_dir}"
done
BUILD_MOUNTS=(
  --mount "$(docker_mount_spec type=bind "src=${REPO_ROOT}/Cargo.toml" dst=/workspace/Cargo.toml readonly)"
  --mount "$(docker_mount_spec type=bind "src=${REPO_ROOT}/Cargo.lock" dst=/workspace/Cargo.lock readonly)"
  --mount "$(docker_mount_spec type=bind "src=${REPO_ROOT}/rust-toolchain.toml" dst=/workspace/rust-toolchain.toml readonly)"
  --mount "$(docker_mount_spec type=bind "src=${REPO_ROOT}/services/mcp" dst=/workspace/services/mcp readonly bind-recursive=readonly bind-propagation=rprivate)"
)
BUILD_CTR_ACTIVE="0"
remove_builder() {
  [[ "${BUILD_CTR_ACTIVE}" == "1" ]] || return 0
  if docker_bounded rm -f "${BUILD_CTR}" >/dev/null 2>&1; then
    BUILD_CTR_ACTIVE="0"
    return 0
  fi
  return 1
}

cleanup_builder_on_exit() {
  remove_builder || true
}

builder_fail() {
  remove_builder || true
  rm -f -- "${BUILD_BINARY_TMP}"
  fail "$*"
}

run_bounded_builder_phase() {
  local timeout_seconds="$1" log_path="$2"
  shift 2
  "${TIMEOUT_BIN}" --foreground --kill-after=5s "${timeout_seconds}s" \
    docker exec "${BUILD_CTR}" "$@" 2>&1 \
    | python3 "${BOUNDED_COPY_HELPER}" "${log_path}" "${BUILD_LOG_MAX_BYTES}"
}

# Docker exec can outlive a killed client. Keep a process-level cleanup guard
# active from immediately before container creation through confirmed removal;
# INT/TERM translate into an exit so the EXIT trap always gets the final retry.
trap cleanup_builder_on_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
BUILD_CTR_ACTIVE="1"

log "fetching locked MCP dependencies before evidence attachment (unprivileged builder)"
if ! docker_bounded run -d --name "${BUILD_CTR}" \
    --pull never \
    --network bridge \
    --no-healthcheck \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --user analyst \
    --memory "${BUILD_MEMORY_LIMIT}" --memory-swap "${BUILD_MEMORY_LIMIT}" \
    --cpus "${BUILD_CPU_LIMIT}" \
    --pids-limit "${BUILD_PIDS_LIMIT}" \
    --tmpfs /tmp:rw,nosuid,nodev,size=1g \
    --tmpfs "/verdict-build:rw,nosuid,nodev,exec,size=${BUILD_TMPFS_LIMIT},mode=1777" \
    "${CLEAR_PROXY_ENV_ARGS[@]}" \
    --env HOME=/verdict-build/home \
    --env CARGO_HOME=/verdict-build/cargo \
    --env CARGO_TARGET_DIR=/verdict-build/target \
    --env RUSTUP_NO_UPDATE_CHECK=1 \
    --env PYTHONDONTWRITEBYTECODE=1 \
    "${BUILD_MOUNTS[@]}" \
    -w /workspace \
    "${IMAGE_ID}" \
    /usr/bin/env -u BASH_ENV -u ENV \
      PATH=/opt/rust/toolchain/bin:/usr/local/bin:/usr/bin:/bin \
      /bin/bash --noprofile --norc -c \
      'mkdir -p "$HOME" "$CARGO_HOME" "$CARGO_TARGET_DIR" && exec sleep infinity' \
    >/dev/null; then
  builder_fail "could not start the isolated Rust dependency builder"
fi

if ! run_bounded_builder_phase "${BUILD_FETCH_TIMEOUT_SECONDS}" "${BUILD_FETCH_LOG}" \
  /usr/bin/env -u BASH_ENV -u ENV \
    PATH=/opt/rust/toolchain/bin:/usr/local/bin:/usr/bin:/bin \
    /bin/bash --noprofile --norc -c \
    '/opt/rust/toolchain/bin/cargo fetch --locked && printf "%s\n" "locked dependency fetch complete"'; then
  builder_fail "locked Rust dependency fetch failed or exceeded its time/resource/log ceiling"
fi

# `cargo fetch` does not execute build.rs. From this point onward, no code from
# a dependency is allowed to retain Docker, LAN, metadata-service, or Internet
# reachability. Treat a failed detach or an ambiguous inspect result as fatal.
docker_bounded network disconnect bridge "${BUILD_CTR}" \
  || builder_fail "could not disconnect the Rust builder network before compilation"
BUILD_NETWORK_COUNT="$(
  docker_bounded inspect --format "{{len .NetworkSettings.Networks}}" "${BUILD_CTR}"
)" || builder_fail "could not prove the Rust builder network was disconnected"
[[ "${BUILD_NETWORK_COUNT}" == "0" ]] \
  || builder_fail "Rust builder still has ${BUILD_NETWORK_COUNT@Q} Docker network(s); refusing to execute dependency build scripts"

log "compiling MCP server offline before evidence attachment (unprivileged builder)"
if ! run_bounded_builder_phase "${BUILD_TIMEOUT_SECONDS}" "${BUILD_COMPILE_LOG}" \
  /usr/bin/env -u BASH_ENV -u ENV \
    PATH=/opt/rust/toolchain/bin:/usr/local/bin:/usr/bin:/bin \
    CARGO_NET_OFFLINE=true \
    /bin/bash --noprofile --norc -c \
    '/opt/rust/toolchain/bin/cargo build --release -p findevil-mcp --frozen --offline && printf "%s\n" "offline compilation complete"'; then
  builder_fail "offline Rust MCP build failed or exceeded its time/resource/log ceiling"
fi

if ! "${TIMEOUT_BIN}" --foreground --kill-after=5s "${DOCKER_TIMEOUT_SECONDS}s" \
  docker exec "${BUILD_CTR}" \
    /usr/bin/env -u BASH_ENV -u ENV \
      PATH=/opt/rust/toolchain/bin:/usr/local/bin:/usr/bin:/bin \
      FINDEVIL_BUILD_BINARY_MAX_BYTES="${BUILD_BINARY_MAX_BYTES}" \
      /bin/bash --noprofile --norc -c \
      'binary="$CARGO_TARGET_DIR/release/findevil-mcp" &&
       test -f "$binary" &&
       size="$(stat -c %s -- "$binary")" &&
       test "$size" -ge 1048576 &&
       test "$size" -le "$FINDEVIL_BUILD_BINARY_MAX_BYTES" &&
       exec /bin/cat -- "$binary"' \
  | python3 "${BOUNDED_COPY_HELPER}" "${BUILD_BINARY_TMP}" "${BUILD_BINARY_MAX_BYTES}"; then
  builder_fail "Rust MCP artifact export failed or exceeded its time/output ceiling"
fi
remove_builder \
  || builder_fail "could not remove the offline Rust builder after artifact export"
trap - EXIT HUP INT TERM
rm -f -- "${BUILD_FETCH_LOG}" "${BUILD_COMPILE_LOG}"
chmod 0555 -- "${BUILD_BINARY_TMP}"
mv -- "${BUILD_BINARY_TMP}" "${RUST_MCP_BINARY}"

# 4. (Re)start the container. Evidence is mounted read-only when supplied.
#
# The image ships `/evidence` as an empty *directory*. Docker cannot bind-mount
# a host *file* onto a directory path (`not a directory`), so a single evidence
# file is mounted at `/evidence/<basename>` and the in-container path is written
# for `scripts/verdict` to hand the engine. Direct compressed EWF input is
# refused before this point; use local/SIFT or export it to raw first. A
# directory argument still mounts only that selected directory at `/evidence`.
CASE_ROOT="${REPO_ROOT}/tmp/auto-runs"
CASE_DIR="${CASE_ROOT}/${CASE_ID}"
RUNTIME_STATE_DIR="${REPO_ROOT}/.project-local/tmp/dfir-runtime/${CASE_ID}"
require_repo_dir "${CASE_ROOT}"
require_repo_dir "${CASE_DIR}"
require_repo_file "${CASE_DIR}/.verdict-case-marker"
if [[ -e "${RUNTIME_STATE_DIR}" || -L "${RUNTIME_STATE_DIR}" ]]; then
  fail "refusing to reuse Docker parser state for case ${CASE_ID}: ${RUNTIME_STATE_DIR}"
fi
ensure_repo_dir "${RUNTIME_STATE_DIR}"
printf '%s\n' "${CASE_ID}" > "${RUNTIME_STATE_DIR}/.verdict-runtime-marker"
require_repo_file "${RUST_MCP_BINARY}"
require_repo_file "${REPO_ROOT}/assets/yara/disk-triage.yar"
CONTAINER_CASE_DIR="/workspace/tmp/auto-runs/${CASE_ID}"
RUNTIME_MOUNTS=(
  --mount "$(docker_mount_spec type=bind "src=${RUST_MCP_BINARY}" dst=/workspace/target/release/findevil-mcp readonly)"
  --mount "$(docker_mount_spec type=bind "src=${REPO_ROOT}/assets/yara/disk-triage.yar" dst=/workspace/assets/yara/disk-triage.yar readonly)"
)
IN_CONTAINER_EVIDENCE=""
mkdir -p "${REPO_ROOT}/.project-local/tmp"
if [[ -n "${EVIDENCE}" ]]; then
  [[ "$(evidence_root_identity "${EVIDENCE_ABS}")" == "${EVIDENCE_ROOT_IDENTITY}" ]] \
    || fail "evidence root changed during isolated build; refusing to attach it"
  validate_evidence_scope "${EVIDENCE_ABS}"
  if [[ -d "${EVIDENCE_ABS}" ]]; then
    RUNTIME_MOUNTS+=(--mount "$(docker_mount_spec type=bind "src=${EVIDENCE_ABS}" dst=/evidence readonly bind-recursive=readonly bind-propagation=rprivate)")
    IN_CONTAINER_EVIDENCE="/evidence"
    log "evidence directory mounted read-only: ${EVIDENCE_ABS} -> /evidence"
  elif [[ -f "${EVIDENCE_ABS}" ]]; then
    base="$(basename "${EVIDENCE_ABS}")"
    # File onto /evidence/<basename> (parent dir already exists in the image).
    RUNTIME_MOUNTS+=(--mount "$(docker_mount_spec type=bind "src=${EVIDENCE_ABS}" "dst=/evidence/${base}" readonly)")
    IN_CONTAINER_EVIDENCE="/evidence/${base}"
    log "evidence file mounted read-only: ${EVIDENCE_ABS} -> ${IN_CONTAINER_EVIDENCE}"
  else
    fail "evidence path is neither a file nor a directory: ${EVIDENCE_ABS}"
  fi
fi
EVIDENCE_PATH_FILE="${RUNTIME_STATE_DIR}/evidence-path"
if [[ -n "${IN_CONTAINER_EVIDENCE}" ]]; then
  evidence_path_tmp="${EVIDENCE_PATH_FILE}.tmp-$$"
  printf '%s\n' "${IN_CONTAINER_EVIDENCE}" > "${evidence_path_tmp}"
  mv -- "${evidence_path_tmp}" "${EVIDENCE_PATH_FILE}"
fi
if docker ps -a --format '{{.Names}}' | grep -qx "${CTR}"; then
  log "recreating existing container ${CTR}"
  docker rm -f "${CTR}" >/dev/null
fi
# Evidence parsing is permanently capability-free. Raw images retain the
# unprivileged direct Sleuth Kit fallback; compressed EWF is rejected above.
RUNTIME_SECURITY_ARGS=(--cap-drop ALL --security-opt no-new-privileges:true)
log "starting ${CTR} capability-free"
docker run -d --name "${CTR}" \
  --pull never \
  --network none \
  --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=512m \
  --tmpfs "${CONTAINER_CASE_DIR}:rw,nosuid,nodev,size=${PARSER_STATE_TMPFS_LIMIT},mode=1777" \
  --tmpfs "/verdict-runtime:rw,nosuid,nodev,size=${RUST_STATE_TMPFS_LIMIT},mode=1777" \
  --memory "${MEMORY_LIMIT}" --memory-swap "${MEMORY_LIMIT}" \
  --cpus "${CPU_LIMIT}" \
  --pids-limit "${PIDS_LIMIT}" \
  "${CLEAR_PROXY_ENV_ARGS[@]}" \
  --env HOME=/verdict-runtime/home \
  --env TMPDIR=/verdict-runtime/tmp \
  --env XDG_CACHE_HOME=/verdict-runtime/xdg-cache \
  --env UV_CACHE_DIR=/verdict-runtime/xdg-cache/uv \
  --env FINDEVIL_HOME=/verdict-runtime/findevil \
  --env PYTHONDONTWRITEBYTECODE=1 \
  "${RUNTIME_SECURITY_ARGS[@]}" \
  --health-cmd '/usr/bin/sha256sum --check --status /opt/verdict/dfir-toolchain.sha256' \
  --health-interval 30s --health-timeout 15s --health-retries 3 \
  "${RUNTIME_MOUNTS[@]}" \
  "${IMAGE_ID}" /bin/bash --noprofile --norc -c \
    'mkdir -p "$HOME" "$TMPDIR" "$XDG_CACHE_HOME" "$FINDEVIL_HOME" && exec sleep infinity' \
  >/dev/null

# 4. Require Docker's terminal healthy state. "starting" is not readiness and
# an image without HEALTHCHECK is not the recommended backend contract.
wait_for_healthy() {
  local deadline health running state
  deadline=$((SECONDS + HEALTH_TIMEOUT_SECONDS))
  while (( SECONDS < deadline )); do
    if ! state="$(docker_bounded inspect --format '{{.State.Running}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "${CTR}" 2>/dev/null)"; then
      log "container disappeared before readiness"
      return 1
    fi
    running="${state%%|*}"
    health="${state#*|}"
    if [[ "${running}" != "true" ]]; then
      log "container stopped before readiness"
      return 1
    fi
    case "${health}" in
      healthy) return 0 ;;
      starting) sleep 1 ;;
      none|unhealthy)
        log "HEALTHCHECK reached '${health}' before readiness"
        return 1
        ;;
      *)
        log "HEALTHCHECK returned unexpected state '${health}'"
        return 1
        ;;
    esac
  done
  log "HEALTHCHECK remained 'starting' for ${HEALTH_TIMEOUT_SECONDS}s"
  return 1
}

if ! wait_for_healthy; then
  health="$(docker_bounded inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "${CTR}" 2>/dev/null || echo none)"
  if [[ "${ALLOW_MISSING}" == "1" ]]; then
    log "WARNING: HEALTHCHECK '${health}'; continuing because FINDEVIL_DFIR_ALLOW_MISSING=1"
  else
    health_detail="$(docker_bounded inspect --format '{{json .State.Health}}' "${CTR}" 2>/dev/null || echo unavailable)"
    if docker_bounded rm -f "${CTR}" >/dev/null 2>&1; then
      cleanup_result="failed container removed; evidence detached"
    else
      cleanup_result="automatic removal failed or timed out; run: scripts/run-dfir-container.sh --down"
    fi
    fail "DFIR container did not reach 'healthy' — refusing to declare it ready
  Last health record: ${health_detail}
  Cleanup: ${cleanup_result}"
  fi
fi

# 5. The offline runtime is ready; all parser build work completed before the
# evidence mount and long-lived parser container existed.
log "ready. Activate the backend: cp .mcp.json.docker .mcp.json  (or run: scripts/verdict --docker <evidence>)"
