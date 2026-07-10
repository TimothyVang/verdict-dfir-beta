#!/usr/bin/env bash
# Host-side custody/signing MCP for the Docker evidence backend. Native parsers
# remain in the container; verify_finding replays through a fixed docker-exec
# transport without exposing the host signing key to that container.
set -euo pipefail
umask 077

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${REPO_ROOT}/scripts/lib/project-env.sh"
: "${FINDEVIL_ACTIVE_CASE_DIR:?scripts/verdict must reserve FINDEVIL_ACTIVE_CASE_DIR}"
: "${FINDEVIL_ACTIVE_CASE_ID:?scripts/verdict must reserve FINDEVIL_ACTIVE_CASE_ID}"
: "${FINDEVIL_ACTIVE_RUN_ID:?scripts/verdict must reserve FINDEVIL_ACTIVE_RUN_ID}"
: "${FINDEVIL_ACTIVE_STARTED_AT:?scripts/verdict must reserve FINDEVIL_ACTIVE_STARTED_AT}"
: "${FINDEVIL_ACTIVE_SIGNER:?scripts/verdict must reserve FINDEVIL_ACTIVE_SIGNER}"
export FINDEVIL_CUSTODY_BOUNDARY=reserved_case
export FINDEVIL_REPLAY_TRANSPORT=docker
export FINDEVIL_REPLAY_DOCKER_CONTAINER="${FINDEVIL_REPLAY_DOCKER_CONTAINER:-${FINDEVIL_DFIR_CONTAINER:-findevil-dfir}}"

exec "${REPO_ROOT}/scripts/run-mcp-python.sh"
