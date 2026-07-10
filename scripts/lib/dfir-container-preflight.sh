#!/usr/bin/env bash
# Execute the recommended DFIR image's required tools before any host path is
# mounted. run-dfir-container.sh pipes this file into a disposable, read-only,
# networkless container with every Linux capability dropped.
set -uo pipefail

PROBE_TIMEOUT_SECONDS="${FINDEVIL_DFIR_PROBE_TIMEOUT:-60}"
TIMEOUT_BIN="${FINDEVIL_TIMEOUT_BIN:-timeout}"
case "${PROBE_TIMEOUT_SECONDS}" in
  ''|*[!0-9]*)
    printf 'invalid FINDEVIL_DFIR_PROBE_TIMEOUT: %s\n' "${PROBE_TIMEOUT_SECONDS}" >&2
    exit 2
    ;;
esac
PROBE_TIMEOUT_SECONDS="$((10#${PROBE_TIMEOUT_SECONDS}))"
if (( PROBE_TIMEOUT_SECONDS < 1 || PROBE_TIMEOUT_SECONDS > 600 )); then
  printf 'FINDEVIL_DFIR_PROBE_TIMEOUT must be between 1 and 600 seconds\n' >&2
  exit 2
fi
if ! command -v "${TIMEOUT_BIN}" >/dev/null 2>&1 \
   || ! "${TIMEOUT_BIN}" --foreground --kill-after=1s 1s true >/dev/null 2>&1; then
  printf 'GNU coreutils timeout is required for bounded DFIR probes\n' >&2
  exit 2
fi

missing=0
probe() {
  local label="$1"
  local status
  shift
  if "${TIMEOUT_BIN}" --foreground --kill-after=5s "${PROBE_TIMEOUT_SECONDS}s" "$@" </dev/null >/dev/null 2>&1; then
    printf '  ok   %s\n' "${label}"
    return 0
  else
    status=$?
  fi
  if (( status == 124 || status == 137 )); then
    printf '  MISS %s (timed out after %ss)\n' "${label}" "${PROBE_TIMEOUT_SECONDS}"
  else
    printf '  MISS %s (exit %s)\n' "${label}" "${status}"
  fi
  missing=$((missing + 1))
  return 0
}

probe "tshark --version" tshark --version
probe "fls -V" fls -V
probe "icat -V" icat -V
probe "ewfexport -V" ewfexport -V
probe "ewfmount -V" ewfmount -V
probe "mmls -V" mmls -V
probe "vol -h" vol -h
probe "hayabusa help" hayabusa help
probe "log2timeline.py --version" log2timeline.py --version
probe "psort.py --version" psort.py --version
probe "/opt/eztools/LECmd --help" /opt/eztools/LECmd --help
probe "/opt/eztools/JLECmd --help" /opt/eztools/JLECmd --help
probe "/opt/eztools/AmcacheParser --help" /opt/eztools/AmcacheParser --help
probe "/opt/eztools/AppCompatCacheParser --help" /opt/eztools/AppCompatCacheParser --help
probe "/opt/eztools/RBCmd --help" /opt/eztools/RBCmd --help
probe "/opt/eztools/SBECmd --help" /opt/eztools/SBECmd --help
probe "/opt/eztools/WxTCmd --help" /opt/eztools/WxTCmd --help
probe "bulk_extractor -V" bulk_extractor -V
probe "chainsaw --version" chainsaw --version
probe "velociraptor version" velociraptor version
probe "pandoc --version" pandoc --version
probe "INDXParse.py -h" INDXParse.py -h
probe "esedbexport -h" esedbexport -h
probe "vshadowinfo -h" vshadowinfo -h
probe "suricata --build-info" suricata --build-info
probe "nfdump -V" nfdump -V
probe "ausearch --version" ausearch --version
probe "yara --version" yara --version
probe "sealed toolchain manifest" /usr/bin/sha256sum --check --status /opt/verdict/dfir-toolchain.sha256

if (( missing > 0 )); then
  exit 1
fi
