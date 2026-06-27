#!/usr/bin/env bash
set -euo pipefail

IMAGE="${RHD_GITLEAKS_IMAGE:-zricethezav/gitleaks:8.27.2}"
TARGET_REPO=""
RUN_SCAN=0

usage() {
  cat <<'USAGE'
Regenerate Gitleaks compatibility output for safe synthetic fixtures only.

This helper does not install scanners on the host, does not run a host scanner,
does not scan unknown repositories, does not mount host HOME, does not mount
the Docker socket, and does not commit raw scanner output.

Usage:
  bash scripts/regenerate-gitleaks-compat-fixtures.sh
  bash scripts/regenerate-gitleaks-compat-fixtures.sh --run --synthetic-repo examples/demo-synthetic-supply-chain

The Docker image must be acquired separately if policy permits it. This helper
uses --pull=never and writes raw scanner output only to a temporary directory.
Review, redact, and normalize manually before updating committed fixtures.
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --run) RUN_SCAN=1 ;;
    --synthetic-repo) TARGET_REPO="${2:-}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'Unexpected argument: %s\n' "$1" >&2; usage; exit 2 ;;
  esac
  shift
done

printf '%s\n' 'WARNING: safe synthetic fixtures only; raw scanner output may contain sensitive values and must not be committed.'

if [ "$RUN_SCAN" -ne 1 ]; then
  usage
  exit 0
fi

case "$TARGET_REPO" in
  ""|/*|*..*) printf '%s\n' 'Refusing target: provide a relative safe synthetic fixture path.' >&2; exit 2 ;;
  examples/*|tests/fixtures/*) ;;
  *) printf '%s\n' 'Refusing target: only examples/ or tests/fixtures/ paths are allowed.' >&2; exit 2 ;;
esac

if [ ! -d "$TARGET_REPO" ]; then
  printf 'Refusing target: %s is not a directory.\n' "$TARGET_REPO" >&2
  exit 2
fi

OUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/rhd-gitleaks-compat.XXXXXX")"
OUT_FILE="${OUT_DIR}/gitleaks.raw.json"

set +e
docker run --rm --network none --pull=never \
  --mount "type=bind,src=$(pwd)/${TARGET_REPO},dst=/repo,readonly" \
  --mount "type=bind,src=${OUT_DIR},dst=/out" \
  "$IMAGE" detect --source /repo --report-format json --report-path /out/gitleaks.raw.json
STATUS=$?
set -e

printf 'Gitleaks exited with status %s. Raw output path: %s\n' "$STATUS" "$OUT_FILE"
printf '%s\n' 'Do not commit raw output. Commit only reviewed redacted normalized fixtures.'
exit "$STATUS"
