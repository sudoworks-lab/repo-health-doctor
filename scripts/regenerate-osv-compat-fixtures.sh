#!/usr/bin/env bash
set -euo pipefail

IMAGE="${RHD_OSV_SCANNER_IMAGE:-ghcr.io/google/osv-scanner:2.0.3}"
TARGET_REPO=""
RUN_SCAN=0
NETWORK_MODE="none"

usage() {
  cat <<'USAGE'
Regenerate OSV-Scanner compatibility output for safe synthetic fixtures only.

This helper does not install scanners on the host, does not run a host scanner,
does not scan unknown repositories, does not mount host HOME, does not mount
the Docker socket, and does not commit raw scanner output.

Usage:
  bash scripts/regenerate-osv-compat-fixtures.sh
  bash scripts/regenerate-osv-compat-fixtures.sh --run --synthetic-repo examples/demo-synthetic-supply-chain
  bash scripts/regenerate-osv-compat-fixtures.sh --run --allow-network-for-osv-db --synthetic-repo examples/demo-synthetic-supply-chain

The Docker image must be acquired separately if policy permits it. This helper
uses --pull=never and writes raw scanner output only to a temporary directory.
Network access is disabled unless explicitly allowed for OSV database lookup on
safe synthetic fixtures. Review, redact, and normalize manually before updating
committed fixtures.
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --run) RUN_SCAN=1 ;;
    --allow-network-for-osv-db) NETWORK_MODE="bridge" ;;
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

OUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/rhd-osv-compat.XXXXXX")"
OUT_FILE="${OUT_DIR}/osv-scanner.raw.json"

set +e
docker run --rm --pull=never --network "$NETWORK_MODE" \
  --mount "type=bind,src=$(pwd)/${TARGET_REPO},dst=/repo,readonly" \
  "$IMAGE" --format json /repo > "$OUT_FILE"
STATUS=$?
set -e

printf 'OSV-Scanner exited with status %s. Raw output path: %s\n' "$STATUS" "$OUT_FILE"
printf '%s\n' 'Do not commit raw output. Commit only reviewed redacted normalized fixtures.'
exit "$STATUS"
