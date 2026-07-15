#!/usr/bin/env bash
# Run Goal Loop initialization once, then commit through the host-side helper.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if command -v python3 >/dev/null 2>&1 && python3 -c 'import sys; raise SystemExit(sys.version_info.major != 3)' >/dev/null 2>&1; then
  PYTHON=python3
elif command -v python >/dev/null 2>&1 && python -c 'import sys; raise SystemExit(sys.version_info.major != 3)' >/dev/null 2>&1; then
  PYTHON=python
else
  echo "error: Python 3 is required; kickoff was not started." >&2
  exit 69
fi

exec "$PYTHON" "$SCRIPT_DIR/host_commit.py" kickoff "$@"
