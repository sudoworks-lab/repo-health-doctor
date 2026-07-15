#!/usr/bin/env bash
# Goal Loop launcher. Host-side stage/commit is enforced by the Python backend.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if command -v python3 >/dev/null 2>&1 && python3 -c 'import sys; raise SystemExit(sys.version_info.major != 3)' >/dev/null 2>&1; then
  PYTHON=python3
elif command -v python >/dev/null 2>&1 && python -c 'import sys; raise SystemExit(sys.version_info.major != 3)' >/dev/null 2>&1; then
  PYTHON=python
else
  echo "error: Python 3 is required; unsafe fallback execution is disabled." >&2
  exit 69
fi

if [[ -f "$SCRIPT_DIR/goal_loop_runner.py" ]]; then
  exec "$PYTHON" "$SCRIPT_DIR/goal_loop_runner.py" "$@"
fi
exec "$PYTHON" "$SCRIPT_DIR/host_commit.py" loop "$@"
