#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

command -v python3 >/dev/null
python3 --version

PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m repo_health_doctor --help >/dev/null
PYTHONPATH=src python3 -m repo_health_doctor --version
PYTHONPATH=src python3 -m repo_health_doctor . --fail-on block --public-safety
PYTHONPATH=src python3 -m repo_health_doctor validate-policy .

report_path="$(mktemp "${TMPDIR:-/tmp}/repo-health-doctor-init.XXXXXX.json")"
trap 'rm -f "$report_path"' EXIT
PYTHONPATH=src python3 -m repo_health_doctor . --public-safety --format json --output "$report_path"
python3 -m json.tool "$report_path" >/dev/null
