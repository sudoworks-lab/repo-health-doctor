#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JSON_OUT="/tmp/repo-health-doctor-release-check.json"
MARKDOWN_OUT="/tmp/repo-health-doctor-release-check.md"

cd "$ROOT_DIR"

PYTHONPATH=src python3 -m repo_health_doctor . --fail-on block --public-safety
PYTHONPATH=src python3 -m repo_health_doctor validate-policy .
PYTHONPATH=src python3 -m repo_health_doctor release-check . --format json --output "$JSON_OUT"
python3 -m json.tool "$JSON_OUT" >/dev/null
PYTHONPATH=src python3 -m repo_health_doctor release-check . --format markdown --output "$MARKDOWN_OUT"
test -s "$MARKDOWN_OUT"
