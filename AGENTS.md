# AGENTS

`repo-health-doctor` is a local-first preflight CLI for maintainers reviewing repository changes.

## Core Contract

- Do not add network calls.
- Do not print raw secrets, tokens, private paths, local IPs, or policy raw values.
- Do not weaken redaction in text output, JSON output, tests, fixtures, or docs.
- Do not change `schema_version`, CLI behavior, or existing `rule_id` values without explicit maintainer instruction.
- Do not add release, publish, or other external actions without human approval.
- Do not commit generated reports, local artifacts, caches, or `.repo-health-doctor.local.yml`.

## When Editing Rules Or Safety Logic

- Inspect `tests/fixtures/` before adding new fixtures.
- Reuse existing fixtures when they can trigger the same detection scenario.
- Update tests, fixtures, and docs together when adding or changing a rule.
- Re-check golden outputs when public-safety or redaction behavior changes.
- Keep policy examples and reports redacted.

## Required Verification

Run these before completion unless the maintainer changes the verify contract:

```bash
git status --short
find docs -maxdepth 2 -type f | sort
find tests/fixtures -maxdepth 3 -type f | sort
wc -l AGENTS.md
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m repo_health_doctor --help
PYTHONPATH=src python3 -m repo_health_doctor --version
PYTHONPATH=src python3 -m repo_health_doctor . --fail-on block --public-safety
PYTHONPATH=src python3 -m repo_health_doctor validate-policy .
PYTHONPATH=src python3 -m repo_health_doctor . --public-safety --format json --output /tmp/repo-health-doctor-result.json
python3 -m json.tool /tmp/repo-health-doctor-result.json >/dev/null
```

## Pointers

- Agent workflow details: [docs/agent-guide.md](docs/agent-guide.md)
- Maintainer workflow: [docs/maintainer-guide.md](docs/maintainer-guide.md)
- Safety boundary: [docs/security-model.md](docs/security-model.md)
- Evaluation model: [docs/evaluation-model.md](docs/evaluation-model.md)
