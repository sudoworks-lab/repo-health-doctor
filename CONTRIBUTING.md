# Contributing

`repo-health-doctor` is a small local-first CLI. Keep changes reviewable, redacted, and fixture-backed.

## Setup

- Run the repo directly with `PYTHONPATH=src`.
- Use editable install only when packaging verify is part of the task.
- Keep local-only overrides in `.repo-health-doctor.local.yml`.

## Test

- `PYTHONPATH=src python3 -m unittest discover -s tests -v`
- `PYTHONPATH=src python3 -m repo_health_doctor . --fail-on block --public-safety`
- `PYTHONPATH=src python3 -m repo_health_doctor validate-policy .`

Detailed verification lives in [AGENTS.md](AGENTS.md) and [docs/release-checklist.md](docs/release-checklist.md).

## Rule Changes

- Inspect `tests/fixtures/` first and extend existing fixtures when they can trigger the same scenario.
- Update tests and docs in the same change.
- Keep `schema_version`, stable `rule_id`, and redaction behavior intact unless the maintainer explicitly asks for a contract change.

See [docs/rules.md](docs/rules.md) and [docs/evaluation-model.md](docs/evaluation-model.md).

## False Positive Reports

- Prefer narrowing the repo content before adding policy exceptions.
- If an allow is required, scope it to the smallest path and single `rule_id`.
- Include why the finding is expected and when the allow should expire.

See [docs/policy.md](docs/policy.md) and [docs/maintainer-guide.md](docs/maintainer-guide.md).

## Security Reports

Do not post suspected secrets or vulnerability details in public issues. Follow [SECURITY.md](SECURITY.md).

## Scope

- Repository health checks
- Public-safety checks
- Policy validation
- Redacted text and JSON reporting

## Non-Goals

- Full secret scanning
- Dependency vulnerability auditing
- GitHub settings management
- Release workflow or publishing automation in this repo
