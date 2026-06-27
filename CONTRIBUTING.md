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

For non-sensitive public review of the security model, use the security model
review issue template. It exists because third-party security review is not
done and focused external review is still needed.

## Feature Requests

Feature requests should preserve repo-health-doctor's role as a pre-execution
safety gate. Prefer evidence adapters, gate evaluator improvements, policy
validation, redaction hardening, or docs clarity over reimplementing dedicated
scanners.

Sandbox-run changes must keep the add-on optional and experimental. Do not add
automatic image pulls, Docker socket access, host credential mounts, or wording
that treats Docker execution as proof of safety.

## Scope

- Repository health checks
- Public-safety checks
- Policy validation
- Redacted text and JSON reporting
- Experimental sandbox-run evidence, approvals, and docs within the documented
  no-auto-pull Docker boundary

## Non-Goals

- Full secret scanning
- Dependency vulnerability auditing
- GitHub settings management
- Release workflow or publishing automation in this repo
- Making Docker or sandbox-run proof of safety for repository-derived code
