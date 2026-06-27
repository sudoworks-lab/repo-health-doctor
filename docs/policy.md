# Policy

`repo-health-doctor` reads `repo-health-doctor.yml` from the repository root as
the shared policy file. `.repo-health-doctor.local.yml` is a local override and
must stay untracked.

Supported commands:

- `repo-health-doctor validate-policy .`
- `repo-health-doctor list-allows .`
- `repo-health-doctor list-allows . --format json`
- `repo-health-doctor list-allows . --fail-on expiring-soon`

## Validate Policy

`validate-policy` checks policy structure without scanning repository content.
It validates top-level keys, `ignore_paths`, `allow_findings`, expiration,
known `rule_id` values, and secret-allow restrictions. Invalid policy returns a
normal redacted report with `overall_status: block`.

## List Allows

`list-allows` returns a redacted inventory of current allow entries. It reports
safe fields such as source, policy id, rule id, scope category, expiration, and
status. It does not echo raw path patterns, reasons, owners, or secret values.

Status values:

- `active`
- `expiring-soon`
- `expired`

## Usage Guidance

- Keep shared exceptions in `repo-health-doctor.yml`
- Keep personal overrides in `.repo-health-doctor.local.yml`
- Re-run `validate-policy` and `--public-safety` after editing policy
- Prefer fixing repository content before adding an allow
- Scope allows narrowly and keep expiration dates short

See [../schemas/policy-config.schema.json](../schemas/policy-config.schema.json)
for the machine-readable policy contract.
