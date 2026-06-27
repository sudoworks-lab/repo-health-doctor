# Rules

`repo-health-doctor` reports stable `rule_id` and severity values. Findings are
redacted and do not include raw matched values.

## Status And Exit Behavior

- `pass`: no blocking finding in the current scope
- `warn`: review before relying on the result
- `block`: do not proceed until the finding is handled

Default exit behavior:

- `0` for `pass`
- `0` for `warn` when using `--fail-on block`
- `1` when any `block` finding exists
- `1` when `--fail-on warn` or `--strict` is used and any `warn` finding exists

## Finding Fields

Reports expose only safe fields:

- `rule_id`
- `severity`
- `file`
- `pattern`
- `line`
- `size_bytes`
- `redacted`

## Current Rule Families

- `rhd.secret.*`: secret-like value categories
- `rhd.public_text.*`: restricted public text, private paths, local IPs
- `rhd.repository.*`: missing metadata and large-file checks
- `rhd.tracked_artifact.*`: generated files, cache directories, env-file candidates
- `rhd.policy.*`: invalid policy structure, expiration, unknown keys, and restricted secret allows

`validate-policy` uses the same redacted report contract as the main public-
safety checks.

## Rule Table

| rule_id | purpose | severity |
| --- | --- | --- |
| `rhd.secret.aws_access_key` | Detect AWS access key shaped secret candidates | `block` |
| `rhd.secret.github_token` | Detect GitHub token shaped secret candidates | `block` |
| `rhd.secret.slack_token` | Detect Slack token shaped secret candidates | `block` |
| `rhd.secret.private_key` | Detect private key material candidates | `block` |
| `rhd.secret.generic_api_key` | Detect generic key, token, or secret candidates | `block` |
| `rhd.public_text.restricted_term` | Detect restricted public-facing text categories | `block` |
| `rhd.public_text.private_path` | Detect private-path categories | `block` |
| `rhd.public_text.local_ip` | Detect local-IP categories | `block` |
| `rhd.repository.missing_readme` | Report missing README metadata | `warn` |
| `rhd.repository.missing_license` | Report missing LICENSE metadata | `warn` |
| `rhd.repository.missing_ci` | Report missing CI workflow metadata | `warn` |
| `rhd.repository.missing_tests` | Report missing test metadata | `warn` |
| `rhd.repository.large_file` | Report unusually large tracked files | `warn` |
| `rhd.tracked_artifact.generated_dir` | Detect tracked generated directories | `block` |
| `rhd.tracked_artifact.cache_dir` | Detect tracked cache directories | `block` |
| `rhd.tracked_artifact.generated_file` | Detect tracked generated files | `block` |
| `rhd.tracked_artifact.env_file` | Detect tracked environment-file candidates | `block` |
| `rhd.policy.invalid_config` | Report unreadable or invalid policy config | `block` |
| `rhd.policy.invalid_ignore` | Report invalid `ignore_paths` entries | `block` |
| `rhd.policy.invalid_allow` | Report invalid `allow_findings` entries | `block` |
| `rhd.policy.expired_allow` | Report expired allow entries | `block` |
| `rhd.policy.unknown_rule_id` | Report allow entries that reference unknown rule ids | `block` |
| `rhd.policy.unknown_top_level_key` | Report unknown top-level policy keys | `block` |
| `rhd.policy.restricted_secret_allow` | Report disallowed secret-rule allow entries | `block` |
