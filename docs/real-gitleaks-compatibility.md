# Real Gitleaks Compatibility

This note records the limited compatibility scope for redacted,
real-output-compatible Gitleaks fixtures.

## Real Scanner Adapter

The real adapter first runs:

```bash
gitleaks version
```

If the binary is missing, times out, or returns a non-zero status, the adapter
fails closed with an unknown result and does not run a scan.

The scan command is built as an argv list, never through `shell=True`:

```bash
gitleaks git --report-format json --report-path <tmp_report_path> --redact --exit-code 2 --no-banner --log-level error <repo_path>
```

Exit codes are interpreted as:

- `0`: completed with no findings; report may be consumed.
- `2`: completed with findings; report may be consumed.
- `1`: tool or scan error; fail closed and do not consume the report.
- `126`: tool interface error; fail closed and do not consume the report.
- Other codes: unknown tool error; fail closed and do not consume the report.

Missing reports, timeouts, invalid JSON, top-level JSON objects, and malformed
top-level arrays fail closed. The supported Gitleaks report shape is a top-level
JSON array.

Normalized external-scanner results use scanner name `gitleaks`, category
`secret_detection`, mode `local_static_no_network`, and source
`external_binary`. The adapter records `git rev-parse HEAD` as the target commit
when available. Because the adapter uses `gitleaks git`, no-finding results are
only accepted when HEAD is known and the worktree is clean. Dirty or unbound
no-finding results fail closed as scope ambiguous evidence.

Raw Gitleaks JSON, stdout, and stderr are not retained. The normalized result
keeps only safe fields such as rule id, relative file path, line and column
ranges, commit, fingerprint, tag count, entropy, and non-sensitive presence
markers for omitted metadata. It does not persist `Secret`, `Match`,
`Description`, `Tags`, `Author`, `Email`, or `Message` values.

## Compatibility Matrix

- JSON required: supported through redacted compatibility fixtures
- SARIF: supported for the documented redacted sample
- Raw output retention: not allowed
- Execution authorization: always false

Compatibility is limited to the documented fixture, version, and scope. It is
not a claim that repo-health-doctor replaces Gitleaks. A no-finding result is
not proof of safety; it means only that the scanner reached scope did not
produce findings under the active rules and configuration.
