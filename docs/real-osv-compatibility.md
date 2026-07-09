# Real OSV-Scanner Compatibility

This note records the limited compatibility scope for redacted,
real-output-compatible OSV-Scanner fixtures.

## Real Scanner Adapter

The real adapter first runs:

```bash
osv-scanner --version
```

If the binary is missing, times out, or returns a non-zero status, the adapter
fails closed with an unknown result and does not run a scan. The adapter does
not install OSV-Scanner.

The scan command is built as an argv list, never through `shell=True`:

```bash
osv-scanner scan source --recursive --format json --output-file <tmp_report_path> <repo_path>
```

This uses the OSV-Scanner v2 `scan source` entrypoint with recursive directory
search so repository-scope evidence can include supported lockfiles,
manifests, SBOMs, and source extractors under subdirectories. The JSON report
is written to a temporary file, parsed, normalized, and discarded. Raw JSON,
stdout, stderr, advisory details, reference URLs, credits, and database raw
objects are not retained in normalized evidence.

Exit codes are interpreted as:

- `0`: scan completed with no known vulnerabilities in reached scope; report
  may be consumed.
- `1`: scan completed with vulnerabilities; report may be consumed.
- `2` through `126`: reserved result-related errors other than the documented
  vulnerability result; fail closed and do not consume the report.
- `127`: tool error; fail closed.
- `128`: no packages found; fail closed as incomplete scope evidence.
- `129` through `255`: non-result-related or unknown errors; fail closed.

Missing reports, timeouts, invalid JSON, top-level arrays, missing `results`,
malformed `source` / `packages` / vulnerability shapes, and exit-code/report
content mismatches fail closed. The supported report shape is a top-level JSON
object with a `results` array. Each result may include `source.path`,
`source.type`, and `packages`; each package may include package name, version,
ecosystem, vulnerabilities, and groups.

Normalized external-scanner results use scanner name `osv-scanner`, category
`vulnerability`, mode `local_static_network`, and source `external_binary`.
The adapter records `git rev-parse HEAD` as the target commit when available.
No-vulnerability results are accepted only when HEAD is known and the worktree
is clean. Dirty or unbound no-vulnerability results fail closed as scope
ambiguous evidence. Vulnerability results remain bounded evidence, not
execution authorization.

Normalized findings keep only the minimum package and vulnerability facts
needed for review: source type, redacted or relative source path, package name,
package version, package ecosystem, vulnerability id, alias count, group id
summary, severity summary, and fixed-version count. Absolute host paths are
redacted. Advisory details, long descriptions, full reference lists, credits,
and raw `database_specific` objects are omitted.

No vulnerabilities is not proof of safety. It means only that OSV-Scanner did
not report known vulnerabilities for the package ecosystems, lockfiles,
manifests, SBOMs, source extractors, and advisory database coverage reached by
that run. No packages found is not proof of safety and is handled as
fail-closed incomplete evidence.

OSV-Scanner live scans normally query the OSV.dev API and may send package
names, versions, ecosystems, lockfile or manifest metadata, and file hashes.
repo-health-doctor records that as `local_static_network`; it does not present
the default live scan as local-only. Offline mode is a future optional adapter
mode and is not implemented here. The official Docker image
`ghcr.io/google/osv-scanner` can be evaluated separately, but this adapter does
not implement a Docker runner.

The optional live adapter test is disabled by default even when `osv-scanner`
is installed. It requires `RHD_LIVE_OSV_TEST=1` so default unit test discovery
does not make a network-capable OSV.dev query by accident.

## Compatibility Matrix

- OSV-Scanner JSON: supported through redacted compatibility fixtures
- Severity mapping: supported for the documented sample inputs
- Raw output retention: not allowed
- Execution authorization: always false

Compatibility is limited to the documented fixture, version, and scope. It is
not a claim that repo-health-doctor replaces OSV-Scanner.
