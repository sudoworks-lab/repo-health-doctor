# Real Trivy Compatibility

This note records the limited compatibility scope for redacted,
real-output-compatible Trivy filesystem scan evidence.

## Real Scanner Adapter

The real adapter first runs:

```bash
trivy --version
```

If the binary is missing, times out, returns a non-zero status, or produces a
version that cannot be parsed, the adapter fails closed with an unknown result
and does not run a scan. The adapter does not install, download, or upgrade
Trivy.

The March 2026 Trivy ecosystem incident affects this trust boundary. The
adapter deny-lists known unsafe Trivy versions `0.69.4`, `0.69.5`, and
`0.69.6` for live execution. `0.69.4` was reported for malicious binary
distribution, and `0.69.5` / `0.69.6` were reported for DockerHub image tags.
Those versions are not used in docs examples.

The scan command is built as an argv list, never through `shell=True`:

```bash
trivy fs --scanners vuln,misconfig --format json --output <tmp_report_path> --exit-code 1 --cache-dir <tmp_cache_dir> <repo_path>
```

When the adapter runs the scanner, it also points Trivy cache state at a
temporary directory. The JSON report is written to a temporary file, parsed,
normalized, and discarded. Raw JSON, stdout, stderr, raw secret matches, code
snippets, long descriptions, reference URL lists, and vendor raw metadata are
not retained in normalized evidence.

The initial live command intentionally enables `vuln,misconfig`, not
`vuln,secret,misconfig`. Trivy secret scan JSON can include match text and code
context, which raises raw-secret retention risk. The parser can safely consume
`Secrets` from a supplied Trivy JSON object by keeping only rule/category,
severity, and location metadata, but default live execution avoids producing
secret-match payloads until a dedicated secret-output hardening pass exists.

Exit codes are interpreted as:

- `0`: scan completed with no findings in reached scope; report may be
  consumed.
- `1`: scan completed with findings because the adapter uses `--exit-code 1`;
  report may be consumed.
- `2` through `126`: tool error; fail closed and do not consume the report.
- `127`: tool unavailable; fail closed.
- `128` through `255`: unknown tool error; fail closed.

Missing reports, timeouts, invalid JSON, top-level arrays, missing `Results`,
malformed `Vulnerabilities` / `Misconfigurations` / `Secrets` / `Licenses`, and
exit-code/report content mismatches fail closed. The supported report shape is
a top-level JSON object with a `Results` array.

Normalized external-scanner results use scanner name `trivy`, category
`custom_static`, mode `local_static_network`, and source `external_binary`.
The adapter records `git rev-parse HEAD` as the target commit when available.
No-finding results are accepted only when HEAD is known and the worktree is
clean. Dirty or unbound no-finding results fail closed as scope ambiguous
evidence. Findings remain bounded evidence, not execution authorization.

Normalized findings keep only the minimum facts needed for review:

- target path redacted or relative
- result class and type
- scanner category summary
- vulnerability id, package name, installed version, fixed-version count, and
  severity
- misconfiguration id, type, severity, status, title presence, and line number
- secret rule id, category, severity, and location
- license name, package name, and severity when a caller-supplied report
  includes license results

Absolute host paths, private-looking paths, local IPs, URLs, token-like
strings, raw secret values, code snippets, match text, long vulnerability
descriptions, raw reference lists, and vendor raw metadata are omitted.

No findings is not proof of safety. It means only that this Trivy filesystem
scan did not report issues for the scanners, ecosystems, manifests, IaC files,
database versions, cache state, and repository paths reached by that run.
Secret and license coverage are not part of the default live command.

Trivy live scans can download or update vulnerability, Java, misconfiguration,
and check databases and can use cache state. repo-health-doctor records that
as `local_static_network`; it does not present the default live scan as
local-only. Offline mode and a Docker runner are future optional modes and are
not implemented here. Docker image scan, remote git scan, Kubernetes scan, and
cloud scan are also not implemented.

The official Trivy container images include `docker.io/aquasec/trivy`,
`ghcr.io/aquasecurity/trivy`, and `public.ecr.aws/aquasecurity/trivy`, but this
adapter does not run Docker and does not mount a Docker socket. Any future
manual Docker example must avoid affected mutable tags and prefer digest-pinned
images after separate human review.

The optional live adapter test is disabled by default even when `trivy` is
installed. It requires `RHD_LIVE_TRIVY_TEST=1` so default unit test discovery
does not download or update Trivy databases by accident.

## Redacted Compatibility Fixture

The committed compatibility contract records Trivy `0.69.3` in
`tests/fixtures/real-scanners/trivy/trivy-version.txt`. Its
`licenses-redacted.real.json` fixture contains only the minimum synthetic
license fields consumed by the adapter; raw scanner output and vendor detail
are not committed. `expected-evidence.json` records the bounded normalized
facts asserted by the compatibility test.

Run the offline consistency check with:

```bash
python3 scripts/regenerate_real_scanner_fixtures.py --scanner trivy --check
```

Raw-output collection, if separately approved, stays under `/tmp` until Human
review and redaction. The helper does not acquire or run Trivy. See
`docs/compatibility-regeneration.md` for the complete boundary.

## Tested Versions

| Scanner | Tested version | Version record | Expected evidence |
|---|---:|---|---|
| Trivy | `0.69.3` | `tests/fixtures/real-scanners/trivy/trivy-version.txt` | `tests/fixtures/real-scanners/trivy/expected-evidence.json` |

`tested`は上表のfixture exact versionだけを指す。同じmajor familyの別releaseは
compatibility記録上`compatible_family_unverified`であり、tested coverageを
拡張しない。documented family外は`unsupported`、`0.69.4`、`0.69.5`、
`0.69.6`は`denylisted`、安全にversionを読めない出力は`unparseable`である。
現行adapterが受理し得るparsed versionであっても、上表にないversionを
`tested`とは表現しない。

## Additional Compatibility Scenarios

- Licenses: `licenses-redacted.real.json`と`expected-evidence.json`が
  review-onlyのlicense findingを固定する。
- Exit/report mismatch: 既存の
  `tests/fixtures/real-compatibility/trivy/vulnerabilities.real.json`と
  `no-findings.real.json`を逆のexit outcomeに組み合わせ、parse failureへ
  正規化されることを確認する。専用の重複fixtureは追加しない。
- Version parse failure: fixture由来でない不正なversion出力をunit testで
  `unparseable`相当のfail-closed resultとして確認する。

## Regeneration

Human review済みのredacted license fixtureからbounded expected evidenceだけを
再生成または照合する。

```bash
python3 scripts/regenerate_real_scanner_fixtures.py --scanner trivy --write
python3 scripts/regenerate_real_scanner_fixtures.py --scanner trivy --check
```

このhelperはscannerを取得・実行せず、raw outputを読まない。raw-output collection
が別途承認された場合も`/tmp`内に限定し、committed fixtureへ移す前にHumanが
reviewとredactionを行う。

## Not Covered

- `0.69.3`以外のTrivy releaseやdatabase/cache combinationの互換性。
- Default live commandに含まれないsecret、license、image、remote git、
  Kubernetes、cloud scanの実行coverage。
- 全result class、schema、exit code、database versionの網羅。
- Scanner binaryまたはcontainer imageの取得元・署名・安全性の証明。
- Finding 0件を安全証明またはexecution authorizationとして扱うこと。

## Compatibility Matrix

- Trivy filesystem JSON: supported through redacted compatibility fixtures
- Default live scanners: vulnerability and misconfiguration only
- Secret JSON normalization: supported only by omitting raw values and snippets
- Raw output retention: not allowed
- Execution authorization: always false

Compatibility is limited to the documented fixture, version, and scope. It is
not a claim that repo-health-doctor replaces Trivy.
