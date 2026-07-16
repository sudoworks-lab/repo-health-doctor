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

## Tested Versions

| Scanner | Tested version | Version record | Expected evidence |
|---|---:|---|---|
| Gitleaks | `8.27.2` | `tests/fixtures/real-compatibility/gitleaks/gitleaks-version.txt` | `tests/fixtures/real-compatibility/gitleaks/expected-evidence.json` |

`tested`は上表のfixture exact versionだけを指す。同じmajor versionの別releaseは
`compatible_family_unverified`であり、実行可能でもdegraded evidenceとして扱う。
major version 8以外は`unsupported`、明示的に拒否する`0.0.0`は`denylisted`、
安全にversionを読めない出力は`unparseable`である。これらのstatusは
compatibilityの確認状況であり、scannerやrepositoryの安全性を示さない。

## Additional Compatibility Scenarios

- Dirty worktree: `no-findings.real.json`を再利用し、`dirty_state=dirty`として
  normalizeするとscope ambiguousとしてfail closedになる。専用の重複fixtureは
  追加しない。
- SARIF: `optional-sarif-redacted.real.sarif`がredactedな追加formatを固定する。
- Version parse failure: fixture由来でない不正なversion出力をunit testで
  `unparseable`として確認し、raw version出力は保存しない。

## Regeneration

Humanが別途image取得と実行を承認したsafe synthetic repositoryだけを対象に、
まず次のdry runで境界を確認する。

```bash
bash scripts/regenerate-gitleaks-compat-fixtures.sh
```

実行を承認した場合の`--run --synthetic-repo`手順、`/tmp`でのraw output管理、
manual redaction、expected evidence照合は
`docs/compatibility-regeneration.md`に従う。helperはcommitted fixtureを直接
上書きせず、scannerをhostへinstallしない。

## Not Covered

- `8.27.2`以外のGitleaks release、rule set、configurationの互換性。
- Unknown repositoryや実secretを含むrepositoryのscan。
- SARIF全variant、全exit code、全Git stateの網羅。
- Scanner binaryの取得元、署名、supply-chain trustの証明。
- Finding 0件を安全証明またはexecution authorizationとして扱うこと。

## Compatibility Matrix

- JSON required: supported through redacted compatibility fixtures
- SARIF: supported for the documented redacted sample
- Raw output retention: not allowed
- Execution authorization: always false

Compatibility is limited to the documented fixture, version, and scope. It is
not a claim that repo-health-doctor replaces Gitleaks. A no-finding result is
not proof of safety; it means only that the scanner reached scope did not
produce findings under the active rules and configuration.
