# Real Scanner Suite

repo-health-doctor has real scanner adapters for Gitleaks, OSV-Scanner, and
Trivy. The suite is an evidence-normalization layer: it calls mature scanners
when explicitly invoked through the adapter/API surface, reads their JSON
reports from temporary files, keeps only a minimal redacted evidence summary,
and feeds that evidence into fail-closed gate logic. It is not a scanner
replacement and not a safety proof.

The default `repo-health-doctor .` CLI path does not run this suite. It does
not install, download, upgrade, or execute Gitleaks, OSV-Scanner, or Trivy, and
it does not contact scanner APIs as part of the default local review command.
The dedicated `real-scan` command is an explicit opt-in surface:

```bash
env PYTHONPATH=src python3 -m repo_health_doctor real-scan . --offline \
  --format json --output /tmp/rhd-real-scan.json
```

`--offline` never invokes OSV-Scanner or Trivy. It is the deterministic CI
smoke mode; Gitleaks is invoked only when its local binary is available. A
live run that omits `--offline` is an operator opt-in and may use network,
cache, or scanner database state. CI does not install, download, or invoke
live scanners. A live run is evidence collection only and is not execution
authorization.

`real-scan`はscanner adapterを呼ぶ前に1つのVerified Snapshotを作る。各adapterは
live repositoryを受け取らず、同じread-only snapshot workspaceと検証済みsubject
だけを受け取る。adapter内のambient `git rev-parse`、`git status`、caller `PATH`
依存Git処理は使用しない。dirty Git repositoryはbounded filesystem snapshotへ
落としてscanできるが、commit bindingがないためno-finding evidenceはscope
ambiguousのままであり、riskを下げない。

The suite applies these bounded defaults before formatting:

- 100 findings per scanner;
- 300 findings across the suite;
- 256 KiB for the compact JSON report;
- 1024 characters for one normalized text field.

`--max-findings-per-scanner`, `--max-findings`, and `--max-report-bytes` can
lower or raise those limits for an explicitly reviewed local run. An exceeded
finding or byte budget keeps only the bounded prefix, records
`omitted_finding_count` and `truncated` on the affected entry, adds a
limitation, and changes the suite to `degraded`. `--fail-on-degraded` returns
exit code 1 after emitting the report. Truncation is never permission to
continue or evidence that the repository is safe.

## Gateへの明示入力

`real-scan`のJSON reportは、明示的に`gate-check --external-evidence`へ渡せる。

```bash
env PYTHONPATH=src python3 -m repo_health_doctor gate-check . \
  --external-evidence /tmp/rhd-real-scan.json \
  -- python3 -c "print('bounded')"
```

`--external-evidence`は最大16件まで繰り返し指定でき、各fileを256 KiB、24時間の
age、schema、fingerprint、現在のrepo commitとdirty state、duplicate、truncationの
境界で検証する。invalidまたは不一致のreportも黙ってskipせず、machine-readableな
reasonを持つinvalid referenceとしてgateへ渡し、verdictを改善させない。

gate decisionに残るのはboundedな`evidence_refs`だけであり、raw suite report、
`entries`、`normalized_result`、入力pathは保存しない。report未指定時には
`evidence_refs`を追加しない。trailing commandは将来の実行候補を表すだけで、
`gate-check`が実行することもauthorizationを自動探索することもない。このversionの
明示的なauthorization validationは`--authorization`と`--argv-json`を使用する。

## Inventory

| Scanner | Scope | Default command shape | Network/cache/privacy notes |
| --- | --- | --- | --- |
| Gitleaks | Git secret scan | `gitleaks git --report-format json --report-path <tmp_report_path> --redact --exit-code 2 --no-banner --log-level error <repo_path>` | Local static no-network adapter. Scanner binary trust and rule coverage remain limitations. |
| OSV-Scanner | Dependency vulnerability scan | `osv-scanner scan source --recursive --format json --output-file <tmp_report_path> <repo_path>` | Live scans can query OSV.dev and can send package names, versions, ecosystems, lockfile or manifest metadata, and file hashes. |
| Trivy | Filesystem vulnerability and misconfiguration scan | `trivy fs --scanners vuln,misconfig --format json --output <tmp_report_path> --exit-code 1 --cache-dir <tmp_cache_dir> <repo_path>` | Live scans can download or update vulnerability, Java, misconfiguration, and check databases and can use cache state. |

The Trivy adapter intentionally runs `vuln,misconfig` by default, not Trivy's
secret scanner, because Trivy secret JSON can include match text and code
context. The parser can normalize supplied `Secrets` objects by retaining only
rule/category/severity/location metadata, but default live execution avoids
creating raw secret-match payloads.

## Shared Contract

Scanner unavailable is fail-closed, not PASS. Missing binaries, unsafe or
unsupported versions, timeouts, missing reports, invalid JSON, schema
mismatches, unknown exit codes, and exit-code/report contradictions become
unknown or quarantine-oriented evidence. They do not lower risk and do not
authorize execution.

No findings is not proof of safety. No vulnerabilities, no packages found, no
results, or no findings mean only that the scanner did not report issues in
the reached scope. The result remains bounded by scanner rules, extractor
coverage, supported ecosystems and manifests, database availability and
freshness, scanner version, local configuration, and the commit/worktree scope
that was actually scanned.

Raw scanner report JSON, raw stdout, raw stderr, raw secret values, raw match
text, code snippets, advisory raw objects, long descriptions, reference URL
lists, credits, vendor metadata, host absolute paths, private-looking paths,
local addresses, and token-like strings are not retained in normalized
evidence. Evidence keeps only minimal IDs, package/version facts, severity
summaries, redacted or relative paths, and limitation records needed for
review.

## Public API Surface

The suite is exposed from `repo_health_doctor.external_scanner`:

- `REAL_SCANNER_ADAPTER_NAMES`
- `REAL_SCANNER_SUITE_LIMITATIONS`
- `default_real_scanner_adapters()`
- `real_scanner_capabilities()`
- `real_scanner_inventory()`

The inventory is static and safe to import. It does not execute scanners,
create cache directories, contact a network, or read scanner reports.

## Compatibility Notes

- [real-gitleaks-compatibility.md](real-gitleaks-compatibility.md)
- [real-osv-compatibility.md](real-osv-compatibility.md)
- [real-trivy-compatibility.md](real-trivy-compatibility.md)

Optional live tests are not the default verification path. OSV-Scanner and
Trivy live tests require explicit environment opt-in because they can use
network or cache state. The normal unit tests use mock runners and redacted
fixtures so CI can pass without local scanner binaries.

## レポートschemaと表示形式

suite reportは`schemas/real-scanner-suite.schema.json`の`0.1-draft`契約で表現する。
JSON、text、Markdownは同じentry、status、finding count、risk effect、limitationを表示し、
`execution_authorized`は常に`false`である。JSONのgolden sampleは
`tests/fixtures/golden/real-scanner-suite.json`に置く。

表示前に、raw scanner output、stdout、stderr、secret-like value、token-like value、
hostの絶対pathをredactする。redaction後の表示もscannerの安全性や実行認可を証明しない。
