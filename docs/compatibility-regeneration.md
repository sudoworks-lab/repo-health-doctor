# Compatibility Regeneration Runbook

This runbook documents how to refresh Gitleaks, OSV-Scanner, and Trivy
real-output-compatible fixtures without weakening repo-health-doctor's safety
boundary.

Regeneration is optional compatibility work. The committed fixtures remain
limited to documented fixture, version, and scope. They are not a public
contract for every scanner version or every repository shape.

## Scope

- Use only safe synthetic repositories or fixtures.
- Do not scan an unknown repository.
- Do not install scanners on the host.
- Do not run scanners directly on the host.
- Do not mount host HOME, credentials, or the Docker socket into the scanner
  container.
- Do not commit raw scanner output.
- Commit only redacted, normalized, reviewable fixtures.
- Do not pass secrets, credentials, personal information, or private paths into
  the container.
- Do not treat regenerated compatibility output as execution authorization.

## Tested Versions

| Scanner | Tested version | Redacted fixture root | Version record | Expected evidence |
|---|---:|---|---|---|
| Gitleaks | `8.27.2` | `tests/fixtures/real-compatibility/gitleaks/` | `gitleaks-version.txt` | `expected-evidence.json` |
| OSV-Scanner | `2.0.3` | `tests/fixtures/real-compatibility/osv/` | `osv-scanner-version.txt` | `expected-evidence.json` |
| Trivy | `0.69.3` | `tests/fixtures/real-scanners/trivy/` | `trivy-version.txt` | `expected-evidence.json` |

表のfixture exact versionだけが`tested`である。同じsupported major familyの
別versionは`compatible_family_unverified`、documented family外は
`unsupported`、明示拒否versionは`denylisted`、parseできないversion出力は
`unparseable`として記録する。regenerationで別versionを観測しただけでは
Tested Versions表を更新しない。redacted fixture、expected evidence、version
record、targeted compatibility testを同時にreviewしてgreenになった場合だけ
表を更新する。

## Separate Image Acquisition From Scan

Image acquisition is a separate human-approved step. The helper scripts use
`--pull=never` so the scan step does not implicitly fetch an image.

If image acquisition is not approved or Docker is unavailable, do not run the
scan step. Record the limitation and keep existing fixtures unchanged.

## Helper Scripts

- `scripts/regenerate-gitleaks-compat-fixtures.sh`
- `scripts/regenerate-osv-compat-fixtures.sh`
- `scripts/regenerate_real_scanner_fixtures.py`

The two shell helpers default to a dry explanation. A scan requires `--run`
and a synthetic target under `examples/` or `tests/fixtures/`.

Raw output is written under `/tmp` or `$TMPDIR`. The scripts do not overwrite
committed fixtures. Manual redaction and normalization are required before any
fixture update.

## Gitleaks Regeneration

Example dry run:

```bash
bash scripts/regenerate-gitleaks-compat-fixtures.sh
```

Example scan step after separate image acquisition and human approval:

```bash
bash scripts/regenerate-gitleaks-compat-fixtures.sh \
  --run \
  --synthetic-repo examples/demo-synthetic-supply-chain
```

Inspect temporary raw output only inside the isolated temporary location long
enough to normalize it. Do not copy raw output into notes, reports, docs, or
committed files. Delete the temporary raw output after redaction and
normalization, and update only the minimal fixture files under
`tests/fixtures/real-compatibility/gitleaks/`.

## OSV-Scanner Regeneration

Example dry run:

```bash
bash scripts/regenerate-osv-compat-fixtures.sh
```

Example scan step after separate image acquisition and human approval:

```bash
bash scripts/regenerate-osv-compat-fixtures.sh \
  --run \
  --synthetic-repo examples/demo-synthetic-supply-chain
```

OSV database lookup may need network access in a dedicated compatibility
session. If network is required, use the explicit script flag for synthetic
fixtures only and record that network was used. Do not use this path for
unknown repositories.

## Trivy Regeneration

Trivy raw-output collection is a separate Human-approved operation. Keep raw
output under `/tmp`, never place it in the repository, and manually reduce it
to the minimum redacted fields required by the compatibility scenario. Do not
commit raw scanner output.

After reviewing and redacting the synthetic license fixture, place only the
reviewed fixture at
`tests/fixtures/real-scanners/trivy/licenses-redacted.real.json`. Then
regenerate the bounded expected evidence and verify it deterministically:

```bash
python3 scripts/regenerate_real_scanner_fixtures.py --scanner trivy --write
python3 scripts/regenerate_real_scanner_fixtures.py --scanner trivy --check
```

The Python helper does not acquire or run Trivy and does not read raw output.
It reads only the committed redacted fixture and version record, normalizes the
fixture through the adapter, validates the result, and writes only
`expected-evidence.json`.

## Docker Unavailable

If Docker is unavailable:

- Do not install a scanner on the host as a workaround.
- Do not run a host scanner directly.
- Keep existing fixtures unchanged.
- Record the limitation in the final verification notes.

## Review Before Commit

Before committing regenerated fixtures:

- Parse JSON fixtures.
- Run targeted compatibility tests.
- Run forbidden leak pattern checks.
- Confirm raw scanner output stayed out of git.
- Confirm docs still say compatibility is limited to documented fixture,
  version, and scope.

Regeneration output is evidence for adapter compatibility only. It is not a
claim that repo-health-doctor can replace the scanner, prove repository safety,
or authorize execution.

Third-party security review is not done. Regeneration does not replace external
review of compatibility assumptions, raw-output handling, or Docker boundaries.

## Not Covered

- Gitleaks `8.27.2`、OSV-Scanner `2.0.3`、Trivy `0.69.3`以外のreleaseを
  testedとすること。
- Unknown repository、実secret、private package、credential、個人情報を使う
  compatibility collection。
- Scannerまたはcontainer imageの自動取得、hostへのinstall、Docker socketの
  mount。
- Scanner rules、advisory/database/cache、全schemaと全exit codeの完全な網羅。
- Regenerated fixtureによるrepositoryの安全証明、risk低下、execution
  authorization。
