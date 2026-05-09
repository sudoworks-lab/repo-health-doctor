# repo-health-doctor

`repo-health-doctor` は、repository を公開・共有前に点検するための小さな Python CLI です。
README や LICENSE の有無、workflow や tests の基本整備、軽量な secrets scan、large file、公開前 safety check をローカルまたは CI で短時間に確認できます。

## Why

公開直前の repository では、深い静的解析より前に「見せてよい状態か」を短時間で確かめたい場面があります。
この tool はその preflight 用です。人間が読みやすい text と、自動化しやすい JSON の両方を返します。

## Quickstart

まずは offline local verify として、開発中の checkout を `PYTHONPATH=src` でそのまま確認できます。

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m repo_health_doctor --help
PYTHONPATH=src python3 -m repo_health_doctor --version
PYTHONPATH=src python3 -m repo_health_doctor . --fail-on block --public-safety
PYTHONPATH=src python3 -m repo_health_doctor validate-policy .
PYTHONPATH=src python3 -m repo_health_doctor . --public-safety --format json --output /tmp/repo-health-doctor-result.json
python3 -m json.tool /tmp/repo-health-doctor-result.json >/dev/null
```

build dependency を解決できる環境では、packaging verify として editable install も確認します。

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .
repo-health-doctor --version
repo-health-doctor . --fail-on block --public-safety
repo-health-doctor validate-policy .
repo-health-doctor . --public-safety --format json --output /tmp/repo-health-doctor-result.json
```

network-restricted な local 環境では build-system dependency の解決前に packaging verify が止まることがあります。その場合でも offline local verify を正本として回し、packaging verify は CI または build dependency 解決済み環境で維持します。

実行の流れをそのまま追いたい場合は [docs/demo.md](docs/demo.md) を参照してください。

## Public Safety

通常 mode は repository hygiene を軽く確認します。
`--public-safety` を付けると、次の公開前チェックも追加します。

- 公開本文に不向きなカテゴリの検知
- 個人環境由来の path カテゴリや local network カテゴリの検知
- tracked な生成物 / log / cache / 環境 file 候補の検知

代表的な実行例:

```bash
repo-health-doctor .
repo-health-doctor . --public-safety
repo-health-doctor . --fail-on warn --public-safety
repo-health-doctor . --public-safety --format json --output /tmp/repo-health-doctor-public-safety.json
```

`PASS` は問題なし、`WARN` は確認推奨、`BLOCK` は公開・共有前に対応が必要です。

## Validate Policy

policy file だけを独立して検証したい場合は `validate-policy` mode を使います。
scan は走らず、policy の形式、期限、rule_id、allow 制約を検証します。

```bash
repo-health-doctor validate-policy .
repo-health-doctor validate-policy . --format json
repo-health-doctor validate-policy . --format json --output /tmp/repo-health-doctor-policy.json
repo-health-doctor validate-policy . --no-local-config
```

local policy は `.repo-health-doctor.local.yml`、公開用 policy は `repo-health-doctor.yml` を使います。

## JSON Output

JSON report の契約は `schema_version` で管理します。現行は `1.1` です。
finding がある場合は少なくとも `rule_id`, `severity`, `file`, `pattern`, `redacted` を含みます。
次の sample は `tests/fixtures/demo-repo` に対する `validate-policy` の正規化済み出力です。

```json
{
  "tool": "repo-health-doctor",
  "version": "0.1.0",
  "schema_version": "1.1",
  "repo_path": "<demo-repo>",
  "overall_status": "pass",
  "summary": {
    "pass": 1,
    "warn": 0,
    "block": 0
  },
  "checks": [
    {
      "name": "policy",
      "status": "pass",
      "summary": "Policy configuration loaded.",
      "details": {
        "findings": [],
        "policy_sources": [
          "repo"
        ],
        "ignore_path_count": 1,
        "allow_finding_count": 0
      }
    }
  ]
}
```

full sample outputs は `tests/fixtures/golden/` に置き、test で drift を検知します。
machine-readable schema は [schemas/public-safety-report.schema.json](schemas/public-safety-report.schema.json) を参照してください。
rule 一覧は [docs/rules.md](docs/rules.md) にあります。

## Policy

policy は `repo-health-doctor.yml` と `.repo-health-doctor.local.yml` から読み込みます。

- `ignore_paths`: repository hygiene 系 check の scan 対象を path pattern で除外
- `allow_findings`: 検出後の例外を理由・owner・期限付きで付与

`ignore_paths` は万能除外ではありません。security / public-safety / tracked-artifact 系 rule には適用しません。
詳細は [docs/policy.md](docs/policy.md) を参照してください。

## CI

CI では offline local verify 相当の command に加えて、packaging verify も維持します。

```bash
python3 -m pip install -e .
PYTHONPATH=src python3 -m unittest discover -s tests -v
repo-health-doctor --help
repo-health-doctor --version
repo-health-doctor . --strict --public-safety
repo-health-doctor . --strict --public-safety --format json --output /tmp/repo-health-doctor-result.json
python3 -m json.tool /tmp/repo-health-doctor-result.json >/dev/null
repo-health-doctor validate-policy .
repo-health-doctor validate-policy . --format json --output /tmp/repo-health-doctor-policy.json
python3 -m json.tool /tmp/repo-health-doctor-policy.json >/dev/null
```

Quickstart の offline local verify は checkout 直後でも回しやすい command を並べています。
packaging verify は editable install と console script を確認する段で、CI または build dependency 解決済み環境で回す前提です。
release 観点の確認項目は [docs/release-checklist.md](docs/release-checklist.md) にまとめています。

## Redaction

- text / JSON report に raw の検知値は出しません
- policy 由来の具体値、reason、owner、path pattern は report に出しません
- public-safety の検知結果は中立的な category を返します
- `repo_path` は絶対 path ではなく、相対 path または masked value を返します

次の sample は `tests/fixtures/demo-repo` に対する `--public-safety` の正規化済み text 出力です。

```text
Repo Health Doctor: PASS
Target: <demo-repo>
Schema: 1.1
Summary: 12 pass, 0 warn, 0 block
Status: PASS ok, WARN review, BLOCK release blocker

Checks:
- [PASS] readme: README found.
    found: README.md

- [PASS] license: License file found.
    found: LICENSE

- [PASS] gitignore: .gitignore found.
    found: .gitignore, .git/info/exclude

- [PASS] ci: Workflow file found.
    found: .github/workflows/ci.yml

- [PASS] tests: Test directory found.
    found: tests

- [PASS] docs: Docs directory found.
    found: docs

- [PASS] scripts: Scripts directory found.
    found: scripts

- [PASS] secrets_scan: No obvious unallowed secrets detected.
    scanned_files: 6

- [PASS] large_files: No unallowed large files detected.
    threshold_bytes: 10485760

- [PASS] public_text_safety: No obvious public-facing text issues detected.
    scanned_files: 6
    scan_scope: tracked

- [PASS] tracked_artifacts: Tracked generated or environment files were not detected.
    scan_scope: tracked

- [PASS] policy: Policy configuration loaded.
    policy_sources: repo
    ignore_path_count: 1
    allow_finding_count: 0
```

## What It Does Not Guarantee

この tool は公開・共有前の軽い診断です。次の保証はしません。

- dependency vulnerability の検査
- license policy の厳密検証
- formatter / linter / type checker の代替
- AST や履歴に基づく高度な detection
- remote repository 設定や hosting 設定の検証
- 完全な secret detection

## Related Docs

- [docs/demo.md](docs/demo.md): 小さな sample repo で実行の流れを確認する
- [docs/policy.md](docs/policy.md): policy の考え方と validate-policy mode
- [docs/rules.md](docs/rules.md): rule_id、severity、redaction 方針
- [docs/architecture.md](docs/architecture.md): 設計方針と対象範囲
- [docs/release-checklist.md](docs/release-checklist.md): 配布前チェック
