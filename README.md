# repo-health-doctor

repo-health-doctor is a local-first preflight gate for maintainers deciding whether to accept AI-generated repository changes.

`repo-health-doctor` は、AI生成差分を受け入れるか判断する maintainer 向けの local-first preflight gate です。repo を公開・共有・自動化へ渡す前に、README、LICENSE、CI、tests、pre-publish signal checks、tracked artifacts、policy validity、redacted JSON output を短時間で確認します。

## Who This Helps

- AI 生成差分をレビューする OSS maintainer
- local-first な公開前 gate を置きたい個人開発者
- repo 作業の前後で安全確認したい coding agent
- PASS / WARN / BLOCK と JSON を CI で扱いたい automation

## What It Checks

- README、LICENSE、workflow、tests、docs、scripts の基本整備
- secret-like pattern、large file、tracked artifact 候補
- `--public-safety` による private path、local IP、限定カテゴリ pattern の検知
- `validate-policy` による allow / ignore policy の形式、期限、rule_id の検証
- raw 値を出さない redacted text / JSON report

## Where It Fits

深い static analysis や security 製品の代替ではありません。maintainer が repo を share、publish、automation へ渡す前に、短時間で publish-or-hold decision を行うための前段 gate です。

## Maintainer And Agent Readiness

- maintainer 向けの運用導線は [docs/maintainer-guide.md](docs/maintainer-guide.md) に分離しています
- agent 向けの短い作業契約は [AGENTS.md](AGENTS.md)、詳細手順は [docs/agent-guide.md](docs/agent-guide.md) に置いています
- redaction 境界は [docs/security-model.md](docs/security-model.md)、fixture と golden の考え方は [docs/evaluation-model.md](docs/evaluation-model.md) で管理します
- phase 設計は [docs/maintainer-system-roadmap.md](docs/maintainer-system-roadmap.md) にまとめています

## Quickstart

まずは offline local verify として、開発中の checkout を `PYTHONPATH=src` でそのまま確認できます。

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m repo_health_doctor --help
PYTHONPATH=src python3 -m repo_health_doctor --version
PYTHONPATH=src python3 -m repo_health_doctor . --fail-on block --public-safety
PYTHONPATH=src python3 -m repo_health_doctor validate-policy .
PYTHONPATH=src python3 -m repo_health_doctor release-check .
PYTHONPATH=src python3 -m repo_health_doctor . --public-safety --format json --output /tmp/repo-health-doctor-result.json
PYTHONPATH=src python3 -m repo_health_doctor . --public-safety --format markdown --output /tmp/repo-health-doctor-summary.md
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
repo-health-doctor release-check . --format markdown --output /tmp/release-check.md
```

network-restricted な local 環境では build-system dependency の解決前に packaging verify が止まることがあります。その場合でも offline local verify を正本として回し、packaging verify は CI または build dependency 解決済み環境で維持します。

実行の流れをそのまま追いたい場合は [docs/demo.md](docs/demo.md) を参照してください。
GitHub Step Summary を含む CI 連携は [docs/ci-integration.md](docs/ci-integration.md) にまとめています。

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
repo-health-doctor . --public-safety --format markdown --output /tmp/repo-health-doctor-public-safety.md
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

## List Allows

stale な allow を棚卸ししたい場合は `list-allows` mode を使います。
allow entry ごとに safe policy id、rule_id、path scope、expires、`active` / `expiring-soon` / `expired` status を返します。

```bash
repo-health-doctor list-allows .
repo-health-doctor list-allows . --format json
repo-health-doctor list-allows . --status expiring-soon
repo-health-doctor list-allows . --fail-on expiring-soon
repo-health-doctor list-allows . --format markdown --output /tmp/repo-health-doctor-allows.md
```

`expiring-soon` は残り 30 日以内の allow、`expired` は期限切れの allow です。
`--status` は表示対象だけを絞り、`--fail-on expiring-soon` は `expiring-soon` または `expired` があれば CI を fail させます。
path pattern、reason、owner などの raw policy value は report に出しません。

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

## Markdown Output

GitHub Step Summary や CI artifact に載せたい場合は `--format markdown` または `--format md` を使います。
Markdown も既存 report dict から描画するだけなので、`schema_version` や JSON 契約は変わりません。

```bash
repo-health-doctor . --public-safety --format markdown
repo-health-doctor . --public-safety --format md --output /tmp/repo-health-doctor-summary.md
```

report には title、target repo path、overall status、summary counts、status meanings、checks、redacted findings を含めます。
CI での貼り付け例は [docs/ci-integration.md](docs/ci-integration.md) を参照してください。

## Report Diff

前回 report と今回 report の差分を maintainer が見たい場合は `diff-reports` を使います。
2 つの JSON report を比較し、overall status の変化、added / resolved findings、unchanged count、severity change、check status change を redacted のまま確認できます。

```bash
repo-health-doctor diff-reports before.json after.json
repo-health-doctor diff-reports before.json after.json --format json
repo-health-doctor diff-reports before.json after.json --format markdown --output /tmp/repo-health-doctor-diff.md
```

`diff-reports` は既存 scan / validate-policy / list-allows の JSON report を入力として扱う comparison command です。
既存 scan report の `schema_version`、rule_id、text / JSON / Markdown 契約は変えません。
diff JSON は同じ `schema_version: 1.1` を維持しつつ `report_kind: report_diff` で区別し、contract は `schemas/report-diff.schema.json` に固定します。
golden fixture は `tests/fixtures/golden/report-diff-demo.json` で drift を確認します。

## Release Check

release 前に scan、policy validation、allow inventory、optional report diff を 1 つの summary にまとめたい場合は `release-check` を使います。
report には overall release readiness、repo scan status、policy validation status、allow inventory summary、recommended next action を含めます。

```bash
repo-health-doctor release-check .
repo-health-doctor release-check . --format json --output /tmp/release-check.json
repo-health-doctor release-check . --format markdown --output /tmp/release-check.md
repo-health-doctor release-check . --baseline-report before.json --format markdown
```

`release-check` は `--public-safety` scan を内部で実行し、baseline scan JSON report がある場合だけ redacted diff summary を追加します。
JSON contract は `schema_version: 1.1` を維持しつつ `report_kind: release_check` で区別し、schema は [schemas/release-check-report.schema.json](schemas/release-check-report.schema.json) に固定します。

## Policy

policy は `repo-health-doctor.yml` と `.repo-health-doctor.local.yml` から読み込みます。

- `ignore_paths`: repository hygiene 系 check の scan 対象を path pattern で除外
- `allow_findings`: 検出後の例外を理由・owner・期限付きで付与

`ignore_paths` は万能除外ではありません。security / public-safety / tracked-artifact 系 rule には適用しません。
stale allow の棚卸しは `repo-health-doctor list-allows .` で行えます。
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
repo-health-doctor . --strict --public-safety --format markdown --output /tmp/repo-health-doctor-summary.md
python3 -m json.tool /tmp/repo-health-doctor-result.json >/dev/null
repo-health-doctor validate-policy .
repo-health-doctor validate-policy . --format json --output /tmp/repo-health-doctor-policy.json
python3 -m json.tool /tmp/repo-health-doctor-policy.json >/dev/null
```

Quickstart の offline local verify は checkout 直後でも回しやすい command を並べています。
packaging verify は editable install と console script を確認する段で、CI または build dependency 解決済み環境で回す前提です。
release 観点の確認項目は [docs/release-checklist.md](docs/release-checklist.md) にまとめています。

## Redaction

- text / JSON / Markdown report に raw の検知値は出しません
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

- [docs/requirements.md](docs/requirements.md): 要件の正本
- [docs/maintainer-guide.md](docs/maintainer-guide.md): maintainer の運用導線
- [docs/agent-guide.md](docs/agent-guide.md): coding agent の作業境界と verify
- [docs/security-model.md](docs/security-model.md): redaction と safety boundary
- [docs/evaluation-model.md](docs/evaluation-model.md): tests、fixtures、golden の役割
- [docs/ci-integration.md](docs/ci-integration.md): CI と GitHub Step Summary へのつなぎ方
- [docs/demo.md](docs/demo.md): 小さな sample repo で実行の流れを確認する
- [docs/policy.md](docs/policy.md): policy の考え方と validate-policy mode
- [docs/rules.md](docs/rules.md): rule_id、severity、redaction 方針
- [docs/architecture.md](docs/architecture.md): 設計方針と対象範囲
- [docs/project-pitch.md](docs/project-pitch.md): 申請前の価値説明 draft
- [docs/roadmap.md](docs/roadmap.md): 今後の改善候補
- [docs/release-checklist.md](docs/release-checklist.md): 配布前チェック
