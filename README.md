# repo-health-doctor

`repo-health-doctor` は、repository を公開・共有前に軽く診断するための小さな Python CLI です。
「README があるか」「tests / docs / scripts があるか」「明らかな secret らしき文字列が混ざっていないか」「大きすぎるファイルがないか」を、ローカルで短時間に確認できます。

派手な機能追加ではなく、ローカル開発や CI の前段で repository の hygiene を機械的に点検する用途を想定しています。

## 何を解決するか

- repository を公開・共有する前の preflight を軽く回したい
- repository を第三者に見せる前に、基本的な抜け漏れを短時間で確認したい
- 人間が読みやすい text 出力と、自動化しやすい JSON 出力の両方がほしい

この tool は「深い静的解析」ではなく、公開・共有前の初期チェックに特化しています。

## 主なチェック項目

現在の実装が確認するのは次の 8 項目です。

- `README` の存在
- `LICENSE` の存在
- `.gitignore` の存在
- `tests` または `test` directory の存在
- `docs` または `doc` directory の存在
- `scripts` / `script` / `bin` directory の存在
- テキスト系ファイルに対する簡易 secrets scan
- 閾値以上の large file 検知

`--public-safety` を付けた場合は、次の公開前チェックも追加します。

- 公開本文に不向きな語や個人 path、local IP の混入検知
- tracked な生成物 / log / cache / 環境 file 候補の検知

## Install

開発中の checkout をそのまま使う前提なら、virtualenv 上の editable install で十分です。

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .
```

インストール後の実行コマンドは `repo-health-doctor` です。

## Quickstart

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .
repo-health-doctor --version
repo-health-doctor . --fail-on block --public-safety
repo-health-doctor validate-policy .
repo-health-doctor . --format json --output /tmp/repo-health-doctor-result.json
python3 -m json.tool /tmp/repo-health-doctor-result.json >/dev/null
```

まず `--public-safety` で repository 内容の公開前チェックを実行し、policy file の破損確認だけを独立させたい場合は `validate-policy` を使います。

## Usage

```bash
repo-health-doctor .
repo-health-doctor . --format json
repo-health-doctor . --fail-on warn
repo-health-doctor . --strict
repo-health-doctor . --large-file-threshold-mb 5
repo-health-doctor . --public-safety
repo-health-doctor . --public-safety --config repo-health-doctor.yml
repo-health-doctor . --public-safety --no-local-config
repo-health-doctor validate-policy .
repo-health-doctor validate-policy . --format json
repo-health-doctor . --format json --output /tmp/repo-health-doctor-result.json
repo-health-doctor . --secrets-ignore artifacts/ --secrets-ignore tmp/
```

開発中に entry point を使わず試す場合は、次も実在します。

```bash
PYTHONPATH=src python3 -m repo_health_doctor .
```

`--output` を指定すると、指定ファイルへ保存しつつ同じ内容を標準出力にも出します。

## 実行例

この repository 自体に対して `--public-safety` 付きで走らせると、次のような text 出力になります。

```text
Repo Health Doctor: PASS
Target: .
Schema: 1.1
Summary: 10 pass, 0 warn, 0 block
Status: PASS ok, WARN review, BLOCK release blocker

Checks:
- [PASS] readme: README found.
    found: README.md

- [PASS] license: License file found.
    found: LICENSE

- [PASS] gitignore: .gitignore found.
    found: .gitignore, .git/info/exclude

- [PASS] tests: Test directory found.
    found: tests

- [PASS] docs: Docs directory found.
    found: docs

- [PASS] scripts: Scripts directory found.
    found: scripts

- [PASS] secrets_scan: No obvious unallowed secrets detected.
    scanned_files: <count>

- [PASS] large_files: No unallowed large files detected.
    threshold_bytes: 10485760

- [PASS] public_text_safety: No obvious public-facing text issues detected.
    scanned_files: <count>
    scan_scope: tracked

- [PASS] tracked_artifacts: Tracked generated or environment files were not detected.
    scan_scope: tracked
```

JSON 出力の先頭は次のようになります。

```json
{
  "tool": "repo-health-doctor",
  "version": "0.1.0",
  "schema_version": "1.1",
  "repo_path": ".",
  "overall_status": "pass"
}
```

JSON report の契約は `schema_version` で管理します。finding が出る場合は `rule_id`, `severity`, `file`, `pattern`, `redacted` を含み、検知値そのものは出力しません。
機械処理する場合は [schemas/public-safety-report.schema.json](schemas/public-safety-report.schema.json) を参照してください。rule の一覧は [docs/rules.md](docs/rules.md) にまとめています。

Policy は `repo-health-doctor.yml` と `.repo-health-doctor.local.yml` から読み込めます。local policy は git 管理外に置く前提です。`ignore_paths` は scan 除外、`allow_findings` は理由・owner・期限付きの finding 例外です。`validate-policy` mode では scan を実行せず policy だけを検証できます。詳細は [docs/policy.md](docs/policy.md) にまとめています。

## Exit Codes

- `0`: `pass` のみ
- `0`: `warn` のみで `--fail-on block`
- `1`: `block` が 1 件以上
- `1`: `--fail-on warn` 指定時に `warn` が 1 件以上
- `1`: `--strict` 指定時に `warn` が 1 件以上

`--strict` は後方互換のため残している `--fail-on warn` 相当の alias です。

## CLI Options

- `--version`: version を表示します
- `--format {text,json}`: 出力形式を切り替えます
- `--fail-on {block,warn}`: exit code `1` にする最小 status を指定します。デフォルトは `block`
- `--strict`: `--fail-on warn` の alias です
- `--large-file-threshold-mb <int>`: large file 判定の閾値を MB 単位で指定します。デフォルトは `10`
- `--output <file>`: text / json の描画結果をファイルへ保存しつつ標準出力にも出します
- `--secrets-ignore <pattern>`: secrets scan から path prefix を除外します。複数回指定できます
- `--public-safety`: 公開前の追加チェックを有効にします
- `--config <file>`: 公開用 policy config を指定します
- `--local-config <file>`: local policy config を指定します
- `--no-local-config`: local policy config を読み込みません

Policy だけを検証する場合は、先頭に `validate-policy` を指定します。

```bash
repo-health-doctor validate-policy .
repo-health-doctor validate-policy . --format json --output /tmp/repo-health-doctor-policy.json
```

## CI / Tests

GitHub Actions workflow を同梱しており、`push` / `pull_request` で Python `3.11` と `3.12` の matrix を回します。
workflow 内で実行しているコマンドは現在次のとおりです。

```bash
python3 -m pip install --upgrade pip
python3 -m pip install -e .
PYTHONPATH=src python -m unittest discover -s tests -v
repo-health-doctor --help
repo-health-doctor --version
python3 -m repo_health_doctor --help
repo-health-doctor .
repo-health-doctor . --strict
repo-health-doctor . --strict --public-safety
repo-health-doctor . --strict --public-safety --format json --output /tmp/repo-health-doctor-result.json
test -s /tmp/repo-health-doctor-result.json
python -m json.tool /tmp/repo-health-doctor-result.json >/dev/null
repo-health-doctor validate-policy .
repo-health-doctor validate-policy . --format json --output /tmp/repo-health-doctor-policy.json
test -s /tmp/repo-health-doctor-policy.json
python -m json.tool /tmp/repo-health-doctor-policy.json >/dev/null
```

デフォルトでは warning-only の repository は成功扱いなので、ローカル確認や段階導入に向いています。CI で warning も失敗扱いにしたい場合は `--fail-on warn` または `--strict` を使います。

## Privacy / Security Notes

- すべてローカル filesystem を読むだけで、network access は行いません
- secrets scan は軽量な heuristic ベースであり、完全な secret detection を保証しません
- binary file は secrets scan の対象外です
- `node_modules/`, `.venv/`, `.pytest_cache/`, `dist/`, `build/` などは既定で scan 対象外です
- `artifacts/` や実行ログのような生成物を除外したい場合は `--secrets-ignore` を追加してください
- `--public-safety` は report 上に生の検知文字列を出さず、中立的なカテゴリ名だけを返します
- public docs や README には、組織固有の禁止語や具体的な検知値を例示しない方針です

## 設計意図

この repository の意図は、公開・共有前に repository の足元を数秒で確認できるようにすることです。
依存解析や SAST のような重い仕組みの代替ではなく、次のような場面での「軽い診断」に寄せています。

- repository を第三者に見せる前の最終確認
- CI や automation に渡す前の preflight
- JSON を downstream automation に渡す前段チェック

特定の周辺 workflow と直接結合せず、「path を inspect して、短い report を返し、local に留まる」ことを契約にしています。生成された `artifacts/` や `logs/` を scan 対象から外したい場合は `--secrets-ignore` で調整できます。

## Architecture

設計方針や「検知するもの / しないもの」は [docs/architecture.md](docs/architecture.md) にまとめています。

## Scope Today

現時点では、次のような項目はまだ対象外です。

- dependency vulnerability の検査
- license policy の検証
- formatter / linter / type checker の実行
- AST や履歴に基づく高度な secret detection
- remote repository 設定の検証
