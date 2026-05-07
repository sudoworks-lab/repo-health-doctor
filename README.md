# repo-health-doctor

`repo-health-doctor` は、repository を AI 開発前に軽く診断するための小さな Python CLI です。
「README があるか」「tests / docs / scripts があるか」「明らかな secret らしき文字列が混ざっていないか」「大きすぎるファイルがないか」を、ローカルで短時間に確認できます。

派手な機能追加ではなく、AI 支援開発やローカル開発基盤の前段で repository の hygiene を機械的に点検する用途を想定しています。

## 何を解決するか

- AI に repository を渡す前の preflight を軽く回したい
- private repo を他人に見せる前に、基本的な抜け漏れを短時間で確認したい
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

## Install

開発中の checkout をそのまま使う前提なら、editable install で十分です。

```bash
python3 -m pip install -e .
```

system 管理下の Python 環境で `externally-managed-environment` が出る場合は、先に virtualenv を作ってから install してください。

インストール後の実行コマンドは `repo-health-doctor` です。

## Usage

```bash
repo-health-doctor .
repo-health-doctor . --format json
repo-health-doctor . --strict
repo-health-doctor . --large-file-threshold-mb 5
repo-health-doctor . --format json --output /tmp/repo-health-doctor-result.json
repo-health-doctor . --secrets-ignore artifacts/ --secrets-ignore tmp/
```

開発中に entry point を使わず試す場合は、次も実在します。

```bash
PYTHONPATH=src python3 -m repo_health_doctor.cli .
```

`--output` を指定すると、指定ファイルへ保存しつつ同じ内容を標準出力にも出します。

## 実行例

この repository 自体に対して現状の実装を走らせると、次のような text 出力になります。

```text
Repo Health Doctor: PASS
Target: /home/itkhyt/projects/repo-health-doctor
Summary: 8 pass, 0 warn, 0 fail

[PASS] readme: README found.
  found: README.md

[PASS] license: License file found.
  found: LICENSE

[PASS] gitignore: .gitignore found.
  found: .gitignore, .git/info/exclude

[PASS] tests: Test directory found.
  found: tests

[PASS] docs: Docs directory found.
  found: docs

[PASS] scripts: Scripts directory found.
  found: scripts

[PASS] secrets_scan: No obvious secrets detected.
  scanned_files: 16

[PASS] large_files: No large files detected.
  threshold_bytes: 10485760
```

JSON 出力の先頭は次のようになります。

```json
{
  "tool": "repo-health-doctor",
  "version": "0.1.0",
  "repo_path": "/home/itkhyt/projects/repo-health-doctor",
  "overall_status": "pass"
}
```

## Exit Codes

- `0`: `pass` のみ
- `0`: `warn` のみで `--strict` なし
- `1`: `fail` が 1 件以上
- `1`: `--strict` 指定時に `warn` が 1 件以上

## CLI Options

- `--format {text,json}`: 出力形式を切り替えます
- `--strict`: warning も失敗扱いにして exit code `1` を返します
- `--large-file-threshold-mb <int>`: large file 判定の閾値を MB 単位で指定します。デフォルトは `10`
- `--output <file>`: text / json の描画結果をファイルへ保存しつつ標準出力にも出します
- `--secrets-ignore <pattern>`: secrets scan から path prefix を除外します。複数回指定できます

## CI / Tests

GitHub Actions workflow を同梱しており、`push` / `pull_request` で Python `3.11` と `3.12` の matrix を回します。
workflow 内で実行しているコマンドは現在次のとおりです。

```bash
python -m pip install --upgrade pip
pip install -e .
PYTHONPATH=src python -m unittest discover -s tests -v
repo-health-doctor .
repo-health-doctor . --strict
repo-health-doctor . --format json --output /tmp/repo-health-doctor-result.json
test -s /tmp/repo-health-doctor-result.json
```

`--strict` なしでは warning-only の repository は成功扱いなので、ローカル確認や段階導入に向いています。CI で warning も失敗扱いにしたい場合は `--strict` を使います。

## Privacy / Security Notes

- すべてローカル filesystem を読むだけで、network access は行いません
- secrets scan は軽量な heuristic ベースであり、完全な secret detection を保証しません
- binary file は secrets scan の対象外です
- `node_modules/`, `.venv/`, `.pytest_cache/`, `dist/`, `build/` などは既定で scan 対象外です
- `artifacts/` や AI 実行ログのような生成物を除外したい場合は `--secrets-ignore` を追加してください

## 設計意図

この repository の意図は、AI がコードを書き始める前に repository の足元を数秒で確認できるようにすることです。
依存解析や SAST のような重い仕組みの代替ではなく、次のような場面での「軽い診断」に寄せています。

- private repo を外部に見せる前の最終確認
- Codex などへ作業依頼する前の preflight
- JSON を downstream automation に渡す前段チェック

`ai-run-logger` や Codex preflight と直接結合しているわけではありませんが、そうした AI 作業フローの前段で走らせる補助 CLI としては相性が良い設計です。生成された `artifacts/` や `logs/` を scan 対象から外したい場合は `--secrets-ignore` で調整できます。

## Architecture

設計方針や「検知するもの / しないもの」は [docs/architecture.md](docs/architecture.md) にまとめています。

## Scope Today

現時点では、次のような項目はまだ対象外です。

- dependency vulnerability の検査
- license policy の検証
- formatter / linter / type checker の実行
- AST や履歴に基づく高度な secret detection
- remote repository 設定の検証
