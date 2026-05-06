# repo-health-doctor

`repo-health-doctor` is a minimal Python CLI that inspects a repository and reports a few practical health signals for humans and automation.

## Purpose

- Spot obvious missing repository basics early.
- Give a fast local check before publishing or handing a repo to someone else.
- Produce both readable terminal output and machine-friendly JSON.

## Usage

```bash
python -m pip install -e .
repo-health-doctor .
repo-health-doctor . --format json
repo-health-doctor . --strict
repo-health-doctor . --large-file-threshold-mb 5
repo-health-doctor . --format json --output /tmp/repo-health-doctor-result.json
repo-health-doctor . --secrets-ignore artifacts/ --secrets-ignore tmp/
```

`--output` を指定した場合は、指定ファイルへ保存しつつ同じ内容を標準出力にも出します。

## CI Usage

```bash
repo-health-doctor .
repo-health-doctor . --strict
repo-health-doctor . --format json --output /tmp/repo-health-doctor-result.json
repo-health-doctor . --strict --secrets-ignore artifacts/ --secrets-ignore tmp/
```

`--strict` なしでは warning のみなら成功扱いなので、ローカル確認や段階導入に向いています。CIで warning も失敗扱いにしたい場合は `--strict` を指定します。

## Output Example

Text output:

```text
Repo Health Doctor: WARN
Target: /path/to/repo
Summary: 5 pass, 3 warn, 0 fail

[PASS] readme: README found.
  found: README.md

[WARN] docs: Docs directory is missing.

[PASS] secrets_scan: No obvious secrets detected.
  scanned_files: 12
```

JSON output:

```json
{
  "tool": "repo-health-doctor",
  "version": "0.1.0",
  "repo_path": "/path/to/repo",
  "overall_status": "warn"
}
```

## Exit Codes

- `0`: pass のみ
- `0`: warn のみで `--strict` なし
- `1`: fail が1件以上
- `1`: `--strict` 指定時に warn が1件以上

## Options

- `--strict`: warn 以上で exit code 1 を返します
- `--large-file-threshold-mb <int>`: large files 判定の閾値を MB 単位で指定します。デフォルトは `10`
- `--output <file>`: text / json の描画結果を指定ファイルへ保存し、同時に標準出力にも出します
- `--secrets-ignore <pattern>`: secrets scan から path prefix を除外します。複数回指定できます

## Secrets Scan

Secrets scan はテキスト系ファイルだけを対象に、シンプルなパターンで明らかな秘密情報らしき文字列を探します。large files 判定とは独立しており、バイナリファイルは secrets scan の対象外です。

デフォルトで次のパス配下は secrets scan 対象外です。

- `.git/`
- `.venv/`
- `venv/`
- `node_modules/`
- `__pycache__/`
- `.pytest_cache/`
- `dist/`
- `build/`

追加で除外したい場合は `--secrets-ignore` を複数回指定できます。

```bash
repo-health-doctor . --secrets-ignore artifacts/ --secrets-ignore tmp/
```

## Checks

- README
- LICENSE
- `.gitignore`
- tests directory
- docs directory
- scripts directory
- basic secrets scan using simple file/content heuristics
- large files over 10 MB

## Roadmap

- Add configurable thresholds and ignore rules
- Add richer secret detection and better false-positive handling
- Detect CI, formatting, lint, and dependency health
