# Release Checklist

配布前には、CLI と JSON 契約、CI、redaction 方針が揃っていることを確認します。

## Local Verification

- `git status --short` が意図した差分だけであること
- `python3 -m unittest discover -s tests -v` が成功すること
- 一時 `venv` を作成して `python -m pip install -e .` が成功すること
- `repo-health-doctor --help` が成功すること
- `repo-health-doctor --version` が成功すること
- `repo-health-doctor . --fail-on warn --public-safety` が期待どおりの exit code を返すこと
- `repo-health-doctor validate-policy .` が policy 破損を独立して検出できること
- JSON 出力が `python3 -m json.tool` で parse できること

## Status And Exit Codes

- `PASS`: 問題なし。exit code `0`
- `WARN`: 確認推奨。`--fail-on block` では exit code `0`、`--fail-on warn` では exit code `1`
- `BLOCK`: 公開・共有前に対応が必要。exit code `1`

`--strict` は `--fail-on warn` 相当の後方互換 option として扱います。

## Public Safety And Policy

- `--public-safety` は repository 内容を走査し、公開前の block/warn を検出する
- `validate-policy` は scan を実行せず、policy file の形式、期限、rule_id、allow 制約を検証する
- CI では `--public-safety` と `validate-policy` の両方を実行する

## Redaction And Docs

- text / JSON report に raw の検知値を出さないこと
- policy 由来の具体値、reason、owner、path pattern を report に出さないこと
- `repo_path` は絶対 path ではなく相対 path または masked value であること
- README、docs、schema、workflow に組織固有の禁止語や具体的な検知値を例示しないこと

## Packaging

- `pyproject.toml` の project metadata と console script が現在の CLI と一致していること
- build backend は標準の `setuptools.build_meta` を維持すること
- editable install 後に `repo-health-doctor --help` と `repo-health-doctor --version` が成功すること
- module 実行 `python3 -m repo_health_doctor --help` が成功すること
