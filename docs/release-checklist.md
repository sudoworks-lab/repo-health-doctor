# Release Checklist

配布前には、CLI と JSON 契約、CI、redaction 方針が揃っていることを確認します。

## Offline Local Verify

- `git status --short` が意図した差分だけであること
- `PYTHONPATH=src python3 -m unittest discover -s tests -v` が成功すること
- `PYTHONPATH=src python3 -m repo_health_doctor --help` が成功すること
- `PYTHONPATH=src python3 -m repo_health_doctor --version` が成功すること
- `wc -l AGENTS.md` が 200 行以内であることを示すこと
- `PYTHONPATH=src python3 -m repo_health_doctor . --fail-on warn --public-safety` が期待どおりの exit code を返すこと
- `PYTHONPATH=src python3 -m repo_health_doctor validate-policy .` が policy 破損を独立して検出できること
- `PYTHONPATH=src python3 -m repo_health_doctor release-check . --format markdown --output /tmp/release-check.md` が成功し、GitHub Step Summary 向け summary を生成できること
- JSON 出力が `python3 -m json.tool` で parse できること
- README の Quickstart と `docs/demo.md` の主要コマンドが現行 CLI と一致していること

## Packaging Verify

- build dependency 解決済み環境または CI で `python3 -m pip install -e .` が成功すること
- editable install 後に `repo-health-doctor --help` と `repo-health-doctor --version` が成功すること
- editable install 後に `repo-health-doctor validate-policy .` が成功すること
- network-restricted な local 環境で build-system dependency 解決前に止まる場合は、offline local verify を正本にし、packaging verify は CI で維持すること

## Status And Exit Codes

- `PASS`: 問題なし。exit code `0`
- `WARN`: 確認推奨。`--fail-on block` では exit code `0`、`--fail-on warn` では exit code `1`
- `BLOCK`: 公開・共有前に対応が必要。exit code `1`

`--strict` は `--fail-on warn` 相当の後方互換 option として扱います。

## Public Safety And Policy

- `--public-safety` は repository 内容を走査し、公開前の block/warn を検出する
- `validate-policy` は scan を実行せず、policy file の形式、期限、rule_id、allow 制約を検証する
- `release-check` は scan、policy validation、allow inventory、optional report diff を 1 つの release readiness summary にまとめる
- CI では `--public-safety` と `validate-policy` の両方を実行する

## Redaction And Docs

- text / JSON report に raw の検知値を出さないこと
- policy 由来の具体値、reason、owner、path pattern を report に出さないこと
- `repo_path` は絶対 path ではなく相対 path または masked value であること
- `AGENTS.md` は短い作業契約に留め、詳細 recipe は `docs/agent-guide.md` に分離すること
- README、docs、schema、workflow に組織固有の禁止語や具体的な検知値を例示しないこと
- README と release-checklist で `--fail-on` / `--strict` / `validate-policy` の導線が矛盾しないこと

## Packaging

- `pyproject.toml` の project metadata と console script が現在の CLI と一致していること
- build backend は標準の `setuptools.build_meta` を維持すること
- module 実行 `python3 -m repo_health_doctor --help` が成功すること
