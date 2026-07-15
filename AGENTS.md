# AGENTS

`repo-health-doctor` is a local-first preflight CLI for maintainers reviewing repository changes.

## Core Contract

- Do not add network calls.
- Do not print raw secrets, tokens, private paths, local IPs, or policy raw values.
- Do not weaken redaction in text output, JSON output, tests, fixtures, or docs.
- Do not change `schema_version`, CLI behavior, or existing `rule_id` values without explicit maintainer instruction.
- Do not add release, publish, or other external actions without human approval.
- Do not commit generated reports, local artifacts, caches, or `.repo-health-doctor.local.yml`.

## When Editing Rules Or Safety Logic

- Inspect `tests/fixtures/` before adding new fixtures.
- Reuse existing fixtures when they can trigger the same detection scenario.
- Update tests, fixtures, and docs together when adding or changing a rule.
- Re-check golden outputs when public-safety or redaction behavior changes.
- Keep policy examples and reports redacted.

## Required Verification

Run these before completion unless the maintainer changes the verify contract:

```bash
git status --short
find docs -maxdepth 2 -type f | sort
find tests/fixtures -maxdepth 3 -type f | sort
wc -l AGENTS.md
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m repo_health_doctor --help
PYTHONPATH=src python3 -m repo_health_doctor --version
PYTHONPATH=src python3 -m repo_health_doctor . --fail-on block --public-safety
PYTHONPATH=src python3 -m repo_health_doctor validate-policy .
PYTHONPATH=src python3 -m repo_health_doctor . --public-safety --format json --output /tmp/repo-health-doctor-result.json
python3 -m json.tool /tmp/repo-health-doctor-result.json >/dev/null
```

## Goal Loop 恒久規則

### ドキュメントの権限

- `docs/GOAL.md` は人間が管理するspecであり、エージェントは読み取り専用とする。
- `docs/PLAN.md` は「判断メモ」セクションへの追記だけを許可する。
- `docs/STATUS.md` は末尾への追記だけを許可し、過去エントリを書き換えない。
- `docs/features.json` でエージェントが変更できるのは `passes`、`verified_at`、`blocked` だけとする。項目の追加・削除や説明・検証手順の変更は行わない。
- 検証を完了していないfeatureを `passes: true` にしない。

### 1 process / 1 feature

- 外部runnerが指定したfeature 1件だけを、1 processかつ1 parent turnで扱う。エージェントはfeatureを選び直さず、完了後に別featureへ進まない。
- 検証が失敗した場合は新しい作業へ進まず、指定featureの範囲で原因調査、最小修正、再検証を優先する（stop-and-fix）。
- Goal Loopのwrite iterationはmain agentだけで実行し、subagent、agent delegation、`/goal`、`wait_agent`を使用しない。
- 「完走」「止まらない」はrunnerが指定した1 featureだけに適用し、プロジェクト全体の完了まで同じprocessを継続する意味に拡張しない。

### Gitとcommit境界

- Goal Loopのwrite iterationでは、エージェントは `git add`、`git commit`、`git reset`、`git checkout`、`git stash`を実行しない。
- host runnerだけがcommit requestに明示された相対pathをstageし、staged pathの完全一致と `git diff --cached --check`を確認してからcommitする。`git add .` と `git add -A`は使用しない。
- 作業開始時のdirty一覧をpre-existing dirtyとして保護し、変更、stage、commit requestへの追加を行わない。
- logs、cache、history、secret、個人情報、generated report、local artifactをcommitしない。

### 言語

- ドキュメント、`docs/STATUS.md`、commit messageは日本語で記述する。code、command、技術用語は英語のまま記述する。

### schema versionの限定許可

- `docs/GOAL.md` に明記されたExperimentalまたはdraft schemaのversion bumpだけは、今回のHumanによる明示許可として扱う。この許可はstable schema、stable public contract、既存の既定CLI behavior、既存の `rule_id` には適用せず、それらの無断変更禁止を維持する。

## Pointers

- Agent workflow details: [docs/agent-development-guide.md](docs/agent-development-guide.md)
- Maintainer workflow: [docs/maintainer-guide.md](docs/maintainer-guide.md)
- Safety boundary: [docs/security-model.md](docs/security-model.md)
- Evaluation model: [docs/evaluation-model.md](docs/evaluation-model.md)
