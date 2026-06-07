# repo-health-doctor 要件定義書 v0.3

## 0. 文書の目的

この文書は `repo-health-doctor` を申請前にブラッシュアップするための要件定義です。

目的は単なる申請用の装飾ではありません。

`repo-health-doctor` を **AI生成差分を受け入れるOSS maintainer向けの local-first preflight gate** として整えます。

人間のmaintainerが使えること。
Codexなどのcoding agentが安全に使えること。
CIが機械的に判定できること。
contributorが安全にrule追加やfalse positive修正を出せること。

この4つを同時に満たすrepoを目指します。

### 0.1 v0.2で反映したレビュー観点

Claudeレビューの必須修正を反映します。

- redaction contractの最低定義を追加
- public-safety用語をmaintainer-configurable patternに限定
- AGENTS.mdとdocs/agent-guide.mdの境界を明確化
- fixture setの最低構成を追加
- rule追加時のmaintainer merge判断基準を追加
- project-pitchの申請後の扱いを追加
- docs過多リスクを抑えるため、詳細docsは既存docs拡張を優先

### 0.2 v0.3で反映したレビュー観点

Claudeのv0.2レビューを反映します。

- Definition of DoneにAGENTS.mdの200行以内確認を追加
- tests/fixtures/以下を先にinspectする作業順を明記
- policy由来値の表現をallow対象の生の値へ限定
- redaction変更時の後方互換性説明は変更PR descriptionへ書くと明記
- Documentation Architectureに新規 / 既存拡張 / 確認のみの分類を追加
- CONTRIBUTING.mdは概要とpointer中心にし、詳細docsへ委譲する方針を追加
- docs/project-pitch.mdは申請後に統合または削除し、長期保守対象にしない方針へ寄せる
- README英語案と申請draftのpublic-safety表現をpre-publish寄りに調整

---

## 1. 100点の定義

このrepoの100点は以下です。

> repo-health-doctor は、AI patchやAI生成差分を受け入れるmaintainerが repo を公開・共有・自動化へ渡す前に使う local-first preflight gate である。

100点状態では以下が成立します。

| 観点 | 成立条件 |
| --- | --- |
| Maintainer-ready | maintainerがAI生成差分を受け入れるか、公開前に止めるか判断できる |
| Agent-ready | Codexなどのagentが安全境界と検証手順を理解できる |
| Safety-ready | raw secretや内部値を出さない境界が明文化されている |
| Evaluation-ready | rule変更やdocs変更をtests / fixtures / golden / smokeで確認できる |
| Community-ready | CONTRIBUTING / SECURITY / CODE_OF_CONDUCT / issue templateがある |
| Automation-ready | JSON schema / rule_id / severity / exit codeでCIやagentが扱える |

---

## 2. Product Positioning

### 2.1 使う言葉

- local-first preflight gate
- maintainer-ready
- agent-ready
- public-safety check
- redacted JSON output
- publish-or-hold decision
- AI-generated repository changes
- AI patch review
- fixture-backed regression checks

### 2.2 避ける言葉

- complete secret scanner
- vulnerability scanner
- DLP
- security platform
- license compliance tool
- legal checker
- AI agent framework

このtoolはsecurity製品ではありません。
公開前に止めるべき明らかな混入や欠落を短時間で見つけるpreflight gateです。

---

## 3. Primary Users

### 3.1 Primary users

- AI生成差分を受け入れるOSS maintainer
- Codexなどが作ったpatchをレビューするmaintainer
- 個人開発者
- 小規模OSS maintainer

### 3.2 Secondary users

- Codexなどのcoding agent
- CI / automation
- rule追加を行うcontributor
- false positiveを報告する利用者

---

## 4. Core Jobs

このrepoが解く仕事は5つです。

1. maintainerがAI生成差分を受け入れてよいか、公開前に止めるべきか判断する
2. agentがrepo作業前後に安全確認できる
3. CIがPASS / WARN / BLOCKをexit codeとJSONで扱える
4. contributorがrule追加やfalse positive修正を安全に出せる
5. JSON schemaとredaction契約を壊さず保守できる

---

## 5. Required Capabilities

### 5.1 Repository health

- READMEの有無を確認する
- LICENSEの有無を確認する
- CI workflowの有無を確認する
- testsの有無を確認する
- docs / scriptsの有無を確認する

### 5.2 Public safety

- secretらしき文字列を検知する
- local pathを検知する
- local IPを検知する
- maintainer-configurable patternまたは既定の限定カテゴリに一致する公開前確認語句を検知する
- raw値をreportへ出さない

public-safety checkは一般的なコンテンツポリシー判定ではありません。
このrepoで定義した限定カテゴリ、またはmaintainerが設定したpatternに対する公開前preflightです。

### 5.3 Redaction contract

redactionの最低契約は以下です。

- secret候補、token候補、private path、local IP、policy allow対象の生の値はtext / JSON reportにそのまま出さない
- reportには原則として `rule_id`、`severity`、repository相対path、行番号、サイズ、カテゴリ名などの中立情報だけを出す
- `redacted: true` はraw値を出力せず、カテゴリ化または固定マスクへ置換済みであることを示す
- debugging目的でもraw値を標準出力、JSON、CI artifact、issue templateへ出さない
- redaction方式を変更する場合はsecurity-modelとgolden outputを更新し、変更PRのdescriptionに後方互換性への影響を明記する

### 5.4 Artifact safety

- trackedされた生成物候補を検知する
- cache候補を検知する
- env file候補を検知する
- log / report / output混入を検知する

### 5.5 Policy

- policy fileを検証する
- allow / ignoreの形式を検証する
- 期限切れallowを検出する
- 未知のrule_idを検出する
- secret系allowは制限する

### 5.6 Automation

- human-readable text outputを出す
- machine-readable JSON outputを出す
- exit codeでgateできる
- schema_versionを持つ
- rule_idを安定させる
- severityを安定させる
- findingはredactedである

---

## 6. Agent-ready Requirements

### 6.1 AGENTS.md

repo rootに `AGENTS.md` を置きます。

AGENTS.mdは短い作業契約だけにします。
目安は200行以内です。
詳細な背景、task recipe、JSON reportの読み方は `docs/agent-guide.md` に逃がします。

AGENTS.mdの必須内容:

- このrepoはlocal-first preflight CLIである
- network callを追加しない
- raw secretを出さない
- redactionを弱めない
- schema_versionを勝手に変えない
- rule追加時はtests / fixtures / docsを更新する
- public-safety変更時はgolden outputを確認する
- generated reportsやlocal artifactsをcommitしない
- publish / release / external actionは人間承認なしで実行しない
- required verificationを列挙する

AGENTS.mdには長い思想説明や申請文を入れません。
Codexなどが最初に読む「守るべき契約」として扱います。

### 6.2 docs/agent-guide.md

agent-guideには以下をまとめます。

- agentがこのrepoでやってよい作業
- agentがやってはいけない作業
- pre-agent / post-agent / release前のgate
- JSON reportの読み方
- rule追加手順
- false positive修正手順
- 最終報告形式

### 6.3 Agent作業前後のgate

| Gate | Timing | Command | Stop condition |
| --- | --- | --- | --- |
| Pre-agent | agent作業前 | `repo-health-doctor . --fail-on block --public-safety` | BLOCK |
| Post-agent | agent作業後 | tests + public-safety | test fail / BLOCK |
| Policy-only | policy編集後 | `repo-health-doctor validate-policy .` | invalid policy |
| Release | 公開前 | `repo-health-doctor . --fail-on warn --public-safety` | WARN / BLOCK |
| Human review | 最後 | checklist | maintainer判断 |

---

## 7. Maintainer-ready Requirements

必要なcommunity health filesを置きます。

```text
CONTRIBUTING.md
SECURITY.md
CODE_OF_CONDUCT.md
.github/ISSUE_TEMPLATE/bug_report.yml
.github/ISSUE_TEMPLATE/rule_request.yml
.github/ISSUE_TEMPLATE/false_positive.yml
.github/ISSUE_TEMPLATE/docs_improvement.yml
.github/pull_request_template.md
```

### 7.1 CONTRIBUTING.md

CONTRIBUTING.mdは概要とpointer中心にします。
詳細なrule追加、policy運用、agent作業、評価手順は各docsへ委譲します。

含める内容:

- setup
- test
- public-safety check
- rule追加の流れ
- false positive報告の流れ
- security issueを公開issueに貼らない案内
- scope
- non-goals
- maintainerのmerge判断基準

### 7.2 Maintainer merge判断基準

rule追加、false positive修正、public-safety変更は以下を満たす場合にmerge候補とします。

- 目的と影響範囲が説明されている
- fixtureまたはgolden outputで変更理由を確認できる
- redaction contractを弱めていない
- schema互換性への影響が明記されている
- secretやprivate pathのraw値をPR本文、issue、test outputに含めていない
- required verificationが通っている
- docs/rules.mdまたは該当docsが更新されている

### 7.3 SECURITY.md

含める内容:

- supported versionsはmainまたはlatest release相当
- vulnerability疑いは公開issueに貼らない
- secret実値を貼らない
- reportには再現手順と影響範囲を書く
- SLAは明記しない。best-effortの対応方針に留める
- このtoolのsecret detectionは補助であり完全ではない

### 7.4 CODE_OF_CONDUCT.md

短い行動規範にします。
長大な全文コピーは避けます。

含める内容:

- respectful communication
- good faith review
- no harassment
- maintainer discretion
- report route

独自短縮版にする場合は、軽量な小規模OSS向け運用として採用していることを短く注記します。

---

## 8. Safety-ready Requirements

`docs/security-model.md` にまとめます。

### 8.1 守るもの

- raw secretをreportに出さない
- local pathを中立カテゴリにする
- local IPを中立カテゴリにする
- policy allow対象の生の値を出さない
- generated artifact混入を検知する
- network送信を前提にしない

### 8.2 守らないもの

このtoolは以下を検知・防止するものではありません。

- 完全なsecret scanning
- dependency vulnerability scan
- GitHub settings監査
- 法務的license判断
- malicious contributorの検知や防止
- enterprise DLPの代替

---

## 9. Evaluation-ready Requirements

`docs/evaluation-model.md` を置きます。

| Layer | Purpose |
| --- | --- |
| unit tests | CLI logicの回帰検知 |
| fixtures | 入力repoの代表例 |
| golden outputs | JSON / text契約のdrift検知 |
| smoke commands | READMEとCI導線の確認 |
| public-safety scan | 公開前block検知 |
| policy validation | allow / ignore運用の破損検知 |

### 9.1 最低限のfixture set

Codex実装時は、まず `tests/fixtures/` 以下をinspectし、既存fixtureで満たせるか確認します。

最低限、以下のfixtureまたは同等の既存fixtureを維持します。

- clean repo: README / LICENSE / tests / docs / CIが揃いPASSする代表例
- missing metadata repo: READMEまたはLICENSEなど基本file不足を再現する例
- secret-like repo: secret候補を含み、raw値を出さずにBLOCKできる例
- public-safety repo: private path、local IP、限定カテゴリpatternを検知する例
- tracked artifact repo: logs / outputs / cache / env file候補の混入を再現する例
- policy violation repo: invalid allow、expired allow、unknown rule_idなどを再現する例

既存fixtureで満たせる場合は新規作成しません。
足りない場合だけ最小fixtureを追加します。

### 9.2 Rule追加時のacceptance criteria

- stable rule_idを追加する
- severityの理由を説明する
- fixtureを追加または更新する
- testを追加または更新する
- docs/rules.mdを更新する
- redactionを維持する
- schema互換性を説明する
- verifyを成功させる
- maintainerがmerge判断できる差分説明を残す

---

## 10. Documentation Architecture

READMEは入口にします。
READMEに全部書きません。

| Doc | Role | Action |
| --- | --- | --- |
| `README.md` | 何のtoolか どう使うか | 既存拡張 |
| `docs/requirements.md` | 要件の正本 | 新規 |
| `docs/maintainer-guide.md` | maintainer運用 | 新規または既存docsへ統合 |
| `docs/agent-guide.md` | Codexなどagent向け | 新規 |
| `docs/rule-authoring.md` | rule追加手順 | 新規または既存rules docsへ統合 |
| `docs/policy-guide.md` | allow / ignore運用 | 既存 `docs/policy.md` があれば拡張。なければ新規 |
| `docs/security-model.md` | threat / redaction / boundary | 新規 |
| `docs/evaluation-model.md` | tests / fixtures / golden | 新規または既存test docsへ統合 |
| `docs/ci-integration.md` | GitHub Actions導入 | 新規またはREADME/CI docsへ統合 |
| `docs/project-pitch.md` | 申請文と価値説明 | 申請前のみ新規。申請後に統合または削除 |
| `docs/roadmap.md` | 今後の改善 | 新規 |
| `docs/architecture.md` | 既存設計方針 | 既存拡張 |
| `docs/rules.md` | rule_idとseverity契約 | 既存拡張 |
| `docs/release-checklist.md` | release前確認 | 既存拡張 |

重複説明は避けます。
正本は1箇所にします。
既存docsと競合する場合は新規追加ではなく既存docsを拡張します。

`docs/project-pitch.md` は申請前の価値説明とdraft置き場として使います。
申請後はREADMEまたはroadmapへ統合するか、削除します。原則として長期保守対象にはしません。

---

## 11. README Requirements

README冒頭は以下の意味に寄せます。

```text
repo-health-doctor is a local-first preflight gate for maintainers deciding whether to accept AI-generated repository changes.

It helps maintainers decide whether a repository is ready to share publish or hand to automation by checking basic repository health pre-publish signal checks tracked artifacts policy validity and redacted machine-readable output.
```

日本語説明では以下を中心にします。

```text
repo-health-doctor は、AI生成差分を受け入れるか判断するmaintainer向けのlocal-first preflight gateです。

repoを公開・共有・自動化へ渡す前に、README、LICENSE、CI、tests、pre-publish checks、tracked artifacts、policy validity、redacted JSON output を短時間で確認します。
```

READMEに追加する節:

- Who this helps
- What it checks
- Where it fits
- Maintainer and agent readiness
- Related docs

既存のQuickstart / Public Safety / JSON Output / Policy / CI / Redaction / What It Does Not Guaranteeは維持します。

---

## 12. CI Requirements

`.github/workflows/ci.yml` は維持します。

追加するもの:

```yaml
permissions:
  contents: read
```

CIで確認するもの:

- unittest
- help
- version
- normal check
- strict check
- public-safety check
- JSON output parse
- validate-policy

---

## 13. pyproject Requirements

`pyproject.toml` のmetadataを自然にします。

### 13.1 Author

現在のauthorが不自然な場合は以下へ寄せます。

```toml
authors = [
  {name = "repo-health-doctor contributors"}
]
```

### 13.2 Keywords

候補:

- repository
- cli
- preflight
- ci
- oss
- maintainer
- public-safety
- repository-health

`security platform` や `complete secret scanner` に見えるkeywordは避けます。

---

## 14. Project Pitch Requirements

`docs/project-pitch.md` を置きます。

含める内容:

- one sentence
- problem
- who it helps
- current capabilities
- why Codex helps
- non-claims
- Japanese application draft under 500 chars
- English application draft under 500 chars
- 申請後にREADMEまたはroadmapへ統合する方針

### 14.1 Japanese draft candidate

```text
repo-health-doctorは、AI生成差分を受け入れるOSS maintainer向けのlocal-first preflight gateです。README、LICENSE、CI、tests、公開前チェックpattern、secretらしき文字列、tracked artifacts、policy validityを確認し、redacted JSONとPASS/WARN/BLOCKで公開前判断を支援します。具体的な作業として、rule追加、fixture/golden整備、false positive改善、docs同期、schema互換性確認をCodexに任せる想定です。
```

### 14.2 English draft candidate

```text
repo-health-doctor is a local-first preflight gate for maintainers reviewing AI-generated repository changes. It checks basic repo health, pre-publish safety signals, secret-like patterns, tracked artifacts, policy validity, and redacted JSON output so maintainers can make publish-or-hold decisions. Codex would help expand rules, fixtures, golden cases, docs, and schema-compatible improvements in small safe changes.
```

---

## 15. Non-goals

今回やらないこと:

- CLI挙動の大幅変更
- rule追加
- schema version変更
- PyPI公開
- release workflow追加
- CodeQL追加
- Dependabot追加
- GitHub settings変更
- PR作成
- branch作成

---

## 16. Definition of Done

この要件定義に基づくブラッシュアップは以下を満たしたら完了です。

- README冒頭が新しいpositioningになっている
- `docs/requirements.md` がある
- `AGENTS.md` がある
- `AGENTS.md` が200行以内である
- community health filesがある
- issue templatesとPR templateがある
- maintainer / agent / safety / evaluation docsがそろっている
- CI permissionsがread-only化されている
- pyproject metadataが自然になっている
- 既存verifyが通る
- docsリンクが破綻していない
- redaction contractがdocs/security-model.mdとtestsで確認できる
- `tests/fixtures/` 以下を先にinspectし、既存fixtureで満たせるものは再利用している
- fixture setの最低構成が既存fixtureまたは追加fixtureで満たされている
- commit済み
- push済み
- PRは作っていない

---

## 17. Required Verification

最低限これを実行します。

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m repo_health_doctor --help
PYTHONPATH=src python3 -m repo_health_doctor --version
PYTHONPATH=src python3 -m repo_health_doctor . --fail-on block --public-safety
PYTHONPATH=src python3 -m repo_health_doctor validate-policy .
PYTHONPATH=src python3 -m repo_health_doctor . --public-safety --format json --output /tmp/repo-health-doctor-result.json
python3 -m json.tool /tmp/repo-health-doctor-result.json >/dev/null
wc -l AGENTS.md
```

packaging確認が可能なら追加します。

```bash
python3 -m pip install -e .
repo-health-doctor --version
repo-health-doctor . --fail-on block --public-safety
repo-health-doctor validate-policy .
```

---

## 18. Review Questions

外部レビューでは以下を確認してもらいます。

1. 主語が明確か
2. AI生成差分を受け入れるmaintainer向けの価値が伝わるか
3. agent-ready layerが過剰ではないか
4. docsが増えすぎていないか
5. existing docsと責務が重複していないか
6. security toolとして過剰主張していないか
7. Codex申請文として自然か
8. 実装範囲が申請前として適切か
9. non-goalsが十分に明確か
10. redaction contractとfixture setが実装指示として十分か
