# Maintainer System Roadmap

`repo-health-doctor` を単発 CLI から maintainer preflight system へ育てるための段階設計です。
ここでいう system は hosted service ではなく、local-first な CLI、policy、report、agent gate、CI 導線をまとめて maintainer が運用できる形を指します。

## Current State

現状の `repo-health-doctor` は local-first single-repo preflight CLI です。
対象は主に 1 repository の checkout で、maintainer が公開・共有・automation へ渡す前に short-lived な preflight を行います。

## Target State

目標は、single-repo scan に留まらず次を一貫して扱える maintainer system です。

- preflight
- policy
- reports
- agent gates
- CI
- multi-repo review

これは deep security scanner ではなく、maintainer が publish-or-hold decision を安定して行うための local-first operating surface です。

## Principles

- local-first
- redacted by default
- deterministic JSON
- agent-safe
- fixture-backed
- honest boundaries

各 phase で機能を増やしても、この原則は変えません。特に raw 値を出さないこと、JSON 契約を安定させること、fixture と golden で回帰を追えることを優先します。

## Phase 1: Current Single-Repo CLI

Phase 1 は現在地です。

- 1 repository に対する preflight CLI
- README、LICENSE、tests、docs、scripts、CI などの基本 hygiene check
- `--public-safety` による redacted safety checks
- `validate-policy` による policy validation
- text / JSON report
- fixture-backed regression coverage

この phase の責務は、single-repo の publish-or-hold decision を安定させることです。

## Phase 2: Maintainer Workflow Integration

Phase 2 では CLI を maintainer の日常作業へ結び付けます。

- maintainer guide、release checklist、review recipe の整備
- review 前後で使う標準 command set の固定化
- policy ownership、expiry、exception handling の運用導線整理
- CI での text / JSON / Markdown gate の扱いの明確化
- docs と tests を揃えた rule change workflow の定着

狙いは、tool 単体ではなく maintainer workflow の一部として再現性を持たせることです。

### Phase 2A Completion Candidates

- `--format markdown` / `--format md` による maintainer-readable report を追加する
- `--output` を使って CI artifact と GitHub Step Summary へ同じ Markdown report を渡せるようにする
- text / JSON 契約を維持したまま report consumption を改善する

## Phase 3: Multi-Repo Maintainer Kit

Phase 3 では single-repo CLI を複数 repository を見る maintainer 向けに広げます。

- 複数 repo へ同じ preflight contract を適用できる運用 kit
- repo ごとの差分を残しつつ共通 policy baseline を扱える構造
- batch review でも redaction と deterministic JSON を維持する report 形式
- small-OSS maintainer が local で回せる multi-repo review flow

この phase でも network call や hosted control plane は前提にしません。

## Phase 4: Agent Workflow Integration

Phase 4 では agent が安全に組み込まれる前提を強化します。

- pre-agent / post-agent / release gate の標準化
- agent-readable docs と concise repo contract の分離
- rule change、policy edit、false positive fix に対する agent-safe workflow
- automatic continuation 前の hazard check など、agent loop 向け guardrail の整理
- maintainer review に返す report shape の統一

目的は autonomy を増やすことではなく、agent work を maintainer が安全に査読できる形へ寄せることです。

## Phase 5: Reports And Dashboard

Phase 5 では report consumption を改善します。

- deterministic JSON を起点にした report aggregation
- trend や recurring findings を見る軽量 dashboard
- maintainer review に必要な summary view
- raw 値を出さない filtered export surface
- local artifact として扱える report bundle

dashboard は analysis aid であり、判定根拠を隠す black box にしません。

## Non-Goals

次はこの project の非目標です。

- vulnerability scanner
- complete secret scanner
- DLP
- legal compliance
- hosted SaaS
- automatic publish

これらを名乗らないことで、tool の境界と期待値を正直に保ちます。

## Near-Term Issue Candidates

- maintainer workflow を phase 単位で説明する overview doc を追加する
- review 開始前と終了後の標準 command set を 1 か所に整理する
- `validate-policy` の運用例を maintainer guide に追加する
- JSON report の field contract を docs で明文化する
- policy expiry review の fixture と test coverage を広げる
- false positive 修正手順を fixture 再利用前提で整理する
- multi-repo review を見据えた report naming 方針を決める
- CI 用の最小 gate profile と release 前 gate profile を切り分ける
- agent report template を docs に追加する
- roadmap と non-goals を README から辿りやすくする
