# キックオフ(initializer)プロンプト — 初回に1度だけ実行

あなたはこのプロジェクトのGoal loopの初期化(initializer)を担当する。**実装はまだ始めないこと。** 以下を順に実行する。

## 1. specの読み込み

- 初期化前に `git status --short` を参考確認する。pre-existing dirtyの正本はhost runnerが開始前に保存し、`GOAL_LOOP_PREEXISTING_DIRTY`で示すsnapshotである。KICKOFF runnerは初期化済みGit repoで実行する。
- 導入先に既存の `AGENTS.md` / `CLAUDE.md` / `.gitignore` / `PROMPT.md` がある場合は上書きせず、人間にマージ判断を求める。
- docs/GOAL.md を読む。不明点・曖昧な点があれば、作業を始める前に箇条書きで質問し、回答を待つこと(曖昧なまま計画を作らない)。

## 2. features.json の生成

- GOAL.md の要件を、検証可能な機能単位に展開して docs/features.json を生成する。
- 各項目のフォーマットは既存の docs/features.json の `_format` 定義に従う。
- description は「〜できる」「〜が存在する」のような検証可能な文にする。「良い」「使いやすい」のような主観語は使わない。
- steps には検証の具体手順(実行するコマンド、確認する内容)を書く。
- 全項目 `"passes": false` で初期化する。
- 主観評価が必要な要件は features.json に入れず、PLAN.md の「人間レビュー項目」に分離する。

## 3. PLAN.md の生成

- docs/PLAN.md のテンプレート構造に従い、以下を書く:
  - マイルストーン一覧。各マイルストーンは**ループ1周(1セッション)で完了する粒度**まで分割する
  - 各マイルストーンの受け入れ基準と、実行可能な検証コマンド
  - 基本検証(毎周のスモークテストで回すコマンド)
  - 想定アーキテクチャ・技術選定とその理由

## 4. init.sh の生成

- 環境のセットアップ・起動・基本検証を1コマンドで行える scripts/init.sh を書く。
- 依存のインストール、サーバやツールの起動、基本検証の実行を含める。

## 5. 初期化の完了

1. docs/STATUS.md に初回エントリを追記する(生成したマイルストーン数・features件数・最初に着手すべき項目を記録)。
2. `git status --short` で生成・更新したファイルを確認し、pre-existing dirtyを除外する。
3. `GOAL_LOOP_COMMIT_REQUEST`が空でないことを確認し、次のschemaでcommit request JSONを書く。

```json
{
  "message": "chore: Goal loop環境を初期化",
  "paths": [
    "docs/PLAN.md",
    "docs/STATUS.md",
    "docs/features.json",
    "scripts/init.sh"
  ]
}
```

4. `paths`は今回生成・更新したrepo相対pathに合わせる。pre-existing dirty、request外の変更、logs/、local-fixtures/、diagnostics/、artifacts/、cache/、history/、secret、個人情報、音声ファイル、ignore対象を含めない。
5. `python3 -m json.tool "$GOAL_LOOP_COMMIT_REQUEST"`でJSON構文を確認する。agentは `git add` / `git commit` / `git reset` / `git checkout` / `git stash` を実行しない。stageと初期化commitはagent終了後にhost runnerが行う。
6. 生成した PLAN.md と features.json の要約を提示し、人間のレビューを求めて終了する。**レビュー承認前に実装ループを開始しないこと。**
