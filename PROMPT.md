# Goal Loop 実行プロンプト(1 process / 1 feature)

あなたはrunnerが明示した1件のbounded featureだけを担当する。feature選択と次のiterationの起動は外部runnerの責務である。以下の手順を上から順に、省略せず実行すること。

Goal Loop write iterationはmain agentだけで実行し、Ultraを既定にしない。model / reasoning effortはrunnerを起動する環境の明示設定に従い、このprocess内で変更しない。

## 1. 開始儀式(get up to speed)

1. `pwd` で作業ディレクトリを確認する。
2. `git status --short` を実行して参考確認する。pre-existing dirtyの正本はhost runnerがiteration開始前に保存し、`GOAL_LOOP_PREEXISTING_DIRTY`で示すsnapshotである。
3. docs/STATUS.md を読み、直近のエントリから前回までの状況を把握する。
4. docs/PLAN.md と docs/features.json を読む。
5. `git log --oneline -20` で直近の作業履歴を確認する。
6. scripts/init.sh があれば実行し、環境を起動する。
7. スモークテスト: PLAN.md の「基本検証」に記載のコマンドを実行する。壊れていたら、新規作業に入らずまず修理する(stop-and-fix)。修理した場合もSTATUS.mdに記録する。

## 2. 指定タスクの確認

- prompt冒頭の `Runner-assigned bounded feature` にあるfeature IDを確認する。
- featureを自分で再選択しない。指定feature以外へ着手しない。

## 3. 実装

- 指定された1件を、PLAN.md の該当マイルストーンのスコープ内で実装する。
- diff を必要以上に広げない。無関係なリファクタリングをしない。

## 4. 検証

- PLAN.md 該当マイルストーンの検証コマンドをすべて実行する。
- features.json の該当項目の `steps` を実際に実行して確認する。
- 失敗したら直し、直るまで次の手順に進まない。
- **すべて通った場合のみ**、features.json の該当項目を `"passes": true` にし、`"verified_at"` に日時(JST)を記録する。
- 実行した検証コマンドとその結果、および指定featureの状態を応答テキストに要約する。

## 5. 記録(クリーンな終了)

1. docs/STATUS.md の末尾に追記する(フォーマットはSTATUS.md冒頭の定義に従う):
   - 今回やったこと / 検証結果 / 下した判断とその理由 / 既知の問題 / follow-up候補
2. `git status --short` を確認し、今回変更したファイルだけを特定する。pre-existing dirtyは変更対象にもcommit requestにも含めない。
3. 改行を含まない説明的な日本語commit messageを決める。
4. `GOAL_LOOP_COMMIT_REQUEST`が空でないことを確認し、そのパスへ次のschemaのJSONを書く。

```json
{
  "message": "何をなぜ変えたか分かる日本語commit message",
  "paths": [
    "relative/path/to/changed-file"
  ]
}
```

5. `paths`には今回変更・作成したrepo相対pathだけを重複なく列挙する。通常は実装ファイルに加えて docs/STATUS.md と、状態を更新した場合の docs/features.json を含める。
6. pre-existing dirty、request外の変更、logs/、local-fixtures/、diagnostics/、artifacts/、cache/、history/、secret、個人情報、音声ファイル、ignore対象をrequestへ含めない。
7. `python3 -m json.tool "$GOAL_LOOP_COMMIT_REQUEST"`でJSON構文を確認する。agentは `git add` / `git commit` / `git reset` / `git checkout` / `git stash` を実行しない。stageとcommitはagent終了後にhost runnerが行う。

## 6. Process終了

- 指定featureの実装・検証・evidence記録・状態更新が終わった時点で、未完了の別featureが残っていても最終報告を出してprocessを終了する。
- 別featureを選ばない。同じparent turnを維持しない。次のfeatureは外部runnerが新しいprocessで開始する。
- `<promise>ALL_FEATURES_PASS</promise>` を含む終了promiseは不要である。全feature完了の最終判定はhost runnerが`docs/features.json`の実状態から行うため、その判定のために別featureを実装してはならない。

## 7. スタックプロトコル

- このprocess内では指定featureについて原因調査、最小修正、再検証を行う。
- 解消できない場合は、試行内容・失敗理由・原因仮説をSTATUS.mdと最終報告に記録し、processを終了する。別featureへ移らない。
- runnerがattempt上限を管理する。agent自身が親turn内でretry loopやGoal Loopを作らない。
- 人間の入力が必要なら指定featureを `"blocked": true` にして、理由と必要な入力をSTATUSへ記録して終了する。ほかに`"passes": false`かつ`"blocked": false`のfeatureが残る場合、これはプロジェクト全体のblocked状態ではない。未完了featureの全件がblockedになった場合だけグローバルblockedであり、その最終判定はhost runnerが`docs/features.json`から行う。終了promiseは不要である。
