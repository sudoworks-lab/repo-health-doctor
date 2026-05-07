# Architecture

## 設計方針

`repo-health-doctor` は、意図的に小さく、決定的で、local-first な CLI として設計しています。

- 深い解析よりも、速い repository hygiene check を優先する
- 人間向け text と automation 向け JSON の両方を同じ report から生成する
- AI 作業や CI の前段で使えるよう、network 依存を持ち込まない
- 小さな Python 実装のまま読めて、拡張しやすい状態を保つ

## repo 診断の考え方

現在の実装は、local repository を走査してコンパクトな health signal を返します。

検査対象:

- `README` の有無
- `LICENSE` の有無
- `.gitignore` の有無
- `tests` / `test` directory の有無
- `docs` / `doc` directory の有無
- `scripts` / `script` / `bin` directory の有無
- テキスト寄りファイルに対する簡易 secret-like pattern scan
- 閾値以上の large file

各結果は `pass` / `warn` / `fail` に集約され、text または JSON として出力されます。

## 何を検知するか

この tool が狙っているのは、公開や共有の前段で見落としやすい基礎的な問題です。

- 主要ドキュメントや housekeeping file の欠落
- tests や docs directory が見当たらない状態
- テキストファイル中の明らかな secret らしき文字列
- source repository としては大きすぎる可能性がある file

## 何を検知しないか

意図的に、次のものまでは扱いません。

- dependency vulnerability scanner
- license compliance tool
- linter / formatter / type checker の実行基盤
- enterprise 向け DLP や高度な secret scanning 製品
- GitHub settings auditor
- architecture や domain semantics を評価する品質スコアラ

この境界を明示する理由は、README が実装以上のことを約束し始めると、公開 repository としての信頼性が下がるためです。

## AI 作業前 preflight としての位置づけ

`repo-health-doctor` は、AI 支援作業の前に実行する軽量 preflight として使うのが自然です。

典型的な流れ:

1. local で health check を走らせる
2. obvious な warning / fail を確認する
3. Codex、CI、その他 automation に repository を渡す

Codex preflight や local run logging のような周辺 workflow と補完関係にはありますが、直接結合はしていません。契約はシンプルで、「path を inspect して、短い report を返し、local に留まる」ことです。

## 出力形式の考え方

同じ report を 2 つの形式で描画します。

- terminal で読みやすい text
- script や CI artifact で扱いやすい JSON

JSON には per-check details を含めているため、呼び出し側が独自の gating や annotation を実装できます。

## Privacy / Safety

- scan は local-only
- binary file は secret scan から除外
- text scan は小さめの file と件数上限に制限
- `--secrets-ignore` で ignore prefix を追加可能

これにより、生成物 directory を過剰に走査しにくくしつつ、挙動を予測しやすくしています。

## 将来拡張候補

現設計の延長で自然なのは次の方向です。

- ignore rule の外部設定化
- secret heuristic の改善と false positive の扱い強化
- CI presence、formatting、metadata completeness などの optional check
- pipeline integration 向けの機械可読な exit reason summary
