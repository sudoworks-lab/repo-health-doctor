# Architecture

## 設計方針

`repo-health-doctor` は、意図的に小さく、決定的で、local-first な CLI として設計しています。

- 深い解析よりも、速い repository hygiene check を優先する
- 人間向け text と automation 向け JSON の両方を同じ report から生成する
- CI や automation の前段で使えるよう、network 依存を持ち込まない
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

各結果は `pass` / `warn` / `block` に集約され、text または JSON として出力されます。

`--public-safety` を有効にすると、通常診断に加えて公開前向けの追加チェックを走らせます。
`validate-policy` は scan を実行せず、policy file の形式と期限、rule_id、allow 制約だけを検証します。

## 何を検知するか

この tool が狙っているのは、公開や共有の前段で見落としやすい基礎的な問題です。

- 主要ドキュメントや housekeeping file の欠落
- tests や docs directory が見当たらない状態
- テキストファイル中の明らかな secret らしき文字列
- source repository としては大きすぎる可能性がある file
- 公開本文に不向きな語、個人 path、local IP の混入
- tracked な生成物 / log / cache / 環境 file 候補

## 何を検知しないか

意図的に、次のものまでは扱いません。

- dependency vulnerability scanner
- license compliance tool
- linter / formatter / type checker の実行基盤
- enterprise 向け DLP や高度な secret scanning 製品
- GitHub settings auditor
- architecture や domain semantics を判定する品質スコアラ

この境界を明示する理由は、README が実装以上のことを約束し始めると、公開 repository としての信頼性が下がるためです。

## 公開・共有前 preflight としての位置づけ

`repo-health-doctor` は、公開・共有前に実行する軽量 preflight として使うのが自然です。

典型的な流れ:

1. local で health check を走らせる
2. obvious な warning / block を確認する
3. CI やその他 automation に repository を渡す

周辺 workflow と補完関係にはありますが、直接結合はしていません。契約はシンプルで、「path を inspect して、短い report を返し、local に留まる」ことです。

## 出力形式の考え方

同じ report を 2 つの形式で描画します。

- terminal で読みやすい text
- script や CI artifact で扱いやすい JSON

JSON には `schema_version` と per-check details を含めているため、呼び出し側が独自の gating や annotation を実装できます。
finding が出る場合は `rule_id` と `severity` を含め、検知値そのものではなく中立カテゴリを返します。
policy が適用された finding には safe な policy id と source だけを付与し、policy file 内の具体値は返しません。
`schema_version: 1.1` は Phase2 系の公開安全 report 契約として維持します。

## Exit Policy

- `pass`: exit code `0`
- `warn`: デフォルトでは exit code `0`、`--fail-on warn` または `--strict` では exit code `1`
- `block`: 常に exit code `1`

CI の公開前 gate では、段階導入なら `--fail-on block`、warning も止めるなら `--fail-on warn` を使います。

## Privacy / Safety

- scan は local-only
- binary file は secret scan から除外
- text scan は小さめの file と件数上限に制限
- `--secrets-ignore` で ignore prefix を追加可能
- `--public-safety` の text check は、可能なら tracked file に対象を絞ります
- `--public-safety` は raw の検知文字列ではなく、中立カテゴリで結果を返します
- finding は `rule_id`, `severity`, repository 相対 path, category を返し、raw の検知値は返しません
- policy は scan 除外と finding 例外を分けて扱い、local policy の具体値を report に出しません

これにより、生成物 directory を過剰に走査しにくくしつつ、挙動を予測しやすくしています。

## 将来拡張候補

現設計の延長で自然なのは次の方向です。

- ignore rule の外部設定化
- secret heuristic の改善と false positive の扱い強化
- CI presence、formatting、metadata completeness などの optional check
- pipeline integration 向けの機械可読な exit reason summary
