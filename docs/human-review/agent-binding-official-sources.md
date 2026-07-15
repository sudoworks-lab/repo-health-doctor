# AI agent binding official-source evidence

- verified_at: 2026-07-16 JST
- prepared_as: Human review input assisted by official-source research
- purpose: F032のoffline入力
- network_contract: Goal Loop iteration中はnetwork accessを行わない
- limitation: このpacketで確認済みと記録していない仕様は未確認として扱う

## Codex

Official source:

https://developers.openai.com/codex/guides/agents-md

Confirmed facts:

- Codexは作業開始前にAGENTS.md系のinstructionを読み込む。
- global scopeとproject scopeからinstruction chainを構成する。
- project rootからcurrent directoryへ向かってinstructionを読み込む。
- current directoryに近いinstructionが後段に結合される。
- AGENTS.mdはinstruction surfaceである。
- このpacketではAGENTS.md単体をcommand実行前の強制hookとは確認していない。

Binding requirement:

- docs/integration-codex.mdではAGENTS.mdによるinstruction-based運用として記述する。
- 未確認の強制hookを存在するものとして記述しない。

## Claude Code

Official source:

https://code.claude.com/docs/en/hooks

Confirmed facts:

- PreToolUseはtool parameter作成後、tool call処理前に実行される。
- PreToolUseはallow、deny、ask、deferのdecisionを扱える。
- command hookのexit 2はblocking errorである。
- PreToolUseにおけるexit 2はtool callをblockする。
- 多くのhook eventではexit 1はnon-blocking errorである。
- structured decisionを返す場合はexit 0とJSON outputを使用する。

Binding requirement:

- docs/integration-claude-code.mdではPreToolUseを強制surface候補として扱える。
- exit 1をblocking errorとして説明しない。
- eventごとのexit behavior差異を明記する。
- accountやtool設定の変更はHuman review対象とする。

## Cursor

Official sources:

https://cursor.com/docs/rules

https://cursor.com/docs/hooks

https://cursor.com/docs/cli/overview

Confirmed facts:

- Cursorには公式のRules documentation pageが存在する。
- Cursorには公式のHooks documentation pageが存在する。
- Cursorには公式のCLI documentation pageが存在する。

Unconfirmed:

- hook event名
- decision schema
- exit codeによるblock契約
- project ruleだけでcommand実行を技術的に停止できるか
- non-interactive CLIでの強制契約

Binding requirement:

- docs/integration-cursor.mdでは公式source URLと確認日を記録する。
- 強制契約の詳細は未確認と明記する。
- 未確認のhook、decision schema、exit semanticsを推測で補完しない。
- 確認済みの強制機構が示せない場合はinstruction-based limitationとして扱う。
