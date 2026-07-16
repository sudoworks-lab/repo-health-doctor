# Claude Code Binding

- verified-as-of: 2026-07-16 JST
- offline evidence: [Human提供の公式source packet](human-review/agent-binding-official-sources.md)
- official source: [Claude Code hooks](https://code.claude.com/docs/en/hooks)

この文書は、上記packetをofflineで参照して作成した。作成時にnetwork access、
account設定変更、Claude Code設定変更は行っていない。verified-as-of以後の公式仕様変更には
自動追随しない。

Start with the plan-only AI agent demo in
[ai-agent-preflight.md](ai-agent-preflight.md). It never executes the target command.

## 確認済み事項

- `PreToolUse`はtool parameter作成後、tool call処理前に実行される。
- `PreToolUse`は`allow`、`deny`、`ask`、`defer`のdecisionを扱える。
- command hookのexit 2はblocking errorである。
- `PreToolUse`におけるexit 2はtool callをblockする。
- 多くのhook eventではexit 1はnon-blocking errorである。
- structured decisionを返す場合はexit 0とJSON outputを使用する。

## Project-Local PreToolUse Sketch

`PreToolUse`は、[AI Agent Canonical Contract](agent-contract.md)をcommand実行前に確認する
強制surfaceの候補として扱える。ただし、この文書はhook設定例をinstallせず、accountまたは
tool設定を変更しない。実際の設定内容と適用範囲は、公式sourceを再確認したうえでHumanが
別途reviewする。Do not change global Claude Code configuration as part of this offline binding work.

hookを設計する場合、exit 2だけをpacketで確認済みのblocking errorとして扱う。exit 1を
blockとして利用しない。structured decisionを使う場合はexit 0とJSON outputを使用し、
eventごとにexit behaviorが異なる境界を維持する。

## 未確認事項

- 対象環境で`PreToolUse` hookが設定済みまたは有効であるか。
- accountまたはprojectごとのhook設定の正確な配置と設定schema。
- packetに個別記載されていない各hook eventのexit behavior。
- structured decision JSONの完全なfield schema。

## Instruction-based limitation

`PreToolUse`はpacketで確認済みの強制surface候補だが、このrepositoryはhookやtool設定を
自動構成しない。Humanが設定をreviewして有効化し、そのblock動作を確認するまでは、文書や
CLAUDE.mdだけの運用はinstruction-based limitationを持ち、tool callの技術的な停止を保証しない。
