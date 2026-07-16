# Cursor Binding

- verified-as-of: 2026-07-16 JST
- offline evidence: [Human提供の公式source packet](human-review/agent-binding-official-sources.md)
- official sources:
  - [Cursor Rules](https://cursor.com/docs/rules)
  - [Cursor Hooks](https://cursor.com/docs/hooks)
  - [Cursor CLI](https://cursor.com/docs/cli/overview)

この文書は、上記packetをofflineで参照して作成した。作成時にnetwork access、
account設定変更、Cursor設定変更は行っていない。verified-as-of以後の公式仕様変更には
自動追随しない。

## 確認済み事項

- Cursorには公式のRules documentation pageが存在する。
- Cursorには公式のHooks documentation pageが存在する。
- Cursorには公式のCLI documentation pageが存在する。

source packetで確認済みなのは、上記3つの公式pageの存在までである。各surfaceの強制契約は
確認済み事項へ昇格させない。

## Binding guidance

[AI Agent Canonical Contract](agent-contract.md)をCursor向けinstructionとして提示できるが、
Rules、Hooks、CLIのいずれがその契約を技術的に強制できるかは、このpacketでは確認していない。
未確認のhook設定例やdecision処理を作らず、accountまたはtool設定も変更しない。

## 未確認事項

- hook event名。
- decision schema。
- exit codeによるblock契約。
- project ruleだけでcommand実行を技術的に停止できるか。
- non-interactive CLIでの強制契約。

## Instruction-based limitation

確認済みの強制機構をこのpacketから示せないため、Cursor bindingはinstruction-based limitation
として扱う。Rules、Hooks、CLI pageが存在することを、command blockや特定のexit semanticsが
利用可能である証拠へ読み替えてはならない。強制契約が公式sourceとHuman reviewで別途確認
されるまでは、Human control、exact authorization、sandbox境界を省略しない。
