# Codex Binding

- verified-as-of: 2026-07-16 JST
- offline evidence: [Human提供の公式source packet](human-review/agent-binding-official-sources.md)
- official source: [AGENTS.md guide](https://developers.openai.com/codex/guides/agents-md)

この文書は、上記packetをofflineで参照して作成した。作成時にnetwork access、
account設定変更、Codex設定変更は行っていない。verified-as-of以後の公式仕様変更には
自動追随しない。

## 確認済み事項

- Codexは作業開始前にAGENTS.md系のinstructionを読み込む。
- global scopeとproject scopeからinstruction chainを構成する。
- project rootからcurrent directoryへ向かってinstructionを読み込む。
- current directoryに近いinstructionが後段に結合される。
- AGENTS.mdはinstruction surfaceである。
- source packetでは、AGENTS.md単体をcommand実行前の強制hookとは確認していない。

## Binding guidance

repository固有のAGENTS.mdには、[AI Agent Canonical Contract](agent-contract.md)を
緩和しないinstructionを置く。たとえば、repository由来commandをhostで直接実行せず、
必要なrepo-health-doctor commandがexit 0になった場合だけ次の定義済み段階へ進み、
Human-controlled authorizationを伴う`sandbox-run`だけを実行surfaceにする。

これはinstructionの記述例であり、この文書はAGENTS.md、Codex設定、account設定を変更しない。

## 未確認事項

- AGENTS.md instructionをcommand実行前に必ず停止させる強制hookの有無。
- tool callをallowまたはblockするdecision schema。
- 強制surfaceに固有のexit code semantics。
- 対象環境でどのglobal instructionまたはproject instructionが実際に有効か。

## Instruction-based limitation

このsource packetで確認できるCodex bindingはAGENTS.mdによるinstruction-based運用である。
packetで確認済みのcommand実行前の強制機構はないため、AGENTS.mdだけではagentがinstructionを
逸脱した時にtool callを技術的に停止できるとは扱わない。外部のHuman control、exact
authorization、sandbox境界を省略してはならない。
