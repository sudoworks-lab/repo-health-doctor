# AI Agent Canonical Contract

この文書は、未知のrepositoryに由来するcommandをAI agentが扱う時の正準契約である。
agent固有のbindingはこの契約を参照し、この契約より実行条件を緩めてはならない。
この文書自体はagent設定を変更せず、target commandを実行しない。

## Normative rules

1. repositoryに由来するcommandをhostで直接実行してはならない。
2. real scannerを使う正準flowでは、`real-scan`に`--fail-on-degraded`を必ず指定する。
3. 必須のrepo-health-doctor commandがすべてexit 0になった場合だけ、次の定義済み段階へ進める。
4. exit 1、exit 2、signal終了、またはその他のunknown exit codeでは停止する。retry、host実行、flag削除によって自動回避してはならない。
5. gate decisionはexecution authorizationではない。gate decisionの`execution_authorized`は`false`のままである。
6. 実行には、exact scope、argv、policy、gate decision、expiryを束縛したHuman-controlled authorizationが必要である。agentやrepository自身がHuman approvalを生成または代行してはならない。
7. bounded executionはCLI commandの`sandbox-run`だけで行い、元repository上またはhost fallbackで行ってはならない。
8. `sandbox-run`のJSON evidenceを次のgateへ`--sandbox-evidence`で明示的に還流する。
9. unknown、degraded、invalid、mismatch、stale、duplicate、truncated、over-budget、またはobserver不足はfail-closedで扱い、riskを下げる材料にしてはならない。

## Canonical flow

```text
real-scan --fail-on-degraded
  | exit 0 only
  v
gate-check --external-evidence ... -- <command>
  | authorizationがなければexit 2で停止し、Human reviewへ引き渡す
  v
Human review / Human-controlled authorization
  | exact scope、argv、policy、gate decision、expiryを承認
  v
gate-check --external-evidence ... --authorization ... --argv-json ...
  | exit 0 only
  v
sandbox-run --authorization ... -- <command>
  | evidence reportを成否にかかわらず保存し、exit 0 onlyで次段階へ進む
  v
gate-check --sandbox-evidence ... -- <next-command>
```

最初の`gate-check`はtarget commandを実行しない。authorizationがない時のexit 2は、
agentが次へ進んでよいという合図ではなく、実行を止めてgate decisionをHumanへ渡すための
fail-closedな結果である。Human-controlled authorizationの作成後、同じsubject、evidence、
policy、exact argvを使って`gate-check`を再実行し、その再実行がexit 0の場合だけ
`sandbox-run`へ進める。途中でrepositoryまたはargvが変わった場合は、以前の結果を再利用せず
real-scanからやり直す。

## Exit contract

| Exit | 正準解釈 | Agent action |
| --- | --- | --- |
| exit 0 | そのcommandが定義した処理を完了した。安全性の証明ではない。 | 次の定義済み段階へだけ進める。 |
| exit 1 | degraded scanner結果、tool failure、sandbox infrastructure failure、またはそのcommandが定義する非policy failureである。 | 停止する。原因とredacted evidenceをHumanへ渡す。 |
| exit 2 | gate、policy、authorization、usageのblock、または開始済みtarget command自身のexit 2である。 | 停止する。reportの`command_started`とstderr prefixで区別し、自動回避しない。 |
| unknown | 上記以外のexit code、signal終了、exit codeを取得できない状態である。 | 停止する。exit 0へ読み替えない。 |

`sandbox-run`がtarget commandを開始した場合は、そのcommandのexit codeを返す。したがって
target commandのexit 1、exit 2、またはその他のnonzeroも正準flowでは停止である。
policy blockのexit 2とtarget command自身のexit 2は同じ意味ではないが、どちらも自動継続を
許可しない。

## 1. Real scanner evidence

`real-scan`は明示的なevidence collectionであり、default scan、execution authorization、
または安全性の証明ではない。正準flowではJSON reportを保存し、必ず
`--fail-on-degraded`を指定する。

```bash
env PYTHONPATH=src python3 -m repo_health_doctor real-scan "$REVIEWED_REPO" \
  --fail-on-degraded \
  --format json \
  --output /tmp/rhd-real-scan.json
```

scanner unavailable、unsupported version、timeout、parse failure、offline skip、findingまたは
reportのtruncationなどでsuiteがdegradedならexit 1となり、そこで停止する。exit 0でも
scannerのcoverage、version、database、network/cache state、limitationsをHuman reviewから
省略してはならない。reportの`execution_authorized`は常に`false`である。

## 2. Gate and external evidence

real scanner reportは`gate-check --external-evidence`へ明示的に渡す。

```bash
env PYTHONPATH=src python3 -m repo_health_doctor gate-check "$REVIEWED_REPO" \
  --fail-on-gate unknown \
  --external-evidence /tmp/rhd-real-scan.json \
  --gate-decision-output /tmp/rhd-gate-decision.json \
  --format json \
  -- "$TARGET_COMMAND" "$TARGET_ARGUMENT"
```

`--external-evidence`はschema、canonical fingerprint、subject、age、size、duplicate、
truncationをboundedに検証する。invalid evidenceを黙ってskipせず、gate verdictを改善させない。
trailing argvは検証対象を示すだけであり、`gate-check`はtarget commandを実行しない。

authorizationなしの初回gateはexit 2で停止する。この結果からgate decisionを取得しても、
gate decision自体、`ALLOW_LIMITED`、scanner finding 0件のいずれも実行許可ではない。

## 3. Human-controlled authorization

authorization draftは`approved=false`のreview資料であり、Human approvalではない。
Humanはagentやreview対象repositoryから独立したcontrolで、少なくともexact argv、subject、
gate decision fingerprint、repository identity、commit、tree、`snapshot_id`、
manifest fingerprint、policy version、expiry、approver、approval時刻を確認する。
Humanだけが承認済みartifactを提供できる。

artifact discoveryはapprovalではない。発見されたartifactも既存validator、exact binding、
expiry、Verified Snapshot integrity、single-use reservationを迂回できない。
dirty/untracked Git treeまたはnon-Git subjectはreal executionへ進めない。
BLOCK、QUARANTINE、UNKNOWNは
authorizationで上書きできず、WARNはHumanによる明示的なrisk受容が必要である。

承認後のgateは明示artifactとexact argvを再検証する。

```bash
env PYTHONPATH=src python3 -m repo_health_doctor gate-check "$REVIEWED_REPO" \
  --fail-on-gate unknown \
  --external-evidence /tmp/rhd-real-scan.json \
  --authorization /tmp/rhd-human-authorization.json \
  --argv-json /tmp/rhd-target-argv.json \
  --format json
```

このcommandは、gate thresholdが許し、authorization validationが
`execution_authorized=true`になった時だけexit 0となる。gate decision単体の
`execution_authorized=false`契約は変わらない。

## 4. Authorized sandbox execution

target commandはhostへfallbackせず、validなHuman-controlled authorizationを指定した
`sandbox-run`で1回だけ実行する。

```bash
env PYTHONPATH=src python3 -m repo_health_doctor sandbox-run "$REVIEWED_REPO" \
  --profile locked-down \
  --fail-on-gate unknown \
  --authorization /tmp/rhd-sandbox-authorization.json \
  --evidence-output /tmp/rhd-sandbox-evidence.json \
  -- "$TARGET_COMMAND" "$TARGET_ARGUMENT"
```

authorizationはsandboxが生成するexact gate decisionとargvにも一致しなければならない。
external-evidence gate用artifactとsandbox内部gate用artifactは、gate decision fingerprintが
異なる場合には流用できない。その場合はHumanがsandboxのexact gateを別途reviewし、
それに束縛したartifactを提供する。agentがartifactを移植したり、evidenceを外して一致を
強制したりしてはならない。
一致しない場合はexit 2で停止し、別のexecution pathへfallbackしない。`sandbox-run`は
disposable workspace、`--pull=never`、default-deny network、locked-down profile、resource
limits、read-only `/workspace`、64 MiB/4096-inode tmpfs `/out`、bounded
streaming redacted outputを使う。real Docker imageはlocalに存在する
strict digest reference (`name@sha256:<64 lowercase hex>`)だけを受理する。
timeout、output budget超過、またはcontainer cleanup uncertaintyはexit 0へ読み替えず停止する。
これらはpracticalな境界であり、完全隔離や安全性の証明ではない。

JSON evidenceはsuccess、policy block、infrastructure failure、timeout、target command failureの
いずれでも保持する。exit 0はその1 commandの完了だけを示し、次のcommandを認可しない。

## 5. Sandbox evidence return

`sandbox-run` reportは次のgateへ`--sandbox-evidence`で還流する。

```bash
env PYTHONPATH=src python3 -m repo_health_doctor gate-check "$REVIEWED_REPO" \
  --fail-on-gate unknown \
  --sandbox-evidence /tmp/rhd-sandbox-evidence.json \
  -- "$NEXT_COMMAND" "$NEXT_ARGUMENT"
```

`--sandbox-evidence`はreport fingerprint、run ID、元gate decision fingerprint、subject、
policy version、age、size、duplicate、truncationを検証し、gateにはboundedな
`evidence_refs`だけを残す。raw report、raw stdout/stderr、host pathをgate decisionへ埋め込まない。

successful executionは`successful_execution_is_not_safety`というinformational evidenceであり、
gate verdictを改善せず、次のcommandをauthorizationしない。次のcommandでもHuman-controlled
authorizationとexit 0 onlyの契約を最初から満たす必要がある。

## Ready-to-copy agent rule

```text
Before running any command derived from this repository:

1. Run the configured repo-health-doctor real-scan and gate-check flow.
2. Proceed only when every required repo-health-doctor command exits 0.
3. Exit 1, exit 2, or any unknown exit code means STOP.
4. Never bypass the gate by running the command directly on the host.
5. A gate decision is not execution authorization.
6. Use sandbox-run only with a valid human-controlled authorization artifact.
7. Feed resulting sandbox evidence back into the next gate decision.
```

## Tool bindings

Each tool-specific guide inherits this contract and must not relax its exit or authorization rules:

- [Codex binding](integration-codex.md)
- [Claude Code binding](integration-claude-code.md)
- [Cursor binding](integration-cursor.md)

The binding guides record what was verified from Human-provided official-source evidence and what
remains instruction-based. They do not install hooks, change account or tool settings, or execute a
target command.

## Residual limits

- Scanner finding 0件、gate exit 0、sandbox exit 0、Docker実行成功はいずれも安全性を証明しない。
- Docker daemon、kernel、image、platform、local configuration、scanner coverageはreview境界として残る。
- staleまたはsubject mismatchのevidence、snapshot mismatch、dirty/untracked Git tree、
  non-Git execution subject、期限切れまたは再利用されたauthorizationは停止理由である。
- この契約はagentのinstructionだけでは技術的強制にならない。各bindingは利用可能なhookやpolicyで強制し、強制できないsurfaceではそのlimitationを明記する。
