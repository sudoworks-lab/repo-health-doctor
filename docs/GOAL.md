# GOAL.md — repo-health-doctor Integrated Hardening v2

- status: frozen-spec-candidate
- owner: Human（すどー）
- target repository: `sudoworks-lab/repo-health-doctor`
- baseline design commit: `e804997`
- created: 2026-07-15 JST
- detailed design: `docs/design/repo-health-doctor-integrated-design-v2.md`

> このファイルはGoal Loopのspec正本であり、Humanだけが編集する。
> 実装agentは読み取り専用とし、要件・順序・非目標を変更しない。
> 実装の詳細は上記detailed designを参照する。本ファイルと詳細設計が衝突する場合は、本ファイルのGoal・制約・非目標を優先する。

---

## 1. 目的

`repo-health-doctor`を、未知repoをAI agentや開発者が実行する前に使う、local-firstかつfail-closedなpre-execution safety gateとして強化する。

今回のGoalでは、すでに存在するreal scanner adapter、gate、authorization、sandbox-runを、次の一貫した流れへ接続する。

```text
real-scan
  ↓ exit 0 only
gate-check --external-evidence ... -- <command>
  ↓ exit 0 only
Human review / execution authorization
  ↓
sandbox-run --authorization ...
  ↓
gate-check --sandbox-evidence ... -- <next-command>
```

この流れは、以下を保証するための契約である。

- scanner不在・失敗・未検証状態をPASSとして扱わない
- scanner結果を実行可否判断へ接続する
- gate decisionとexecution authorizationを分離する
- authorizationをrepo・commit・tree・argv・policy・container imageへ束縛する
- sandbox実行成功を安全証明として扱わない
- 問題のあるexecution evidenceだけを判定の悪化方向へ還流する
- AI agentはexit 0以外で必ず停止する

本Goalは安全性やmalware containmentを証明するものではない。確認できたevidenceとlimitationを機械可読に残し、根拠の薄い安全判断と未確認状態での実行を防ぐことを目的とする。

---

## 2. 背景となる確認済み事実

基準commit `e804997` では、次が確認されている。

- Gitleaks、OSV-Scanner、Trivy、zizmorのreal adapterが存在する
- dedicated real scanner suite CLIは存在しない
- default `repo-health-doctor <path>`はscannerを実行しない
- default scanはstable public contractである
- sandbox-runはDocker runnerとfake runnerを持つ
- Docker argvは`--pull=never`、network none、read-only rootfs、non-root、capability drop等を構築する
- seccompはruntime defaultへ暗黙依存している
- real Docker daemonで境界の実効性を検証するCIは存在しない
- version表記は0.1.0だが、2026-07-15時点でGit tagは存在しない
- GitHub Releaseの有無は未確認

---

## 3. Ordered Goals

以下は依存順であり、後続Goalを先に完了扱いにしない。

### G001 — Baselineとrelease表現が実態と一致する

- tag、GitHub Release、README、CHANGELOG、`pyproject.toml`、release notesの実態を確認する
- Goal Loop内ではtag・Releaseを作成しない
- tagやReleaseが存在しない場合、正式release済みと誤認させない表現へ文書を整合させる
- baseline commitと未確認事項が文書化される

### G002 — explicit `real-scan` CLIが存在する

次の明示コマンドで、ローカルに存在するGitleaks、OSV-Scanner、Trivy adapterを順次実行できる。

```text
repo-health-doctor real-scan <path>
```

必須特性:

- default scanの挙動は変えない
- scannerをinstall・downloadしない
- scanner不在、timeout、errorでもsuite reportを生成する
- unavailableやfailureをPASSにしない
- redactedでschema-validなaggregated reportを出力する
- finding数とreport sizeに上限を持ち、truncationとomitted countを記録する
- `--offline`、scanner選択、timeout、text/json/markdown、output、`--fail-on-degraded`を持つ
- reportはexecution authorizationではない

### G003 — real scanner evidenceがgate decisionへ接続される

`gate-check`は、明示されたreal scanner suite reportをexternal evidenceとして受け取れる。

```text
gate-check --external-evidence <report>
```

必須特性:

- report kind、schema、fingerprint、subject、commit、tree、policy、age、size、truncationを検証する
- invalid、stale、subject mismatch、truncated evidenceを黙って無視しない
- finding 0件やsuite completedでverdictを改善しない
- unavailable、timeout、invalid、未検証versionはunknown/review方向へ作用する
- secret、vulnerability、misconfigurationは既存risk mappingに基づき悪化方向へ作用する
- verdictが良い方向へ動かない単調性を機械検証する
- gate decisionにはraw reportを埋め込まず、fingerprint等のreferenceだけを残す

### G004 — real compatibilityの検証範囲が3scannerで対称化される

Gitleaks、OSV-Scanner、Trivyについて、次が整備される。

- redacted fixture
- expected evidence
- fixture生成version
- regeneration手順
- compatibility test
- Tested Versions表
- Not Covered範囲

version statusは次を区別する。

```text
tested
compatible_family_unverified
unsupported
denylisted
unparseable
```

同じmajor versionであるだけでは`tested`としない。
`compatible_family_unverified`は実行可能でもdegraded evidenceとして扱う。

### G005 — authorization auto-discoveryがfail-closedで動作する

`gate-check`は、argvが明示され、`--authorization`がない場合に限り、次の1ファイルだけを探索できる。

```text
<repo_root>/.repo-health-doctor.authorization.json
```

必須特性:

- argvはdiscoverしない
- explicit authorizationが常に優先される
- tracked artifactは拒否する
- non-git、symlink、oversize、parse failure、git error、read中のfile変化を拒否する
- discoveryはauthorization validationを緩和しない
- refusal reasonは機械可読
- fallback探索を行わない
- local write可能processによる残余riskを文書化する

### G006 — sandbox profile contractが明示化される

初期profileとして、Moby default相当のcopyを次の正確な名称で同梱する。

```text
rhd-moby-default-v1
```

必須特性:

- 初期profileを`locked-down`と誇張しない
- defaultは従来どおり`runtime-default`
- 任意seccomp pathや`unconfined`を許可しない
- profileをpackage dataとして配布し、installed wheelから解決できる
- source、commit/version、license、取得日、変更内容、hashを記録する
- Docker argv contractをgolden testで固定する
- rootless検出と制約を文書化する
- 実Dockerでの有効性主張はG009完了後に限定する

### G007 — execution authorizationが強く束縛される

authorization draft schemaを後方互換付きで拡張し、次を実現する。

- schema versionごとのrequired/allowed fields
- expiry CLI
- repo、commit、tree、dirty worktreeの直接照合
- approved argvとpolicyの既存束縛維持
- exact digest-pinned image referenceの束縛
- registry manifest digestとlocal image IDを区別する
- command起動直前のsingle-use atomic reservation
- refusal reason contractとdocs同期test

旧artifactにimage bindingがない場合は後方互換として受理できるが、limitationを記録する。

### G008 — sandbox execution evidenceがgateへ単調に還流される

`sandbox-run` reportをnormalizationし、明示されたevidenceとしてgateへ渡せる。

```text
gate-check --sandbox-evidence <report>
```

必須特性:

- success、timeout、policy block、cleanup failure、observer degraded、binding mismatch、fake/dry runを区別する
- informational noteとdecision-affecting signalを分離する
- successful executionはverdictを改善しない
- invalid、stale、subject mismatch、over-budget evidenceを黙って無視しない
- evidence count、file size、total bytes、ageをboundedにする
- duplicate fingerprintを排除する
- gate decisionとsandbox reportをfingerprintで相互参照する
- evidence未指定時の既存挙動を維持する

### G009 — real Docker境界検証をHuman-triggered CIで実行できる

専用workflowを用意する。

```text
.github/workflows/real-docker-verification.yml
```

初期triggerは`workflow_dispatch`だけとする。

必須検証:

- normal executionとdiff evidence
- network none
- read-only rootfs
- writable `/tmp` tmpfs
- non-root
- timeout
- copy budget block
- `rhd-moby-default-v1`
- image binding一致・不一致
- installed packageからseccomp profileを解決できること
- original repoが変更されないこと
- cleanup
- schema-valid evidence

固定の無害な合成commandだけを使い、repo由来command、実malware、外部serviceへのrequestを実行しない。

image取得はHuman-triggered workflow内のdigest-pinned独立stepとし、sandbox-runは`--pull=never`を維持する。

### G010 — 実測に基づく`rhd-locked-down-v1`が存在する

G009のreal Docker検証を基に、Moby default copyを置き換えず、別profileとして次を追加する。

```text
rhd-locked-down-v1
```

必須特性:

- 削除したsyscallを小単位で検証する
- 削除理由を文書化する
- profile hash、provenance、tested runtime、未対応runtimeを記録する
- G009の検証をgreenに保つ
- syscall削減判断はHuman review対象
- malware containmentや完全な隔離を主張しない

### G011 — AI Agent Contractが最終仕様と一致する

agent非依存の正準文書と、Codex、Claude Code、Cursor向けbinding文書を整備する。

必須ルール:

- repo由来commandをhostで直接実行しない
- canonical flowでは`real-scan --fail-on-degraded`を使う
- exit 0だけが次の定義済み段階へ進める
- exit 1、exit 2、未知exit codeはすべて停止する
- gate decisionはexecution authorizationではない
- Human-controlled authorizationなしでsandbox実行しない
- sandbox evidenceを次のgateへ還流する
- unknown、degraded、mismatch、stale、over-budgetはfail-closed

外部toolのhook、rules、settings仕様は、実装時に公式文書で確認し、確認日を記録する。
強制機構がない場合、instruction-based運用に技術的強制力がないことを明記する。

---

## 4. Hard Constraints

### 4.1 Security

- network callをdefault pathへ追加しない
- scannerやimageを自動取得しない
- raw secret、token、cookie、`.env`値を保存・表示しない
- raw scanner output、raw stdout/stderrを保存しない
- host private path、local IP、生policy値を保存しない
- redactionを弱めない
- invalid evidenceを黙ってskipしない
- default host executionを追加しない
- `--pull=never`を維持する
- `seccomp=unconfined`、`apparmor=unconfined`、privileged、cap-add、host namespace、docker.sock mountを許可しない

### 4.2 Compatibility

- default `repo-health-doctor <path>`の挙動を変えない
- stable schema version、CLI contract、existing rule IDを暗黙変更しない
- draft schema変更時はversion bump、version別field contract、migration note、old/new golden、後方互換testを必須とする
- runtime dependencyゼロを維持する
- standard libraryと`unittest`を使う

### 4.3 Evidence

- reportとevidenceはboundedにする
- canonical JSON fingerprint規約を共通化する
- success evidenceで判定を改善しない
- gate decisionとauthorizationを混同しない
- real Docker検証は確認したruntime、OS、architecture、image、dateの範囲だけを主張する

### 4.4 Git・公開

- `git add .`と`git add -A`を使わない
- stageは変更fileを明示指定する
- logs、cache、generated report、local artifactをcommitしない
- commitはGoal Loopの規約に従いlocal branchで行ってよい
- push、tag、GitHub Release、外部公開はHumanの明示指示なしに行わない
- force push、hard reset、破壊的操作を行わない
- 実装は隔離したgit worktreeで行う

### 4.5 Goal Loop

- `docs/GOAL.md`はread-only
- `docs/PLAN.md`はKICKOFF生成後に凍結し、loop中は判断memo以外を書き換えない
- `docs/STATUS.md`はappend-only
- `docs/features.json`は項目定義を変えず、許可されたstatus fieldだけを更新する
- 1 sessionでは未完了featureを原則1件だけ扱う
- 検証に通っていないfeatureを`passes: true`にしない
- Human-only actionが必要な場合は`blocked`にし、成功を偽装しない

---

## 5. Deliverables

- `real-scan` CLI、schema、formatter、test、docs
- real scanner evidenceのgate統合
- compatibility fixture/version/regeneration基盤
- authorization discovery
- packaged seccomp profileとprovenance
- authorization schema 0.2-draftと後方互換
- image binding、single-use reservation、worktree binding
- sandbox execution evidence adapterとgate統合
- manual real Docker GitHub Actions workflow
- `rhd-locked-down-v1`
- AI Agent Contractとagent別integration docs
- README、CHANGELOG、public contracts、evaluation/security docs、sample outputsの整合
- 全変更に対応するunit、golden、schema、CLI、real Docker verification

---

## 6. Non-goals

- scannerの自動install・download
- default scanでのscanner実行
- repo由来commandをdefault CIで実行すること
- malware containmentの証明
- 実malware fixture
- cloud production実績
- 実在downstreamの本番実績
- long-running production SLO実績
- centralized authorization revocation
- distributed atomic lock
- Podman、containerd、gVisor、Kata対応
- AppArmor、SELinux profileの同梱
- MCP server
- agentへの自動install
- 第三者security reviewを内部reviewで代替すること
- 実在する疑わしいtoolの公開晒し
- push、tag、Releaseの自動実行

---

## 7. Required Verification

`AGENTS.md`のRequired Verificationを正本とし、各feature完了時に少なくとも次を実行する。

```bash
git status --short
git diff --check
find docs -maxdepth 2 -type f | sort
find tests/fixtures -maxdepth 3 -type f | sort
wc -l AGENTS.md
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m repo_health_doctor --help
PYTHONPATH=src python3 -m repo_health_doctor --version
PYTHONPATH=src python3 -m repo_health_doctor . --fail-on block --public-safety
PYTHONPATH=src python3 -m repo_health_doctor validate-policy .
PYTHONPATH=src python3 -m repo_health_doctor . --public-safety --format json --output /tmp/repo-health-doctor-result.json
python3 -m json.tool /tmp/repo-health-doctor-result.json >/dev/null
```

変更内容に応じて、PLANで追加されるfeature固有testも実行する。

real Docker検証は、G009で作成するHuman-triggered workflowがgreenになった事実をevidenceとして使う。ローカルやfake runnerだけでG009、G010を完了扱いにしない。

---

## 8. Human Review Items

以下は機械検証だけで最終決定しない。

1. baselineをtagged releaseにするか
2. GitHub Releaseを作るか
3. seccomp syscall削減の妥当性
4. real Docker workflowの自動scheduleを将来許可するか
5. agent別integration docsが外部toolの公式仕様を正確に表現しているか
6. security claimが実績を超えていないか
7. public docsにsecret、private path、個人情報がないか
8. 全feature完了後にmerge、push、tag、releaseするか

Goal Loop内では、1、2、8を実行しない。
G001は「正式release済みと誤認させない内部整合」を完了条件とする。

---

## 9. Done When

次をすべて満たしたとき、このGoalは完了する。

- KICKOFFで生成された全featureが`passes: true`
- `blocked: true`のfeatureが残っていない
- G001〜G011が依存順に実装・検証されている
- default scan contractが維持されている
- real scanner evidenceとsandbox evidenceがgateへ接続されている
- verdictの単調性testがgreen
- authorization discovery、image binding、single-use、worktree bindingがfail-closed
- packaged seccomp profileがsource checkoutとinstalled wheelの両方で解決できる
- manual real Docker workflowがgreen
- `rhd-locked-down-v1`のHuman reviewが完了
- AI Agent Contractがexit 0 onlyで統一されている
- full unittest、schema parse、CLI、public-safety verificationがgreen
- README、CHANGELOG、public contracts、design docsと実装が一致する
- raw secret、raw output、private path、cache、history、個人情報がcommitされていない
- working treeがclean
- local Goal branch上のcommit履歴がfeature単位で追跡可能
- push、tag、Releaseは行われていない
- `docs/STATUS.md`に最終検証、残risk、Human review結果が追記されている
- loopが`<promise>ALL_FEATURES_PASS</promise>`を出力する
