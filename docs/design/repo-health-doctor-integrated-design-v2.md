# repo-health-doctor 強化 統合実装設計 v2

- 対象repo: `sudoworks-lab/repo-health-doctor`
- 設計基準commit: `e804997`
- 基準日: 2026-07-15 JST
- status: 実装開始前の統合設計・凍結候補
- 実装担当想定: Codex
- 正本: 本ファイル
- 旧`00-INDEX.md`およびRHD-01〜RHD-08は根拠資料として保持するが、実装順・契約・名称が衝突する場合は本ファイルを優先する

---

## 0. 目的

repo-health-doctorを次の状態まで強化する。

1. 実装済みのGitleaks / OSV-Scanner / Trivy real adapterを明示CLIから実行する。
2. real scanner結果をfail-closedのままgate decisionへ接続する。
3. `gate-check`をAI agentから使いやすくしつつ、repo自身による自己承認を防ぐ。
4. sandbox-runのDocker境界、authorization、execution evidenceを強化する。
5. fake runner常時回帰とreal Docker境界検証を分離する。
6. Codex / Claude Code / Cursor向けに、exit 0以外では進まないAI Agent Contractを整備する。
7. 「安全を証明する」のではなく、「根拠の薄い安全判断と未確認状態での実行を防ぐ」という思想を維持する。

対外説明では実績の範囲を超えて表現せず、「個人開発で設計・実装・検証した」と明記する。

---

# 1. 基準時点の事実

## 1.1 release

2026-07-15時点:

- `pyproject.toml`、README、CHANGELOG、release notesには0.1.0の記載あり
- Git tagは存在しない
- GitHub Releaseは未確認
- test fileは実測61件

tagとReleaseを確認するまで「v0.1.0正式release済み」と断定しない。

## 1.2 real scanner

- Gitleaks / OSV-Scanner / Trivy / zizmor adapter実装済み
- dedicated real scanner suite CLIは未実装
- default `repo-health-doctor <path>`はscannerを実行しない
- default scanはstable public contract

## 1.3 sandbox-run

- Docker runnerとfake runner群あり
- `--pull=never`
- network none / read-only rootfs / cap-drop ALL / no-new-privileges / non-root / tmpfs / resource limit / mount制約あり
- rootless / userns-remap検出fieldあり
- seccompはruntime defaultへ暗黙依存
- real Docker CIは未実装

---

# 2. 不変条件

## 2.1 stable contract

- default scanはscannerをinstall・download・runしない
- stable schema、rule ID、exit contractを暗黙変更しない
- Experimental/draft schemaは、明示version bumpと後方互換testを条件に変更可
- schema versionごとにrequired/allowed fieldsを分離する

## 2.2 fail-closed

以下をPASSにしない。

- scanner unavailable / timeout / error
- report missing / parse error
- unsupported / unverified version
- authorization missing / mismatch
- evidence invalid / stale / subject mismatch
- Docker infrastructure / cleanup failure
- unknown exit code

## 2.3 成功は安全証明ではない

- finding 0件でも安全とは断定しない
- sandbox-run exit 0でも安全とは断定しない
- 成功evidenceはverdictを改善しない
- 問題evidenceのみ悪化方向へ作用できる
- gate decisionはexecution authorizationではない

## 2.4 redaction

保存禁止:

- raw secret
- raw scanner output
- raw stdout/stderr
- host private path
- cookie/token/.env値
- shell history/cache
- 個人情報
- 生policy値

## 2.5 network / acquisition

- scannerやimageを自動取得しない
- default CIでnetwork取得しない
- real Docker CI初期版は`workflow_dispatch`のみ
- live testはenv opt-in
- image取得はdigest-pinned独立step
- sandbox-runは`--pull=never`

## 2.6 implementation

- runtime dependencyゼロ
- standard libraryのみ
- `unittest`
- frozen dataclass、型ヒント、runner injection
- fail-closed exception normalization

---

# 3. 改訂後の一本道

| 順 | ID | 項目 | 依存 |
|---:|---|---|---|
| 0 | RHD-00 | Baseline / Release Alignment | なし |
| 1 | RHD-01 | `real-scan` CLI | RHD-00推奨 |
| 2 | RHD-01B | Real Scanner Evidence → Gate Integration | RHD-01必須 |
| 3 | RHD-03 | Real Compatibility拡充 | RHD-01推奨 |
| 4 | RHD-02 | authorization auto-discovery | RHD-01B後推奨 |
| 5 | RHD-04A | Profile Hardening 配線・契約 | なし |
| 6 | RHD-05 | Stronger Authorization Binding | RHD-02/04A推奨 |
| 7 | RHD-06 | Execution Evidence Integration | RHD-05推奨 |
| 8 | RHD-08 | Real Docker Verification | RHD-04A/05必須 |
| 9 | RHD-04B | 実測に基づくseccomp絞り込み | RHD-08必須 |
| 10 | RHD-07 | AI Agent Contract | RHD-01B/02/06必須 |

RHD-07は最終仕様確定後に書く。
S-007外部security reviewは第三者が必要なため対象外。

---

# 4. Codex共通実行契約

## 4.1 開始前

```bash
pwd
git rev-parse --show-toplevel
git status --short --branch
git log -1 --oneline --decorate
git diff --check
```

- repo rootが違えば停止
- secret、`.env`、cookie、SSH key、history、cache、個人情報を読まない
- commit/push/tag/releaseは明示指示なし禁止
- 既存dirty変更と混ぜない

## 4.2 agent

通常実装:

- mainが司令塔
- write agentは原則`impl-worker` 1体
- `test-doctor`
- `diff-reviewer`

公開・commit前:

- `secret-sweeper`
- `release-auditor`

read-only agentは変更禁止。

## 4.3 失敗時

ログ・差分・既存契約を読み、原因仮説→最小修正→再検証をGoal達成まで続ける。
`manualRequired/blocked/unable`は、secret閲覧、外部公開、push、破壊的操作、明示禁止操作が必要な場合だけ。

## 4.4 verification

`AGENTS.md`を正本とし、少なくとも以下を実行。

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

## 4.5 final report

- 要約
- repo/branch/start HEAD/start status
- 変更file
- 既対応/今回対応
- secret・個人情報・cache・history除外
- 未確認/仮定/Human判断
- verification
- git結果、commit hash、push有無
- 次手順
- 残risk
- 指示逸脱

---

# 5. RHD-00: Baseline / Release Alignment

## 5.1 目的

`e804997`をどのrelease状態として扱うか確定する。

## 5.2 Human判断

### A. v0.1.0正式baseline化

- full verification
- public state確認
- secret確認
- annotated tag
- GitHub Release
- release notes整合

tag/releaseは明示指示時のみ。

### B. 正式releaseではない状態を維持

README、CHANGELOG、release notesを実態に合わせて修正する。

## 5.3 DoD

- tag/Release/README/CHANGELOG/pyprojectが矛盾しない
- baseline commit明示
- test green
- working tree clean
- 未確認事項記録

---

# 6. RHD-01: `real-scan` CLI

## 6.1 CLI

```text
repo-health-doctor real-scan <path>
  [--scanners gitleaks,osv-scanner,trivy]
  [--offline]
  [--timeout-seconds N]
  [--format text|json|markdown|md]
  [--output PATH]
  [--fail-on-degraded]
```

この段階では`--fail-on-gate`と`--gate-decision-output`を入れない。
scanner gate統合はRHD-01Bで行う。

## 6.2 model

```python
SUITE_REPORT_KIND = "real_scanner_suite"
SUITE_SCHEMA_VERSION = "0.1-draft"

@dataclass(frozen=True)
class RealScannerSuiteEntry:
    scanner_name: str
    executed: bool
    valid: bool
    status: str
    blocking_errors: tuple[str, ...]
    warnings: tuple[str, ...]
    risk_summary: Mapping[str, object]
    normalized_result: Mapping[str, object]
    finding_count: int
    omitted_finding_count: int
    truncated: bool

@dataclass(frozen=True)
class RealScannerSuiteReport:
    suite_status: str
    entries: tuple[RealScannerSuiteEntry, ...]
    limitations: tuple[str, ...]
    execution_authorized: bool
    report_fingerprint: str
    generated_at: str
    subject: Mapping[str, object]
```

- status: `completed` / `unknown` / `skipped_offline`
- 全entry completedかつvalidのみsuite `completed`
- それ以外は`degraded`
- `execution_authorized=false`

## 6.3 rules

- sequential execution
- unknown scanner nameはCLI error
- unavailable/timeout/errorでもsuite完走
- unavailableをPASSにしない
- offlineはnetwork scannerをskip、Gitleaksのみ
- no findingは安全宣言なし

## 6.4 budget

既存adapterの上限を確認し、不足なら追加。

- per-scanner finding max
- suite finding max
- omitted count
- truncation
- report byte目安
- text field length max

truncationはlimitationとして記録。

## 6.5 exit

- 0: report生成完了。degraded含む
- 1: CLI/output failure
- `--fail-on-degraded`時のdegradedは1
- 2は使わない

## 6.6 test/CI

unit/CLI testではrunner/PATHを制御しunavailableを再現。
Hosted runnerのscanner有無を前提にしない。
CI smokeはschema-validとredactionのみ確認。

## 6.7 docs

default scan不変、auto-installなし、missing/failureはunknown、no findingは安全証明でない、reportはauthorizationでないことを明記。

---

# 7. RHD-01B: Scanner Evidence → Gate

## 7.1 CLI

```text
gate-check --external-evidence PATH
```

複数可。初期kindは`real_scanner_suite`。

```bash
repo-health-doctor real-scan . \
  --format json \
  --output /tmp/rhd-real-scan.json \
  --fail-on-degraded

repo-health-doctor gate-check . \
  --external-evidence /tmp/rhd-real-scan.json \
  -- <command>
```

前段exit 0以外では進まない。

## 7.2 validation

- report kind/version/schema/fingerprint
- generated_at、age
- file size、entry/finding count
- truncation
- duplicate fingerprint
- repo identity、commit、tree hash、policy version

subjectが弱い場合はlimitationにし、verdictを改善しない。

## 7.3 monotonicity

- no finding/completed → verdict不変
- unavailable/timeout/invalid/unverified → unknown方向
- secret-like → quarantine/block方向
- vulnerability/misconfig → existing risk mappingに従い悪化
- invalid/stale/subject mismatch/truncated →悪化
- 左方向への移動禁止

既存`validate_external_scanner_result`と`map_external_scanner_risk`を使用する。
RISK013等が`secret_like_value`をfail-closedに扱うことを横断testする。

## 7.4 gate report

raw reportを埋め込まず、fingerprint等の`evidence_refs`だけ追加する。

---

# 8. RHD-03: Real Compatibility

## 8.1 Trivy対称化

追加:

- expected evidence
- version record
- regeneration script
- compatibility test

raw outputは`/tmp`、committed fixtureはredacted、取得はHuman-approved。

## 8.2 version status

3scanner共通:

```text
tested
compatible_family_unverified
unsupported
denylisted
unparseable
```

同一majorをtested扱いしない。

- fixture exact version: tested
- 同一supported familyの別version: compatible_family_unverified
- compatible_family_unverifiedは実行可だがsuite degraded、gateではreview/unknown方向
- unsupported/denylisted/unparseableは実行しない

## 8.3 fixture

- Gitleaks dirty worktree
- Gitleaks SARIF追加
- OSV exit 128
- OSV exit/report mismatch
- Trivy licenses含有
- Trivy exit/report mismatch
- version parse failure

既存fixtureで足りる場合は追加しない。

---

# 9. RHD-02: authorization discovery

## 9.1 candidate

```text
<repo_root>/.repo-health-doctor.authorization.json
```

argvあり、明示authorizationなし、`--no-discover`なしの時だけ発動。
argvはdiscoverしない。

## 9.2 git判定

1. `git rev-parse --show-toplevel`
2. top-level一致
3. `git ls-files --error-unmatch`
4. exit 0 tracked拒否
5. exit 1 untracked
6. その他git error拒否

## 9.3 file safety

- lstat
- symlink拒否
- 64KiB max
- `O_NOFOLLOW`利用可能時は使用
- open後fstat
- regular file
- bounded read
- parse object
- TOCTOU完全防止とは書かない

## 9.4 reasons

- tracked_refused
- not_a_git_repo
- symlink_refused
- not_found
- parse_failed
- too_large
- git_error
- file_changed

machine-readableな正式prefixを既存命名規約に合わせる。

## 9.5 test

tmp git repo。tracked化は`git add`まででよい。
untracked/tracked/non-git/symlink/broken/too-large/not-found/git unavailable/file replacement/既存回帰を検証。

---

# 10. RHD-04A: Profile Hardening配線

## 10.1 profile名

初期同梱:

```text
rhd-moby-default-v1
```

default相当でありlocked-downとは呼ばない。

RHD-08後に別profileとして:

```text
rhd-locked-down-v1
```

## 10.2 CLI

```text
--seccomp runtime-default
--seccomp rhd-moby-default-v1
```

defaultはruntime-default。
任意path、unconfinedは不可。

## 10.3 packaging

- package data
- `importlib.resources`
- wheel build test
- installed wheel resource test
- source checkout/install両方対応

## 10.4 provenance

- Moby repo
- source commit/version
- license
-取得日
-変更内容
-file hash

## 10.5 argv/evidence

禁止flagを拡張し、profile、profile hash、runtime detection sourceをevidenceへ記録。
全profile×seccompのargv goldenを追加。
rootlessは検出・限界を文書化し、全機能対応とは書かない。


---

# 11. RHD-05: Stronger Authorization Binding

## 11.1 T0

実装前に確認する。

- gate decision subjectの算出元
- commit/tree hash
- dirty worktree
- non-git
- binding_kind
- sandbox-run時の既存照合

根拠メモを先に作る。

## 11.2 schema

- 0.1-draftを受理
- 新形式は0.2-draft
- version別required/allowed fields
- 0.1へ0.2専用fieldを入れたartifactは拒否
- backward compatibility golden必須

## 11.3 refusal reason contract

既存reason、RHD-02 discovery reason、本項目のreasonをdocs表へ集約し、コードとの同期testを作る。

## 11.4 expiry

```text
--expires-in-minutes N
--expires-at ISO8601
```

併用不可。未指定は従来どおりnull。
approval前に設定が必要なlimitationを付ける。
60分以内は推奨であり、固定policyとはしない。

## 11.5 image binding

optional:

```json
"approved_image": {
  "requested_reference": "python:3.12-slim@sha256:<registry-manifest-digest>",
  "resolved_image_id": "sha256:<local-image-config-id>"
}
```

### requested_reference

- Humanが承認したexact image reference
- `sandbox-run --image`と完全一致
- digest-pinned必須

### resolved_image_id

- command起動直前に`docker image inspect`で取得するlocal image ID
- authorization作成時の値と一致
- 未解決は拒否

RepoDigestsと`.Id`を代替可能な同一値として扱わない。

reason:

- `approved_image_reference_mismatch`
- `approved_image_digest_unpinned`
- `runtime_image_id_unresolved`
- `approved_image_id_mismatch`

旧artifactにapproved_imageがなければ受理するが、`authorization_not_image_bound`をlimitationに記録。

## 11.6 single-use

optional:

```json
"single_use": true
```

command起動直前にsidecarをatomic createする。

```python
os.open(
    consumed_path,
    os.O_CREAT | os.O_EXCL | os.O_WRONLY,
    0o600,
)
```

- 既存なら`authorization_already_consumed`
- create失敗なら実行中止
- create後のDocker起動失敗でも消費済み
- gate-check/dry-runでは消費しない
- 分散lockやcentral revocationとは書かない

sidecar例:

```json
{
  "authorization_fingerprint": "sha256:...",
  "reserved_at": "...",
  "run_id": "...",
  "state": "reserved_for_execution"
}
```

## 11.7 worktree direct binding

workspace copy前にrepo root、HEAD commit、HEAD tree、dirty statusを取得し、authorization subjectと直接比較。

- mismatch/unresolvedはblock
- commit bindingを主張しdirtyならblock
- 緩和flagなし

## 11.8 test

- 0.1 backward compatibility
- 0.2 optional fields
- reference/image ID match/mismatch/unresolved
- atomic reservation
- reuse refusal
- reservation write failure
- dry-run non-consumption
- dirty worktree
- RHD-08 real Docker image binding case

---

# 12. RHD-06: Execution Evidence Integration

## 12.1 目的

sandbox-run reportをgateへ還流させる。
成功はverdictを改善せず、問題のみ悪化方向へ反映する。

## 12.2 T0

- limitation policy
- verdict mapping
- evidence model
- v3 adapter
- observer evidence
- gate sidecar

を精読し、field名は既存流儀へ合わせる。

## 12.3 normalized evidence

新adapter:

```python
normalize_sandbox_run_evidence(report)
```

取り込む:

- run_id
- report fingerprint
- subject/repo/commit/tree
- policy version
- gate decision fingerprint
- generated_at
- runner kind
- policy block
- command started/exit category
- timeout
- cleanup
- observer status
- boundary mismatch
- seccomp profile
- image identity
- diff summary count

取り込まない:

- raw preview
- raw stdout/stderr
- raw host path
- command内容の不要な再掲

## 12.4 informationalとdecision signalの分離

```json
"informational_notes": [
  "successful_execution_is_not_safety"
],
"decision_signals": [
  "execution_timeout"
]
```

`successful_execution_is_not_safety`は常時記録可能だが、それ自体でverdictを悪化させない。

decision signal:

- execution_policy_blocked
- subject_binding_mismatch
- execution_timeout
- workspace_cleanup_failed
- observer_degraded
- not_real_execution_evidence
- sandbox_evidence_invalid
- sandbox_evidence_stale
- sandbox_evidence_truncated

## 12.5 CLI/budget

```text
--sandbox-evidence PATH
```

複数可。

検証:

- max file size
- max count
- total bytes
- max age
- duplicate fingerprint
- subject一致
- policy version一致
- gate fingerprint照合

具体値は既存budget規約を読んで確定する。

## 12.6 monotonicity

実装前にtestを書く。

- successで不変
- timeout/block/invalidで同じか悪化
- fake/dryは実行証拠扱いしない
- 左方向への移動禁止
- evidenceなしの既存出力不変

## 12.7 cross reference

gate decisionはfingerprintとrun IDのみ参照。
sandbox report側には元gate fingerprintを含める。
raw reportを相互埋込しない。

---

# 13. RHD-08: Real Docker Verification

## 13.1 workflow

初期版:

```text
.github/workflows/real-docker-verification.yml
```

```yaml
on:
  workflow_dispatch:
```

初期版ではPR、push、scheduleを使わない。
将来自動化する場合はHuman承認と共通規約改訂が必要。

## 13.2 acquisition

manual workflow内の独立stepでdigest-pinned pull。

- registry digestの種類をdocsへ記録
- sandbox-runは`--pull=never`
- local image IDを記録
- Docker version、OS、architectureをstep summaryへ記録

## 13.3 opt-in

```text
RHD_REAL_DOCKER_TEST=1
```

未設定時はtest discover後、`unittest.skipUnless`によりskip。

## 13.4 cases

1. 正常実行 + diff evidence
2. network deny
3. read-only rootfs
4. `/tmp` tmpfs
5. non-root
6. timeout
7. copy budget block
8. `rhd-moby-default-v1`
9. image binding一致/不一致
10. installed package resourceからseccomp profile解決

固定の無害な`python3 -c`だけを使う。
repo由来commandや実マルウェアを実行しない。

## 13.5 validation

- raw stdout/stderrでなくevidence JSONとexit categoryを検証
- schema validate
- original repo不変
- cleanup
- network noneは安全なreport fieldでも確認
- 外部serviceへ実requestしない

## 13.6 first green後

image compatibility docsへ以下を記録。

- image reference
- local image ID
- Docker version
- runner OS/architecture
- verified date/workflow run
- tested profile
- limitations

---

# 14. RHD-04B: 実測に基づくseccomp絞り込み

## 14.1 profile

RHD-04Aの`rhd-moby-default-v1`を置換せず、別profileとして追加。

```text
rhd-locked-down-v1
```

## 14.2 手順

1. Moby default provenance確認
2. sandbox-run用途整理
3. 削除候補syscallを理由付き列挙
4. 小単位で削除
5. RHD-08を毎回実行
6. failureを原因調査
7. 最終削除listと根拠をdocs化

Codexへ自由裁量でsyscall削除を任せない。
Human review必須。

## 14.3 DoD

- real Docker case green
- profile hash
- provenance/license
- removed syscall/rationale
- tested runtime
- unsupported runtime
- malware containment claimなし

---

# 15. RHD-07: AI Agent Contract

## 15.1 normative rules

1. repo由来commandをhostで直接実行しない
2. real-scanを使うcanonical flowでは`--fail-on-degraded`
3. exit 0だけが次の定義済み段階へ進める
4. exit 1はtool failureとして停止
5. exit 2はgate/policy blockとして停止
6. unknown exit codeも停止
7. gate decisionはauthorizationではない
8. Human-controlled authorizationが必要
9. bounded executionはsandbox-run
10. sandbox evidenceを次のgateへ還流
11. unknown/degraded/mismatch/stale/over-budgetはfail-closed

## 15.2 canonical flow

```text
real-scan
  ↓ exit 0 only
gate-check --external-evidence ... -- <command>
  ↓ exit 0 only
human review / authorization
  ↓
sandbox-run --authorization ...
  ↓
gate-check --sandbox-evidence ... -- <next-command>
```

## 15.3 docs

- `docs/agent-contract.md`
- `docs/integration-codex.md`
- `docs/integration-cursor.md`
- `docs/integration-claude-code.md`

agent別docsは正準文書への薄いbindingにする。

## 15.4 external facts

各toolのhook/rules/settingsは実装時に公式docsを確認し、次を明記。

```text
Verified against official documentation as of YYYY-MM-DD.
```

未確認は未確認と書く。
instruction fileだけの場合、技術的強制ではないと明記する。

## 15.5 ready-to-copy rule

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

## 15.6 test

- docs存在/cross-link
- verified-as-of
- command smoke
- target commandを実行しない
- exit表とpublic contract一致
- exit 0 only
- README導線
- link切れなし

---

# 16. 横断schema/fingerprint規約

## 16.1 schema

stableは変更しない。
draft version bump時は必須:

- version-specific required fields
- version-specific allowed fields
- migration note
- old/new golden
- backward compatibility test
- CHANGELOG/public-contracts

## 16.2 canonical fingerprint

共通関数へ寄せる。

- UTF-8
- sorted keys
- fixed separators
- raw pathを含めない
- timestampを対象に含めるかkindごとに明示
- `sha256:`prefix

用途:

- gate decision
- authorization
- scanner suite
- sandbox report
- consumption reservation

---

# 17. 横断exit code

| code | 意味 | AI Agent |
|---:|---|---|
| 0 | contractどおり完了し、指定thresholdで停止条件なし | 次の定義済み段階へ |
| 1 | CLI/tool/output/infrastructure failure | 停止 |
| 2 | gate/policy/authorization block | 停止 |
| その他 | 未定義 | 停止 |

`real-scan`はevidence収集目的ではdegraded exit 0を許容するが、AI canonical flowでは`--fail-on-degraded`を必須にする。

---

# 18. docs共通規約

各featureで実績と制約を対で書く。

## 実績

- working code
- test
- CI
- exact version/scope/date

## 制約

- unavailable is not PASS
- no finding is not proof of safety
- successful execution is not proof of safety
- gate decision is not authorization
- local single-useはrevocationでない
- seccompはdefense in depth
- real Docker verificationはtested runtime限定
- external review未完了
- production claimなし

更新対象:

- README
- feature docs
- CHANGELOG Unreleased
- public-contracts
- schema
- sample output
- docs index

---

# 19. 対象外

- scanner自動install/download
- default scanでscanner実行
- repo由来commandのdefault CI実行
- malware containment claim
- real malware fixture
- cloud production/実在downstream/long-running実績の演出
- centralized revocation
- distributed atomic lock
- Podman/containerd/gVisor/Kata
- AppArmor/SELinux profile同梱
- MCP server
- agent自動install
- 第三者reviewの自己代替
- 疑わしいtoolの公開晒し

---

# 20. 最終受入条件

## Product

- default scan不変
- real-scan
- scanner evidence→gate
- authorization discovery
- compatibility/version
- packaged seccomp
- image binding
- atomic single-use
- monotonic sandbox evidence
- manual real Docker verification
- agent contract

## Safety

- raw secret/output/pathなし
- host direct executionなし
- auto pullなし
- fail-openなし
- exit 1/2/unknownでagent停止
- successでverdict改善なし
- invalid evidenceを黙って無視しない

## Verification

- full unittest
- schema parse
- CLI help/version
- public safety self-scan
- manual real Docker green
- installed wheel resource test
- redaction review
- diff check

## Git

- repo/branch/HEAD/status記録
- commit/push/tag/releaseはHuman指示時のみ
- final report

---

# 21. 開始方法

最初にCodexへ渡すのはRHD-00。

RHD-00でbaselineを確定後、RHD-01へ進む。
各項目はPR単位に分割するが、失敗で即終了せず、原因調査・最小修正・再検証をGoal達成まで継続する。

次項目へ進む条件:

- 現項目DoD達成
- Required Verification green
- docsと実装一致
- blocking findingなし
- unresolved事項明示
- Humanが次へ進む判断
