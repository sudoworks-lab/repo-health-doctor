# Goal Loop 実装計画 — Human-directed correction

## 対象と運用契約

docs/GOAL.md の Integrated Hardening v2 を、F001〜F036の依存順で実装・検証する。本PLANはKICKOFF後かつ実装loop開始前のHuman reviewで、旧11-feature planを1 processあたり原則60分以内で完了できる36 bounded featuresへ差し替えたものである。

- 1 process = 1 parent turn = 1 feature = 1 bounded goal とし、指定feature以外へ進まない。
- F001〜F034は、scanner・imageの取得、push、Hosted workflow実行、Human承認を伴わずに進める。F030のreal Docker regressionは、ローカルに既に存在するdaemonとimageだけを明示的opt-inで使用し、取得を行わない。
- F032はHumanが事前作成したdocs/human-review/agent-binding-official-sources.mdをread-only参照し、Goal Loop iterationではnetwork access、外部設定、account操作を行わない。
- feature完了後はdocs/features.jsonの項目定義を凍結し、通常iterationで変更できるのは対象featureのpasses、verified_at、blockedだけである。
- docs/STATUS.mdは実装loop開始後append-only、docs/PLAN.mdは判断メモ以外read-only、docs/GOAL.mdは常にread-onlyとする。

## Goal / milestone / feature対応

| Goal / milestone | Features | 依存 |
|---|---|---|
| G001 / Baselineとrelease整合 | F001 | なし |
| G002 / explicit real-scan | F002〜F005 | F001 |
| G003 / scanner evidence gate統合 | F006〜F008 | F005 |
| G004 / 3 scanner compatibility | F009〜F011 | F008 |
| G005 / authorization discovery | F012〜F014 | F011 |
| G006 / sandbox profile contract | F015〜F017 | F014 |
| G007 / authorization強化 | F018〜F021 | F017 |
| G008 / sandbox evidence gate還流 | F022〜F024 | F021 |
| G009 / real Docker verification | F025〜F027 | F024 |
| G010 / candidate seccompとHuman承認 | F028〜F030、F035、F036 | F027、F034 |
| G011 / AI Agent Contract | F031〜F033 | F024、F027、F030 |
| 横断品質 | F034 | F033 |
| Human Gate | F035 | F027、F030、F034 |
| 最終統合 | F036 | F035 |

## 共通scope

各featureで変更できるのは、その節の「Allowed」に列挙したpathと、進捗記録用のdocs/STATUS.md、対象featureの状態更新用docs/features.jsonだけである。既存fixtureで同じ検出scenarioを作れる場合は再利用する。

全feature共通のForbidden:

- docs/GOAL.md、docs/design/repo-health-doctor-integrated-design-v2.md、AGENTS.md、CLAUDE.md、PROMPT.md、Goal Loop runtime。
- 指定feature外の製品機能、無関係なrefactor、stable schema_version、既存rule_id、default scan contractの暗黙変更。
- scanner/imageの自動install、download、pull、network acquisition。
- raw secret、raw scanner output、raw stdout/stderr、private path、local IP、生policy値、cache、history、個人情報の保存または出力。
- git add、git commit、git reset、git checkout、git stash、push、tag、Release、外部公開。
- Hosted workflowの起動。Hosted workflowはHumanがworkflow_dispatchから実行する。
- candidate seccompをverified、production-ready、malware containment、完全隔離と表現すること。
- finding 0件、suite完走、sandbox成功などのsuccess evidenceでverdictを改善すること。

## Features

### F001 / G001 — Baseline、version、release表現の監査

- Dependency: なし。
- Scope: local Git refsと文書を監査し、baseline、version表記、tagおよびReleaseの確認状況を整合させる。
- Allowed: README.md、CHANGELOG.md、pyproject.toml、docs/versioning.md、docs/release-notes/、docs/public-contracts.md。
- Forbidden: tagまたはReleaseの作成、remote照会、製品code変更。
- Acceptance: e804997、local tag refs、0.1.0表記、GitHub Release未確認の状態が矛盾なく記録され、正式release済みと誤認させない。
- Verification: git show --no-patch --format="%H %ad" e804997、git for-each-ref --format="%(refname)" refs/tags、PYTHONPATH=src python3 -m unittest tests.test_release_docs -v。

### F002 / G002 — Suite model、runner、fake runner

- Dependency: F001。
- Scope: RealScannerSuiteEntry、RealScannerSuiteReport、sequential suite runnerとfake runner unit testだけを実装する。
- Allowed: src/repo_health_doctor/external_scanner/real_scanner_suite.py、tests/test_real_scanner_suite.py、必要な同package __init__.py。
- Forbidden: schema、formatter、CLI dispatch、live scanner実行。
- Acceptance: unavailable、timeout、error後も3 scannerのsuiteが完走し、execution_authorized=falseとdegraded状態を返す。
- Verification: PYTHONPATH=src python3 -m unittest tests.test_real_scanner_suite -v。

### F003 / G002 — Suite schemaとformatter

- Dependency: F002。
- Scope: real scanner suite schema、text/json/markdown formatter、golden sample、schema/redaction testを追加する。
- Allowed: schemas/real-scanner-suite.schema.json、src/repo_health_doctor/external_scanner/real_scanner_suite.py、src/repo_health_doctor/formatters.py、tests/test_real_scanner_suite_contract.py、tests/fixtures/golden/、docs/real-scanner-suite.md。
- Forbidden: CLI parser/dispatch、scanner subprocess実行。
- Acceptance: 3 formatが同じbounded reportを表し、JSONがschema-validでraw output、secret-like value、private pathを出さない。
- Verification: PYTHONPATH=src python3 -m unittest tests.test_real_scanner_suite_contract -v、python3 -m json.tool tests/fixtures/golden/real-scanner-suite.json >/dev/null。

### F004 / G002 — real-scan CLI

- Dependency: F002、F003。
- Scope: real-scan dispatch、parser、scanner選択、offline、timeout、format/output、exit codeを配線する。
- Allowed: src/repo_health_doctor/cli.py、src/repo_health_doctor/__main__.py、src/repo_health_doctor/external_scanner/real_scanner_suite.py、tests/test_real_scan_cli.py。
- Forbidden: default scanの挙動変更、auto acquisition、budget/docsの横断拡張。
- Acceptance: unknown scannerはusage error、offlineはnetwork-capable scannerを実行せず、degraded reportの通常exitとCLI/output failureを区別する。
- Verification: PYTHONPATH=src python3 -m unittest tests.test_real_scan_cli -v、PYTHONPATH=src python3 -m repo_health_doctor real-scan . --offline --format json --output /tmp/rhd-real-scan.json、python3 -m json.tool /tmp/rhd-real-scan.json >/dev/null。

### F005 / G002 — Budget、fail-on-degraded、CI/docs

- Dependency: F004。
- Scope: finding/report budget、truncation、omitted count、--fail-on-degraded、offline CI smoke、live opt-in、README/docsを完結させる。
- Allowed: src/repo_health_doctor/external_scanner/real_scanner_suite.py、src/repo_health_doctor/cli.py、tests/test_real_scan_budget.py、tests/test_real_scan_cli.py、.github/workflows/ci.yml、README.md、docs/real-scanner-suite.md、docs/README.md、CHANGELOG.md。
- Forbidden: Hosted scanner前提、scanner取得、default scan変更。
- Acceptance: per-scanner/suite/byte budget超過をtruncatedとomitted countへ正規化し、canonical flowのdegradedが非0になり、CI smokeがscanner不在でも決定的に完了する。
- Verification: PYTHONPATH=src python3 -m unittest tests.test_real_scan_budget tests.test_real_scan_cli -v、PYTHONPATH=src python3 -m repo_health_doctor real-scan . --offline --fail-on-degraded --format json --output /tmp/rhd-real-scan.json。

### F006 / G003 — External suite evidence validation

- Dependency: F005。
- Scope: evidence schema、fingerprint、subject、age、size、duplicate、truncation validationを実装する。
- Allowed: src/repo_health_doctor/gate/external_evidence.py、src/repo_health_doctor/evidence/、schemas/real-scanner-suite.schema.json、tests/test_external_suite_evidence.py、tests/fixtures/external-scanner-results/。
- Forbidden: risk mapper、gate verdict、CLI配線。
- Acceptance: invalid、stale、subject mismatch、over-budget、duplicate、truncatedの各reasonが機械可読で返り、raw reportをgate decisionへ埋め込まない。
- Verification: PYTHONPATH=src python3 -m unittest tests.test_external_suite_evidence -v。

### F007 / G003 — Risk mapper接続と単調性

- Dependency: F006。
- Scope: validated suite findingを既存risk mapperへ接続し、verdict単調性とsecret_like_valueのfail-closedを固定する。
- Allowed: src/repo_health_doctor/external_scanner/risk_mapper.py、src/repo_health_doctor/gate/evaluator.py、src/repo_health_doctor/gate/verdict.py、tests/test_external_suite_gate_mapping.py、既存risk fixture。
- Forbidden: CLI/schema変更、success evidenceによる改善。
- Acceptance: no finding/completedはverdict不変で、invalid/unverified/findingは同じか悪化し、secret_like_valueを含むfindingはfail-closedになる。
- Verification: PYTHONPATH=src python3 -m unittest tests.test_external_suite_gate_mapping tests.test_external_scanner_risk_mapper -v。

### F008 / G003 — gate-check external evidence CLI

- Dependency: F007。
- Scope: gate-check --external-evidence、bounded evidence_refs、gate schema、CLI test、docsを追加する。
- Allowed: src/repo_health_doctor/cli.py、src/repo_health_doctor/gate/、schemas/gate-decision.schema.json、tests/test_external_evidence_cli.py、docs/public-contracts.md、docs/real-scanner-suite.md、CHANGELOG.md。
- Forbidden: sandbox evidence、authorization discovery、raw reportの埋め込み。
- Acceptance: 複数evidenceを明示入力でき、evidence_refsだけが出力され、未指定時の既存出力が変わらない。
- Verification: PYTHONPATH=src python3 -m unittest tests.test_external_evidence_cli -v、PYTHONPATH=src python3 -m repo_health_doctor gate-check . --external-evidence /tmp/rhd-real-scan.json -- python3 -c "print('bounded')"。

### F009 / G004 — Gitleaks/OSV version assessment

- Dependency: F008。
- Scope: Gitleaks/OSV-Scannerのversion assessmentを共通statusへ揃える。
- Allowed: src/repo_health_doctor/external_scanner/、tests/test_real_gitleaks_compatibility.py、tests/test_real_osv_compatibility.py、tests/test_real_scanner_version_status.py、既存のredacted compatibility fixtures。
- Forbidden: Trivy fixture/regeneration、live scanner取得。
- Acceptance: tested、compatible_family_unverified、unsupported、denylisted、unparseableを区別し、exact fixture version以外をtestedにしない。
- Verification: PYTHONPATH=src python3 -m unittest tests.test_real_gitleaks_compatibility tests.test_real_osv_compatibility tests.test_real_scanner_version_status -v。

### F010 / G004 — Trivy compatibility対称化

- Dependency: F009。
- Scope: Trivy expected evidence、version record、regeneration script、compatibility testを追加する。
- Allowed: tests/test_real_trivy_compatibility.py、tests/fixtures/real-scanners/trivy/、scripts/regenerate_real_scanner_fixtures.py、docs/compatibility-regeneration.md、docs/real-trivy-compatibility.md。
- Forbidden: live acquisition、raw outputのcommit、Gitleaks/OSV実装変更。
- Acceptance: redacted fixtureからexpected evidenceを再現でき、fixture versionとregeneration手順が機械検証される。
- Verification: PYTHONPATH=src python3 -m unittest tests.test_real_trivy_compatibility tests.test_compatibility_regeneration_scripts -v。

### F011 / G004 — Compatibility matrixとdocs

- Dependency: F010。
- Scope: 不足fixture、Tested Versions表、Not Covered、CHANGELOG/docsを3 scannerで対称化する。
- Allowed: tests/fixtures/real-scanners/、tests/test_real_scanner_compatibility_matrix.py、docs/real-gitleaks-compatibility.md、docs/real-osv-compatibility.md、docs/real-trivy-compatibility.md、docs/compatibility-regeneration.md、CHANGELOG.md。
- Forbidden: 既存fixtureで足りるscenarioの重複追加、raw scanner output、scanner取得。
- Acceptance: 3 scannerのfixture/version/regeneration/test/Tested Versions/Not Coveredが対応し、coverage外をtestedと表現しない。
- Verification: find tests/fixtures -maxdepth 3 -type f | sort、PYTHONPATH=src python3 -m unittest tests.test_real_scanner_compatibility_matrix -v。

### F012 / G005 — Authorization discovery module

- Dependency: F011。
- Scope: git top-level、tracked判定、lstat、symlink、size、O_NOFOLLOW/fstat、bounded readを独立moduleで実装する。
- Allowed: src/repo_health_doctor/gate/authorization_discovery.py、tests/test_authorization_discovery.py。
- Forbidden: CLI dispatch、authorization validation緩和、fallback探索。
- Acceptance: untracked regular fileだけをboundedに読み、tracked/non-git/symlink/oversize/git error/file changeをreason付きで拒否する。
- Verification: PYTHONPATH=src python3 -m unittest tests.test_authorization_discovery -v。

### F013 / G005 — Discovery CLI integration

- Dependency: F012。
- Scope: gate-check trailing argv、--no-discover、explicit authorization優先をCLIへ接続する。
- Allowed: src/repo_health_doctor/cli.py、src/repo_health_doctor/gate/authorization_discovery.py、tests/test_authorization_discovery_cli.py。
- Forbidden: argv discovery、複数path探索、既存explicit validation変更。
- Acceptance: argvあり/explicitなし/no-discoverなしの場合だけrepo root候補を読み、explicit指定を常に優先する。
- Verification: PYTHONPATH=src python3 -m unittest tests.test_authorization_discovery_cli -v。

### F014 / G005 — Refusal contractとdocs

- Dependency: F013。
- Scope: discovery reason contract、.gitignore例、threat model、public contracts、docsを同期する。
- Allowed: docs/authorization-discovery.md、docs/threat-model.md、docs/public-contracts.md、docs/README.md、.gitignore、tests/test_authorization_discovery_contract.py、CHANGELOG.md。
- Forbidden: authorization code、候補artifactのcommit、残余riskの安全証明化。
- Acceptance: 全reasonとsingle-file/no-fallback/TOCTOU残riskが文書とtestで一致し、候補fileがignoreされる。
- Verification: PYTHONPATH=src python3 -m unittest tests.test_authorization_discovery_contract -v。

### F015 / G006 — rhd-moby-default-v1 package data

- Dependency: F014。
- Scope: profile、importlib.resources解決、provenance/license、wheel resource testを追加する。
- Allowed: src/repo_health_doctor/sandbox/resources/、src/repo_health_doctor/sandbox/profiles.py、pyproject.toml、tests/test_seccomp_package_resource.py、docs/seccomp-profiles.md、licenses/。
- Forbidden: locked-down名称、CLI/argv接続、profile内容の独自削減。
- Acceptance: source checkoutとinstalled wheelの双方で同一hashのrhd-moby-default-v1を解決でき、source/version/license/date/変更内容を追跡できる。
- Verification: PYTHONPATH=src python3 -m unittest tests.test_seccomp_package_resource -v、python3 -m build --wheel --no-isolation。

### F016 / G006 — --seccomp CLIとevidence

- Dependency: F015。
- Scope: runtime-defaultとrhd-moby-default-v1だけをCLI、Docker argv、evidence、draft schemaへ接続する。
- Allowed: src/repo_health_doctor/cli.py、src/repo_health_doctor/sandbox/、schemas/sandbox-run.schema.json、tests/test_seccomp_cli.py、tests/test_sandbox_run_report.py。
- Forbidden: 任意path、unconfined、default変更、candidate profile接続。
- Acceptance: defaultはruntime-defaultのままで、選択profile/hash/sourceがevidenceへ記録され、未許可値を拒否する。
- Verification: PYTHONPATH=src python3 -m unittest tests.test_seccomp_cli tests.test_sandbox_run_report -v。

### F017 / G006 — Docker argv contractとrootless

- Dependency: F016。
- Scope: Docker argv golden、禁止option、rootless detection、image compatibility docsを固定する。
- Allowed: src/repo_health_doctor/sandbox/docker_runner.py、src/repo_health_doctor/sandbox/detect.py、tests/test_sandbox_run_docker_command.py、tests/fixtures/golden/、docs/seccomp-profiles.md、docs/image-compatibility.md。
- Forbidden: 実Docker有効性の主張、auto pull、privileged/cap-add/host namespace/docker.sock。
- Acceptance: profileごとのargvがgolden一致し、禁止optionが拒否され、rootlessの検出元と未対応範囲が記録される。
- Verification: PYTHONPATH=src python3 -m unittest tests.test_sandbox_run_docker_command -v。

### F018 / G007 — Subject T0、reason台帳、expiry

- Dependency: F017。
- Scope: subject binding算出元を調査記録し、refusal reason台帳とexpiry CLI/testを追加する。
- Allowed: docs/authorization-contract.md、src/repo_health_doctor/gate/authorization.py、src/repo_health_doctor/cli.py、tests/test_execution_authorization_expiry.py。
- Forbidden: image binding、single-use、worktree enforcement。
- Acceptance: repo/commit/tree/dirty/binding_kindの算出元が記録され、expires optionsの相互排他・期限切れ拒否と既存null互換がtestされる。
- Verification: PYTHONPATH=src python3 -m unittest tests.test_execution_authorization_expiry -v。

### F019 / G007 — Authorization 0.2-draftとimage binding

- Dependency: F018。
- Scope: 0.1-draft後方互換、0.2-draft field contract、requested image reference/local image ID bindingを実装する。
- Allowed: schemas/execution-authorization.schema.json、src/repo_health_doctor/gate/authorization.py、src/repo_health_doctor/sandbox/、tests/test_execution_authorization_image_binding.py、tests/fixtures/execution-authorization/、docs/authorization-contract.md、CHANGELOG.md。
- Forbidden: single-use、worktree enforcement、RepoDigestsとimage IDの同一視。
- Acceptance: version別allowed/required fields、digest pin、exact reference、local image ID一致を検証し、旧artifactはlimitation付きで受理する。
- Verification: PYTHONPATH=src python3 -m unittest tests.test_execution_authorization_image_binding tests.test_execution_authorization -v。

### F020 / G007 — Single-use atomic reservation

- Dependency: F019。
- Scope: command直前のatomic reservation、再利用拒否、write failure、dry-run非消費を実装する。
- Allowed: src/repo_health_doctor/gate/authorization.py、src/repo_health_doctor/sandbox/run.py、tests/test_execution_authorization_single_use.py、docs/authorization-contract.md。
- Forbidden: distributed lock、central revocation、reservation削除による再利用。
- Acceptance: O_CREAT|O_EXCL reservationが実行直前に作られ、Docker起動失敗後も消費済み、gate-check/dry-runは非消費となる。
- Verification: PYTHONPATH=src python3 -m unittest tests.test_execution_authorization_single_use -v。

### F021 / G007 — Worktree direct binding

- Dependency: F020。
- Scope: workspace copy前にcommit/tree/dirtyを直接照合し、sandbox-runへ接続する。
- Allowed: src/repo_health_doctor/gate/authorization.py、src/repo_health_doctor/sandbox/run.py、src/repo_health_doctor/sandbox/run_workspace.py、tests/test_execution_authorization_worktree_binding.py、tests/test_sandbox_run_approval.py、docs/authorization-contract.md。
- Forbidden: dirty緩和flag、non-gitの暗黙許可、G008 evidence処理。
- Acceptance: mismatch/unresolved/dirtyをcommand開始前に拒否し、repo由来値ではなく直接取得値を照合する。
- Verification: PYTHONPATH=src python3 -m unittest tests.test_execution_authorization_worktree_binding tests.test_sandbox_run_approval -v。

### F022 / G008 — Sandbox evidence normalizer

- Dependency: F021。
- Scope: sandbox-run report normalizer、informational_notesとdecision_signals、golden testを実装する。
- Allowed: src/repo_health_doctor/evidence/sandbox_run.py、src/repo_health_doctor/evidence/、tests/test_sandbox_evidence_normalizer.py、tests/fixtures/golden/。
- Forbidden: gate verdict/CLI接続、raw preview/stdout/stderr/path取り込み。
- Acceptance: success/timeout/policy block/cleanup/observer/binding/fakeを区別し、成功noteはdecision signalにならない。
- Verification: PYTHONPATH=src python3 -m unittest tests.test_sandbox_evidence_normalizer -v。

### F023 / G008 — Sandbox evidence gate mapping

- Dependency: F022。
- Scope: normalized evidenceをgateへ合流し、単調性、invalid/stale/mismatch/over-budgetをtestする。
- Allowed: src/repo_health_doctor/gate/、src/repo_health_doctor/evidence/sandbox_run.py、tests/test_sandbox_evidence_gate_mapping.py。
- Forbidden: CLI/schema/docs、successによるverdict改善。
- Acceptance: successでverdict不変、問題evidenceで同じか悪化し、invalid等を黙ってskipしない。
- Verification: PYTHONPATH=src python3 -m unittest tests.test_sandbox_evidence_gate_mapping -v。

### F024 / G008 — --sandbox-evidence CLIとcross reference

- Dependency: F023。
- Scope: CLI、evidence_refs、gate/sandbox fingerprint相互参照、schema、docsを追加する。
- Allowed: src/repo_health_doctor/cli.py、src/repo_health_doctor/gate/、src/repo_health_doctor/sandbox/report.py、schemas/gate-decision.schema.json、schemas/sandbox-run.schema.json、tests/test_sandbox_evidence_cli.py、docs/public-contracts.md、docs/sandbox-run.md、CHANGELOG.md。
- Forbidden: raw report相互埋込、evidence未指定時の挙動変更。
- Acceptance: 複数evidenceのcount/size/total bytes/age/duplicateを検証し、fingerprintとrun IDだけを参照する。
- Verification: PYTHONPATH=src python3 -m unittest tests.test_sandbox_evidence_cli -v。

### F025 / G009 — Real Docker cases 1〜7

- Dependency: F024。
- Scope: opt-in test moduleでnormal/network/read-only/tmpfs/non-root/timeout/copy budgetを固定commandにより検証する。
- Allowed: tests/test_real_docker_verification.py、必要なtests fixture、観測されたtest failureに直接関係するsrc/repo_health_doctor/sandbox/ module。
- Forbidden: repo由来command、外部service request、image pull、workflow。
- Acceptance: RHD_REAL_DOCKER_TEST=1の時だけ既存local imageでcases 1〜7を実行し、original repo不変、cleanup、schema-valid evidenceを確認する。
- Verification: RHD_REAL_DOCKER_TEST=1 PYTHONPATH=src python3 -m unittest tests.test_real_docker_verification.RealDockerBoundaryCasesOneToSeven -v。

### F026 / G009 — Real Docker cases 8〜10

- Dependency: F025。
- Scope: rhd-moby-default-v1、image binding、installed package resourceのcasesとlocal手順を追加する。
- Allowed: tests/test_real_docker_verification.py、tests/test_seccomp_package_resource.py、docs/real-docker-verification.md、観測されたtest failureに直接関係するsrc/repo_health_doctor/sandbox/ module。
- Forbidden: candidate profile、image pull、Hosted run。
- Acceptance: 既存local digest-pinned imageでcases 8〜10を実行でき、未準備環境は取得せず前提不足を明示する。
- Verification: RHD_REAL_DOCKER_TEST=1 PYTHONPATH=src python3 -m unittest tests.test_real_docker_verification.RealDockerBoundaryCasesEightToTen -v。

### F027 / G009 — workflow_dispatch workflow

- Dependency: F026。
- Scope: workflow_dispatch専用workflow、digest-pinned acquisition step、runtime summary、docs、static validationを作る。
- Allowed: .github/workflows/real-docker-verification.yml、tests/test_real_docker_workflow_contract.py、docs/real-docker-verification.md、docs/image-compatibility.md、CHANGELOG.md。
- Forbidden: push/pull_request/schedule trigger、workflow起動、push、Release、unpinned image。
- Acceptance: static testがworkflow_dispatch単独、独立acquisition、sandbox --pull=never、Docker/OS/architecture summary、固定無害commandを確認する。
- Verification: PYTHONPATH=src python3 -m unittest tests.test_real_docker_workflow_contract -v。

### F028 / G010 — Seccomp Human review packet

- Dependency: F027。
- Scope: Moby defaultとsandbox用途を比較し、syscall削減候補、根拠、残riskをreview packetへ記録する。
- Allowed: docs/human-review/seccomp-review-packet.md、docs/human-review/seccomp-review-packet.json、tests/test_seccomp_review_packet.py。
- Forbidden: profile作成、package/schema/argv接続、有効化、verified表現。
- Acceptance: 候補ごとの根拠、影響case、未確認runtime、却下条件がmachine-readable packetと文書で対応する。
- Verification: python3 -m json.tool docs/human-review/seccomp-review-packet.json >/dev/null、PYTHONPATH=src python3 -m unittest tests.test_seccomp_review_packet -v。

### F029 / G010 — Unapproved candidate profile

- Dependency: F028。
- Scope: rhd-locked-down-v1候補をHuman未承認のreview artifactとして固定する。
- Allowed: docs/human-review/rhd-locked-down-v1.candidate.json、docs/human-review/seccomp-review-packet.md、docs/human-review/seccomp-review-packet.json、tests/test_seccomp_candidate_contract.py。
- Forbidden: package data、schema、CLI、Docker argv、production/default選択肢への接続、verified表現。
- Acceptance: candidate hashと削除syscallがpacketに対応し、製品resource lookupとCLIから到達不能である。
- Verification: python3 -m json.tool docs/human-review/rhd-locked-down-v1.candidate.json >/dev/null、PYTHONPATH=src python3 -m unittest tests.test_seccomp_candidate_contract -v。

### F030 / G010 — Candidate local real Docker regression

- Dependency: F029。
- Scope: candidate専用の明示test pathを作り、local real Docker結果と全failureをreview packetへ記録する。
- Allowed: tests/test_candidate_seccomp_real_docker.py、scripts/run_candidate_seccomp_review.py、docs/human-review/seccomp-review-packet.md、docs/human-review/seccomp-review-packet.json。
- Forbidden: image取得、Hosted run、candidateのproduction/default接続、失敗の隠蔽、verified表現。
- Acceptance: 既存local daemon/imageだけを--pull=neverで使用し、環境、profile hash、case別結果、failureをpacketへ記録する。test pathの完成はHuman approvalを意味しない。
- Verification: RHD_REAL_DOCKER_TEST=1 PYTHONPATH=src python3 -m unittest tests.test_candidate_seccomp_real_docker -v、python3 -m json.tool docs/human-review/seccomp-review-packet.json >/dev/null。

### F031 / G011 — Canonical agent contract

- Dependency: F024、F027、F030。
- Scope: docs/agent-contract.mdへexit 0 onlyの正準flowを記述する。
- Allowed: docs/agent-contract.md、tests/test_agent_contract_docs.py。
- Forbidden: tool別binding、README/docs index、agent設定変更、target command実行。
- Acceptance: real-scan→gate→Human authorization→sandbox→evidence還流、exit 1/2/unknown停止、gateとauthorization分離が一意に定義される。
- Verification: PYTHONPATH=src python3 -m unittest tests.test_agent_contract_docs -v。

### F032 / G011 — Tool-specific binding docs

- Dependency: F031。
- Scope: Humanが事前作成したdocs/human-review/agent-binding-official-sources.mdをread-only参照し、network accessなしでverified-as-of付きbinding docsを作る。
- Allowed: docs/integration-codex.md、docs/integration-claude-code.md、docs/integration-cursor.md、tests/test_agent_binding_docs.py。docs/human-review/agent-binding-official-sources.mdはread-only sourceとしてのみ参照する。
- Forbidden: network access、source packetの変更、account/tool設定変更、非公式情報を仕様根拠にすること、packetで未確認の強制機構やexit semanticsを推測すること。
- Acceptance: 各docがpacket由来の公式source URLと確認日を持ち、確認済み事項と未確認事項を分離し、強制機構が確認できないsurfaceはinstruction-based limitationを明記する。
- Verification: PYTHONPATH=src python3 -m unittest tests.test_agent_binding_docs -v。

### F033 / G011 — Contract docs integration

- Dependency: F032。
- Scope: docs smoke、cross-link、exit/public contract同期、README/docs index/CHANGELOGを完了する。
- Allowed: README.md、docs/README.md、docs/agent-contract.md、docs/integration-codex.md、docs/integration-claude-code.md、docs/integration-cursor.md、docs/public-contracts.md、CHANGELOG.md、tests/test_ai_agent_integration_docs.py、tests/test_agent_contract_docs.py。
- Forbidden: 製品code、target command実行、agent自動install。
- Acceptance: 全doc linkが解決し、exit tableとcanonical flowが同期し、smoke testは表示対象commandを実行しない。
- Verification: PYTHONPATH=src python3 -m unittest tests.test_ai_agent_integration_docs tests.test_agent_contract_docs -v。

### F034 / 横断品質 — Full local verification

- Dependency: F033。
- Scope: 全実装のunit/schema/CLI/public-safety/redaction/docs/diff整合を検証し、修正は失敗に直接関係する最小範囲に限る。
- Allowed: 失敗したF001〜F033の既存allowed path、tests、docs/STATUS.md、docs/features.json。
- Forbidden: Hosted workflow実行、Human seccomp承認、release操作、未関連refactor。
- Acceptance: 基本検証とschema/redaction/docs contractがgreenで、Hosted real DockerとHuman seccomp承認は未完了と記録される。
- Verification: 「基本検証」の全commandに加え、PYTHONPATH=src python3 -m unittest tests.test_schema_contracts tests.test_public_contracts -v。

### F035 / Human Gate — Machine-readable Human evidence

- Dependency: F027、F030、F034。
- Scope: docs/human-review/final-security-gates.jsonのHosted run metadataとseccomp Human approvalをvalidatorで検証する。
- Allowed: scripts/validate_final_security_gates.py、tests/test_final_security_gates.py、docs/human-review/final-security-gates.schema.json、Humanが提供するdocs/human-review/final-security-gates.jsonのread-only参照、docs/STATUS.md、F035のstatus fields。
- Forbidden: workflow起動、push、image/scanner取得、Human approvalの生成・代行、F036実装。
- Acceptance: green workflow_dispatch run、対象commit、Docker version、OS、architecture、Human approval、approved profile hashを検証する。evidence不在またはinvalidならpasses:falseのままF035をblocked:trueにし、必要なHuman操作をSTATUSへ追記する。
- Verification: python3 scripts/validate_final_security_gates.py docs/human-review/final-security-gates.json、PYTHONPATH=src python3 -m unittest tests.test_final_security_gates -v。

### F036 / 最終統合 — Approved profileの正式接続

- Dependency: F035 passes:trueかつblocked:false。
- Scope: validなHuman evidenceのapproved profile hashとcandidate hashが一致する時だけ、rhd-locked-down-v1を明示選択肢としてpackage/schema/argv/docsへ接続する。
- Allowed: F015〜F017のprofile/package/schema/argv path、tests/test_seccomp_cli.py、tests/test_sandbox_run_docker_command.py、docs/image-compatibility.md、docs/seccomp-profiles.md、docs/public-contracts.md、CHANGELOG.md、docs/STATUS.md、F036のstatus fields。
- Forbidden: evidence不在時の実装、default profile変更、approval対象外hashの接続、push/tag/Release。
- Acceptance: F035 evidenceがvalidな場合だけapproved hashを接続し、image compatibility/public contracts/CHANGELOGとfull verificationを完了する。F035未完了またはevidence invalidならpasses:falseのままF036をblocked:trueにし、成功を偽装しない。
- Verification: python3 scripts/validate_final_security_gates.py docs/human-review/final-security-gates.json、PYTHONPATH=src python3 -m unittest tests.test_seccomp_cli tests.test_sandbox_run_docker_command -v、「基本検証」の全command。

## 基本検証

各featureは専用検証に加え、開始時smokeと終了時に次を実行する。reportは/tmpへ出力し、repoへ追加しない。

~~~bash
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
~~~

## Human Reviewとblocking contract

- Hosted workflowはHumanがworkflow_dispatchから実行する。Goal Loopはpush、workflow実行、image取得、approval作成を行わない。
- Humanはgreen run URLまたはrun ID、対象commit、Docker version、OS、architecture、seccomp syscall削減の承認、approved profile hashをdocs/human-review/final-security-gates.jsonとして提供する。
- F035は初期値blocked:falseである。F035 iterationがevidence不在/invalidを検出した時だけ、passes:falseを維持してblocked:trueへ変更し、必要なHuman操作をSTATUSへ記録する。
- F036も初期値blocked:falseである。Goal Loop runnerはblocked featureを飛ばすため、F035がblockedになった後にF036が選択されても、F036自身が同じevidenceとF035状態を確認する。前提未達ならF036もpasses:false、blocked:trueとして終了する。
- F035/F036がともにblockedになると、他のfeatureが完了済みなら全未完了featureがblockedとなり、runnerは成功を偽装せず安全に停止できる。
- Human evidence追加後の再開では、人間がevidenceをreviewし、F035/F036のblocked解除とrunner再実行を明示判断する。

## Residual risk

- Scanner finding 0件、sandbox exit 0、Hosted workflow greenはいずれも安全証明ではない。
- Docker/seccomp検証は記録されたimage、Docker version、OS、architecture、dateに限定される。
- local file discoveryのTOCTOU、local single-use reservationの非分散性、未対応runtime、第三者security review未完了は残る。
- 公式tool文書のbindingはverified-as-of以後の仕様変更を自動追随しない。
- candidate seccompはF035のHuman approvalとF036の正式接続が完了するまでverifiedまたはproduction optionではない。

## Non-goals

- scannerの自動install/download、default scanからのscanner実行。
- imageの自動pull、repo由来commandのdefault CI/host実行、実malware fixture。
- malware containment、完全隔離、cloud production、実在downstream、long-running SLOの証明。
- centralized revocation、distributed atomic lock、Podman/containerd/gVisor/Kata、AppArmor/SELinux同梱。
- MCP server、agent自動install、第三者reviewの自己代替、外部公開。
- Goal Loopによるmerge、push、tag、Release。

## 判断メモ

- 2026-07-15 Human review: KICKOFFの旧11-feature planは1 process / 1 feature / 1 bounded goal契約に対して大きすぎたため、F001〜F036へ差し替えた。製品実装は未開始である。
