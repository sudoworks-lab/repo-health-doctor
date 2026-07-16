# Goal Loop STATUS

この文書はGoal Loopの実績を追記する。実装loop開始後は過去のエントリを書き換えず、各processの検証結果、判断、既知の問題、follow-upを日本語で記録する。

## 2026-07-15 JST — KICKOFF初期化とHuman plan correction

- 実施内容: KICKOFFが生成したG001〜G011の旧11-feature planをHuman reviewで差し替え、1 process = 1 feature = 1 bounded goalに合わせてF001〜F036の36 featuresへ分割した。
- 最初に着手すべき項目: F001 / G001（baseline、tag、Release、version表記の監査と文書整合）。
- 実装状態: 製品機能の実装は開始していない。36 featuresはすべてpasses:false、blocked:false、verified_at:nullで初期化した。
- 自動実装候補: F001〜F034は原則として夜間loopから外部公開や自動取得なしで進める。F030は既存local Docker daemon/imageだけを明示的opt-inで使用し、F032は公式文書のread-only確認だけを行う。
- Human Gate: F035はHumanが実行するHosted workflow_dispatchのgreen run metadataとseccomp syscall削減のHuman approvalを検証する。evidence pathはdocs/human-review/final-security-gates.jsonである。
- 最終統合: F036はF035のvalid evidenceに依存する。F035が未完了ならF036自身もevidenceを確認してblockedとなり、成功を偽装しない。
- Human review検証: Python 3.12.3でscripts/init.shを実行し、unit test 678件中675件pass、3件skip、0件fail、CLI help/version、public-safety self-scan、policy validation、JSON parseが成功した。
- Git・公開: push、tag、Releaseは行っていない。KICKOFF host commitは生成物末尾の余分な空行により失敗したままで、今回もagentはcommitしない。
- 既存管理ファイル: docs/GOAL.md、詳細設計、AGENTS.md、CLAUDE.md、PROMPT.md、Goal Loop runtimeは変更していない。
- F032のoffline化: Human review用の公式source packetを2026-07-16 JSTに追加した。F032はpacketをread-only参照し、network accessを行わない。Cursorのhook event、decision schema、exit semanticsは未確認として扱う。
- follow-up: Humanが36-feature PLAN/featuresをレビューし、承認後に新しいprocessでF001の実装loopを開始する。

## 2026-07-16 JST — F001 baselineとpublication statusの文書整合

- 今回やったこと: `e804997f94c4e2814ad4d4ca414e2ff45f553414`（2026-07-10 13:08:22 +0900）をlocal audit baselineとしてREADME、CHANGELOG、versioning、v0.1.0 release notesに記録した。local tag refsが空であること、GitHub Release statusはlocal-only auditでは未確認であること、`0.1.0`はmetadataとversioned documentationの表記であり公開済みの証拠ではないことを文書間で統一した。`pyproject.toml`のversionは変更していない。
- 検証結果: `git show --no-patch --format="%H %ad" e804997` は対象full hashと日時を返し、`git for-each-ref --format="%(refname)" refs/tags` は空だった。指定文言の`rg`確認、矛盾する`Initial Public Release`表記の不在、`git diff --check`は成功した。`tests.test_release_docs`は7件pass、全unit suiteは678件中678件実行・3件skip・0件failだった。CLI help/version、public-safety scan、policy validationは成功し、JSON reportはparseできた。
- 判断と理由: F001ではローカル情報だけを確認対象とした。外部の公開状態は確認しておらず、確認できていない事項を不存在とは記載しなかった。
- 既知の問題: GitHub Releaseの実在、公開日時、package registryへの公開状態は未確認である。local tag refsは現時点で存在しない。
- follow-up候補: Maintainerが対象remoteのGitHub Releaseとpackage publicationを人手で確認し、確認後にrelease wordingを更新する。F002以降は今回のprocessでは扱っていない。

## 2026-07-16 JST — F002 real scanner suite modelと逐次runner

- 今回やったこと: `RealScannerSuiteEntry`、`RealScannerSuiteReport`、3 scannerを固定順で処理する`run_real_scanner_suite`を実装し、unavailable、timeout、runner error後も後続entryを処理するfake runner unit testを追加した。suiteは問題発生時に`degraded`となり、各entryとreportの`execution_authorized`をfalseに固定する。
- 検証結果: `env PYTHONPATH=src python3 -m unittest tests.test_real_scanner_suite -v`は9件pass、`env PYTHONPATH=src python3 -m unittest discover -s tests -v`は682件実行・3件skip・0件failだった。CLI help/version、policy validation、JSON report生成とparse、`git diff --check`も成功した。
- 判断と理由: runnerからの例外はraw errorを保存せず、`suite_runner_error`とunknown/quarantine相当のbounded entryへ変換して処理継続する。offlineのnetwork scannerは実行せず`skipped_offline`とする。F002の専用検証は完了したが、基本検証の全green条件を満たしていないため、`docs/features.json`のF002状態は未更新とした。
- 既知の問題: `env PYTHONPATH=src python3 -m repo_health_doctor . --fail-on block --public-safety`は既存の`docs/STATUS.md:23`に対するrestricted-term検出でexit 1となった。F002の許可範囲外の過去記録は変更していない。
- follow-up候補: F001側で既存STATUS記録を人間が確認して文言を見直した後、基本検証を再実行する。

## 2026-07-16 JST — F002 mixed fake runner再検証

- 今回やったこと: F002の許可範囲内で、`run_real_scanner_suite_sequential`に対してunavailable、timeout、runner errorを1回ずつ返すmixed fake runnerテストを追加した。3 scannerの固定順処理、後続entryの処理継続、degraded、`execution_authorized=false`を同一テストで確認できるようにした。
- 検証結果: `env PYTHONPATH=src python3 -m unittest tests.test_real_scanner_suite -v`は10件pass、`env PYTHONPATH=src python3 -m unittest discover -s tests -v`は683件実行・3件skip・0件failだった。CLI help/version、policy validation、JSON report生成と`python3 -m json.tool`によるparse、`git diff --check`も成功した。
- 判断と理由: F002の実装と専用検証は受入条件を満たすが、基本検証のpublic-safetyだけは既存の`docs/STATUS.md:23`を原因にexit 1となる。STATUSはappend-onlyであり、該当過去行はF002の許可範囲外なので変更せず、`docs/features.json`のF002状態も未更新とした。
- 既知の問題: `env PYTHONPATH=src python3 -m repo_health_doctor . --fail-on block --public-safety`とJSON出力版は既存の`docs/STATUS.md:23`に対するrestricted-term検出でexit 1となった。`scripts/init.sh`は存在するが、実行は環境のapproval policyにより拒否された。
- follow-up候補: F001側で既存STATUS記録を人間が確認して文言を見直した後、基本検証を再実行する。F002以外のfeatureは今回扱っていない。

## 2026-07-16 JST — F002完了検証

- 今回やったこと: `RealScannerSuiteEntry`、`RealScannerSuiteReport`、sequential suite runnerの現行実装とfake runnerテストを再確認した。mixed runnerがunavailable、timeout、runner errorを順に返しても、3 scannerを固定順で処理し、後続entryを失わないことを確認した。
- 検証結果: `env PYTHONPATH=src python3 -m unittest tests.test_real_scanner_suite -v`は10件pass、全unit suiteは683件pass・3件skip・0件failだった。CLI help/version、public-safety、policy validation、JSON report生成とparseも成功した。
- 判断と理由: 受入条件の3 scanner処理継続、`suite_status=degraded`、reportおよびentryの`execution_authorized=false`を専用テストで確認できたため、F002を`passes: true`、`blocked: false`、検証日時をJSTで記録した。raw runner errorはentryへ保存されないことも確認した。
- 既知の問題: `scripts/init.sh`は存在確認後の実行が環境のapproval policyで拒否された。ただし、専用検証とPLANの基本検証は個別に実行し、いずれも成功した。
- follow-up候補: F002の範囲に残作業はない。F003以降のfeatureは今回扱っていない。

## 2026-07-16 JST — F003 suite schemaとformatter contract

- 今回やったこと: real scanner suite reportの`0.1-draft` schema、redactedなJSON・text・Markdown formatter、golden sample、schema/redaction/formatter contract testを追加した。新schemaを既存schema inventoryへ登録し、`docs/real-scanner-suite.md`に表示契約とredaction境界を追記した。CLI parser/dispatchとscanner subprocess実行は変更していない。
- 検証結果: `env PYTHONPATH=src python3 -m unittest tests.test_real_scanner_suite_contract -v`は3件pass、`python3 -m json.tool tests/fixtures/golden/real-scanner-suite.json`は成功、`env PYTHONPATH=src python3 -m unittest discover -s tests -v`は686件pass・3件skip・0件failだった。`bash scripts/init.sh`もPython 3.12.3、全unit、CLI help/version、public-safety、policy validation、JSON report生成・parseまで成功した。`git diff --check`も成功した。
- 判断と理由: formatterはreport modelまたはmappingを受け取り、JSON・text・Markdownの各出力直前にraw output、secret-like value、token-like value、host絶対pathをredactする設計とした。`execution_authorized=false`をschemaで固定し、goldenはscanner未実行またはoffline skipをPASSへ変換しないdegraded reportにした。schema追加に伴う既存inventory更新は、全schema contractをgreenに保つための必要最小変更である。
- 既知の問題: 実scannerのCLI配線、budget、gate integrationはF003の範囲外であり、今回扱っていない。golden sampleはredactedな固定データで、live scanner実行の証拠ではない。
- follow-up候補: F004でreal-scan CLI parser/dispatchとoffline・format/output・exit codeを接続する。

## 2026-07-16 JST — F004 real-scan CLI

- 今回やったこと: `real-scan` dispatchと専用parserを追加し、`--scanner`の複数選択、`--offline`、`--timeout`/`--timeout-seconds`、`--format`、`--output`をsequential suite runnerとredacted formatterへ接続した。degraded reportの通常exitを0、usage errorとoutput書込み失敗を2として区別し、6件のCLI contract testを追加した。
- 検証結果: `env PYTHONPATH=src python3 -m unittest tests.test_real_scan_cli -v`は6件pass、`env PYTHONPATH=src python3 -m unittest discover -s tests -v`は692件pass・3件skip・0件failだった。`env PYTHONPATH=src python3 -m repo_health_doctor real-scan . --offline --format json --output /tmp/rhd-real-scan.json`はexit 0で、`python3 -m json.tool /tmp/rhd-real-scan.json`も成功した。PLANの基本検証、`bash scripts/init.sh`、`py_compile`、`git diff --check`も成功した。
- 判断と理由: unknown scannerはargparseのusage errorとしてexit 2にし、offline時はnetwork-capable scannerをsuite側で実行せず`skipped_offline`へ正規化する。scanner不在・dirty worktreeによるdegradedはbounded reportを出力できた場合の正常CLI完了とし、F005の`--fail-on-degraded`で扱う余地を残した。output failureはreportを成功扱いせずexit 2とした。
- 既知の問題: 実repoのoffline smokeはgitleaksのdirty worktree scope ambiguityを含む`degraded` reportになったが、これは既存suiteのfail-closed契約に従う結果であり、実行認可や安全性を示さない。network-capable scannerは`skipped_offline`である。F005以降のbudget、gate integration、docs拡張は今回扱っていない。
- follow-up候補: F005でbudget、truncation、`--fail-on-degraded`を接続する。F004の範囲に残作業はない。

## 2026-07-16 JST — F005 real-scan budget、degraded停止、offline CI smoke

- 今回やったこと: `run_real_scanner_suite`にper-scanner finding budget、suite finding budget、compact JSON report byte budget、normalized text field上限を追加した。超過時は保持したfinding数、`omitted_finding_count`、`truncated`、machine-readable limitationをentry/reportへ残し、suiteを`degraded`へ固定する。CLIへ`--max-findings-per-scanner`、`--max-findings`、`--max-report-bytes`、`--fail-on-degraded`を追加し、degraded report出力後のexit 1を接続した。CIへscanner取得なしのoffline real-scan smokeを追加し、README、docs、CHANGELOGへlive opt-in、authorization非付与、budgetと利用制約を記録した。F005専用テストを4件追加した。
- 検証結果: `env PYTHONPATH=src python3 -m unittest tests.test_real_scan_budget tests.test_real_scan_cli -v`は10件pass・0件fail、`env PYTHONPATH=src python3 -m unittest discover -s tests -v`は696件pass・3件skip・0件failだった。`rg -n "offline|opt-in|truncated|omitted|fail-on-degraded|authorization" .github/workflows/ci.yml README.md docs/real-scanner-suite.md CHANGELOG.md`は必要な文言を確認した。`env PYTHONPATH=src python3 -m repo_health_doctor real-scan . --offline --fail-on-degraded --format json --output /tmp/rhd-real-scan.json`はdegraded reportを出力してexit 1、`python3 -m json.tool /tmp/rhd-real-scan.json`は成功した。実repoではGitleaksがdirty worktree scope ambiguityでfail-closed、OSV-ScannerとTrivyは`skipped_offline`だった。`python3 -m py_compile ...`、`git diff --check`、PLANの`find`、`wc`、CLI help/version、public-safety scan、policy validation、default JSON report parseも成功した。`bash scripts/init.sh`は開始時にPython 3.12.3、692件pass・3件skip・0件failを確認した。
- 判断と理由: report schemaの`schema_version`、既存`rule_id`、既存entry fieldを変更せず、budget結果は既存の`omitted_finding_count`、`truncated`、`limitations`へ正規化した。byte budgetはcompact JSONのサイズで測り、schema-validなreportを保つためfindingを後方entryから削減する。offline smokeでは意図的なnetwork scanner skipを`--fail-on-degraded`で失敗にできるため、CI smoke自体は通常exitでschema/redactionだけを確認する。real-scanはdefault scanから分離し、live実行は明示的なoperator opt-in、reportはexecution authorizationでも安全証明でもないとした。
- 既知の問題: live OSV-Scanner/Trivyはnetwork、cache、database状態を伴うため実行していない。dirty worktreeの実repo smokeはclean commit bound evidenceではない。これらはF005の利用制約であり、今回の検証失敗ではない。
- follow-up候補: F006でtruncated reportを含むexternal suite evidenceのschema、fingerprint、subject、age、size validationへ接続する。F005以外のfeatureは今回扱っていない。

## 2026-07-16 JST — F006 external suite evidence validation

- 今回やったこと: `real_scanner_suite`の入力を静的に検証する`validate_external_suite_evidence`を追加した。closed schema shape、canonical SHA-256 fingerprint、期待subject、24時間のage、256 KiBの入力size、既知fingerprintとのduplicate、entry/report truncationを検証し、invalid、fingerprint mismatch、stale、subject mismatch、over-budget、duplicate、truncatedを機械可読reasonで返す。validation結果はboundedな`evidence_ref`だけを持ち、raw `entries`や`normalized_result`を保持しない。risk mapper、gate verdict、CLI配線は変更していない。
- 検証結果: `env PYTHONPATH=src python3 -m unittest tests.test_external_suite_evidence -v`は8件pass・0件failで、valid、`external_evidence_invalid`、`external_evidence_stale`、`external_evidence_subject_mismatch`、`external_evidence_over_budget`、`external_evidence_duplicate`、`external_evidence_truncated`を確認した。fingerprint mismatchはinvalidと`external_evidence_fingerprint_mismatch`を同時に返す。`bash scripts/init.sh`はPython 3.12.3で全unit 704件pass・3件skip・0件fail、CLI help/version、public-safety、policy validation、JSON report生成・parseまで成功した。`python3 -m py_compile`と`git diff --check`も成功した。
- 判断と理由: report生成側の既存256 KiB budgetを入力側でも再利用し、ageは24時間、未来時刻の許容skewは5分に限定した。truncated evidenceは成功扱いせず、dedupe済みreasonを返してfail-closedにした。draft schemaと既存`rule_id`は変更していない。
- 既知の問題: fileの実byte sizeはJSON parse前にcallerが測定して`source_size_bytes`へ渡す必要がある。F006は静的validatorだけであり、file loader、risk mapping、gate decision、CLI接続は実装していない。
- follow-up候補: F007でvalidated suite findingと既存risk mapperを接続し、success evidenceでverdictを改善しない単調性を検証する。F006以外のfeatureは今回扱っていない。
