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

## 2026-07-16 JST — F007 external suite risk mappingとverdict単調性

- 今回やったこと: validated external suite reportをgate evaluatorへ渡す入力境界を追加し、completed entryの`normalized_result`を既存の`validate_external_scanner_result`と`map_external_scanner_risk`へ接続した。completed/no-findingはverdict候補を追加せず、suite validation失敗、未完了entry、unverified scannerはunknown方向へ、既存risk ruleのfindingはwarn、quarantine、blockの悪化方向へだけ反映する。raw `entries`と`normalized_result`はgate decisionへ埋め込まない。`secret_like_value`が既存RISK001を発火してlive executionをblockする横断testも追加した。
- 検証結果: `env PYTHONPATH=src python3 -m unittest tests.test_external_suite_gate_mapping tests.test_external_scanner_risk_mapper -v`は11件pass・0件failで、5段階の既存verdictに対するcompleted/no-finding不変、invalid、unavailable、unverified、vulnerability findingの単調性、`secret_like_value`のRISK001経由BLOCKを確認した。全unit suiteは708件pass・3件skip・0件failだった。PLANの`find`、`wc`、CLI help/version、public-safety scan、policy validation、default JSON report生成・parse、`py_compile`、`git diff --check`も成功した。
- 判断と理由: suite validationが成功したentryだけを既存risk mapperへ渡し、問題signalは`strongest_verdict`の候補追加だけで合流させることで、既存verdictを改善できない構造にした。invalidまたは未完了entryのraw内容は解釈せずunknownへ固定し、validated findingでもraw scanner内容はgate decisionへ転記せず、固定IDと既存RISK rule IDだけをreasonとして残す。
- 既知の問題: 指定test commandの直接表記とJSON parserの`>/dev/null`付き表記は実行環境のapproval policyによりprocess生成前に拒否された。同じcommandを`env PYTHONPATH=src`で実行し、JSON parserは出力抑制を外して実行したところ、いずれもexit 0で成功した。これは環境差分であり、testまたはparseの失敗ではない。
- follow-up候補: F008でCLIからexternal suite evidenceをboundedに受け取り、gate decisionにはraw reportではなく`evidence_refs`だけを記録する。F008以降のfeatureは今回扱っていない。

## 2026-07-16 JST — F008 gate-check external evidence CLI

- 今回やったこと: `gate-check`へ繰り返し指定可能な`--external-evidence`を追加し、最大16件、各256 KiBのbounded read、24時間のage、現在repoのcommitとdirty state、schema、fingerprint、duplicate、truncationを既存validatorで検証するよう接続した。gate decision schemaにはoptionalな`evidence_refs`を追加し、report kind、fingerprint、生成日時、bounded subject、byte数、truncation、validation status、machine-readable reasonだけを残す。raw suite report、`entries`、`normalized_result`、入力pathは出力へ埋め込まない。未指定時は`evidence_refs` field自体を追加せず、既存出力shapeを維持した。指定smokeのtrailing argvは受理するが実行せず、authorization未指定なら従来どおりexit 2でfail-closedにする。
- 検証結果: `env PYTHONPATH=src python3 -m unittest tests.test_external_evidence_cli -v`は4件pass・0件failで、CLI、gate schema、複数入力とduplicate reason、invalid JSON、未指定時互換、text smokeのraw report不在を確認した。F006/F007、gate model、既存gate-check、schema、public contract、formatterの回帰46件もpassした。`env PYTHONPATH=src python3 -m repo_health_doctor real-scan . --offline --format json --output /tmp/rhd-real-scan.json`はexit 0でbounded reportを生成し、指定の`gate-check . --external-evidence /tmp/rhd-real-scan.json -- python3 -c "print('bounded')"`は意図どおりauthorization missingのexit 2となり、1件のfingerprint、`status=valid`、reasonだけを表示した。全unit suiteは712件pass・3件skip・0件failだった。
- 判断と理由: `evidence_refs`をoptionalにし、external evidence指定時だけ追加することで未指定時の既存出力を変えない。file pathは保存せず、invalid JSONやover-budget inputも黙ってskipせずinvalidなbounded referenceへ変換する。trailing argvによるauthorization discoveryはF013の範囲なので実装せず、明示authorizationは従来の`--authorization`と`--argv-json`に限定した。
- 既知の問題: 指定test commandの`PYTHONPATH=src`直接表記は実行環境のapproval policyによりprocess生成前に拒否されたため、同値の`env PYTHONPATH=src`で実行しexit 0を確認した。実repoのoffline suiteはdirty worktreeとnetwork scanner skipによりdegradedだが、これは既存のfail-closed契約に従う結果である。
- follow-up候補: F008の範囲に残作業はない。F009以降のfeatureは今回扱っていない。

## 2026-07-16 JST — F009 Gitleaks/OSV version assessment

- 今回やったこと: GitleaksとOSV-Scannerに共通のversion assessmentを追加し、既存fixtureのexact versionだけを`tested`、同一majorの別versionを`compatible_family_unverified`、別majorを`unsupported`、明示denylistを`denylisted`、安全にparseできない出力を`unparseable`として区別した。compatible familyは実行可能のままentryへwarningを残し、real scanner suite全体を`degraded`にするよう接続した。Trivy、fixture、schema version、既存`rule_id`は変更していない。
- 検証結果: 指定の3-module検証を同値の`env PYTHONPATH=src python3 -m unittest tests.test_real_gitleaks_compatibility tests.test_real_osv_compatibility tests.test_real_scanner_version_status -v`で実行し、18件pass・0件failだった。test出力でGitleaks 8.27.2とOSV-Scanner 2.0.3だけが`tested`となり、同一familyの別versionが`compatible_family_unverified`かつsuite `degraded`になることを確認した。suite、formatter、budget、CLI、両adapterの回帰60件は59件pass・1件skip・0件fail、全unit suiteは717件pass・3件skip・0件failだった。CLI help/version、public-safety、policy validation、JSON report生成・parse、docs/fixture一覧、AGENTS行数、`git diff --check`も成功した。
- 判断と理由: major versionの一致だけではfixtureで観測した出力互換性を証明できないため、exact fixture version以外を`tested`へ昇格させない。denylistは各scanner policyに明示し、`unsupported`より先に評価することで両statusを機械的に区別する。version出力はscanner名付きまたはbare versionの1行だけを受理し、任意文字列からversionらしい部分を抽出しない。
- 既知の問題: 指定commandの先頭`PYTHONPATH=src`形式とJSON parserの`>/dev/null`付き形式は実行環境のapproval policyによりprocess生成前に拒否されたため、同値の`env PYTHONPATH=src`形式と出力抑制なしのJSON parseで検証した。live scannerの取得は行っていない。local Gitleaks binaryが存在する環境の既存optional adapter testは実行されたが、network accessやfixture再生成は行っていない。
- follow-up候補: F010のTrivy compatibility対称化とF011の3 scanner文書matrixは今回扱っていない。F009の範囲に残作業はない。

## 2026-07-16 JST — F010 Trivy compatibility資材

- 今回やったこと: `tests/fixtures/real-scanners/trivy/`へTrivy 0.69.3のversion record、raw scanner fieldを含まないsynthetic license fixture、bounded expected evidenceを追加した。redacted fixtureを現行adapterでnormalizeしてexpected evidenceを再生成または照合するoffline Python helperと、version、redaction、非認可、再生成、文書境界を固定するcompatibility testを追加し、2つのcompatibility文書へHuman-approved raw collectionと`/tmp`境界を記録した。
- 検証結果: 指定の`env PYTHONPATH=src python3 -m unittest tests.test_real_trivy_compatibility tests.test_compatibility_regeneration_scripts -v`は最終的に9件pass・0件failだった。初回は文書中の正規なpublic ECR domainをprivate config markerとして拾うtest過検知と、adapter findingのgate effectを別mapperの返値へ誤適用したtest期待により2件failし、製品codeを変えずtest主張を実契約へ修正した。指定の`find tests/fixtures/real-scanners/trivy -maxdepth 2 -type f | sort`はfixture、expected evidence、version recordの3件を返し、raw field、secret-like pattern、private path検査は無検出だった。全unit suiteは722件pass・3件skip・0件fail、CLI help/version、public-safety、policy validation、JSON report生成・parse、`git diff --check`、docs/fixture一覧、AGENTS行数も成功した。
- 判断と理由: 既存のvulnerability、misconfiguration、secret、no-finding fixtureを重複させず、設計で未充足だったlicense含有scenarioだけを追加した。再生成helperはscanner取得やraw output読込みを行わず、Humanがreview・redactしたcommitted fixtureからexpected evidenceだけを決定的に生成する境界とした。
- 既知の問題: live Trivy実行、imageまたはscanner取得、raw output収集は実施していない。fixtureは安全なsynthetic compatibility資材であり、実repoの安全性やexecution authorizationを証明しない。
- follow-up候補: F011で3 scannerのTested Versions表、Not Covered、追加fixture、CHANGELOGを対称化する。F011は今回のprocessでは扱っていない。

## 2026-07-16 JST — F011 3 scanner compatibility matrixと文書対称化

- 今回やったこと: Gitleaks、OSV-Scanner、Trivyの各compatibility文書へ`Tested Versions`、追加scenario、regeneration、`Not Covered`を同じ構成で追加し、5つのversion statusとCHANGELOGを同期した。新しいmatrix testはGitleaks dirty worktree/SARIF、OSV exit 128/exit-report mismatch、Trivy license/exit-report mismatch、3 scannerのversion parse failureを既存のredacted fixtureで確認する。
- 検証結果: 指定testと同値の`env PYTHONPATH=src python3 -m unittest tests.test_real_scanner_compatibility_matrix -v`は5件pass・0件fail、関連compatibility回帰は32件pass・0件failだった。指定`rg -n "Tested Versions|Not Covered|compatible_family_unverified|unsupported|denylisted|unparseable" docs/real-*compatibility.md docs/compatibility-regeneration.md CHANGELOG.md`は3 scanner文書、runbook、CHANGELOGの記載を確認した。`find tests/fixtures -maxdepth 3 -type f | sort`、`git diff --check`、docs一覧、AGENTS 77行も成功した。終了時`bash scripts/init.sh`はPython 3.12.3で全unit 727件pass・3件skip・0件fail、CLI help/version、public-safety、policy validation、JSON report生成・parseまで成功した。
- 判断と理由: 設計で求める追加scenarioは既存fixtureへdirty stateまたはexit outcomeを組み合わせれば再現できるため、禁止されている重複fixtureを追加しなかった。Tested Versions表はfixture exact versionのGitleaks 8.27.2、OSV-Scanner 2.0.3、Trivy 0.69.3だけに限定し、同一familyや未検証releaseへtested coverageを広げなかった。
- 既知の問題: 指定commandの先頭`PYTHONPATH=src`形式は実行環境のapproval policyによりprocess生成前に拒否されたため、同値の`env PYTHONPATH=src`形式で実行した。live scanner、network、image/scanner取得、raw output収集は実施しておらず、fixture結果は安全証明やexecution authorizationではない。
- follow-up候補: F011の範囲に残作業はない。F012以降のfeatureは今回扱っていない。

## 2026-07-16 JST — F012 authorization discovery module

- 今回やったこと: Git top-levelの完全一致と`git ls-files --error-unmatch`によるtracked判定を行い、repo rootの`.repo-health-doctor.authorization.json`だけを読む独立moduleを追加した。untrackedなregular fileに限定し、`lstat`、symlink拒否、64 KiB上限、利用可能時の`O_NOFOLLOW`、open後と読取後の`fstat`、bounded read、JSON object判定を通過した場合だけartifactを返す。拒否時はpathやGit stderrを保持せず、`tracked_refused`、`not_a_git_repo`、`symlink_refused`、`not_found`、`parse_failed`、`too_large`、`git_error`、`file_changed`のmachine-readable reasonを返す。
- 検証結果: 指定testと同値の`env PYTHONPATH=src python3 -m unittest tests.test_authorization_discovery -v`は12件pass・0件failだった。test出力でuntracked成功、tracked、non-git、symlinkとbroken symlink、oversize、Git unavailable、読取中変更、`lstat`後のfile replacementを確認し、`O_NOFOLLOW`、複数回`fstat`、max bytes + 1のbounded readも直接検証した。終了時`bash scripts/init.sh`はPython 3.12.3で全unit 739件pass・3件skip・0件fail、CLI help/version、public-safety、policy validation、JSON report生成・parseまで成功した。`py_compile`、secret-like pattern検査、PLANのdocs/fixture一覧とAGENTS 77行も成功した。
- 判断と理由: tracked判定をfile openより前に行い、Gitのunexpected exit、timeout、実行不能をすべて`git_error`へ閉じた。`lstat`とopen後`fstat`のdevice、inode、mode、size、mtime、ctimeを比較し、読取後にも同じ状態とbyte数を照合することで観測可能なfile差替え・変更を拒否する。discovery結果は既存authorization validatorを緩和せず、CLI接続も行わない独立境界に限定した。
- 既知の問題: 指定commandの先頭`PYTHONPATH=src`形式は実行環境のapproval policyによりprocess生成前に拒否されたため、同値の`env PYTHONPATH=src`形式で検証した。local write可能processとのTOCTOUを完全には排除できず、moduleはartifactを発見するだけでexecution authorizationを付与しない。
- follow-up候補: F013で明示authorization優先、trailing argv条件、`--no-discover`をCLIへ接続し、F014でreason contractとTOCTOU残余riskを文書化する。F013以降は今回のprocessでは扱っていない。

## 2026-07-16 JST — F013 gate-check authorization discovery CLI接続

- 今回やったこと: `gate-check`へ`--no-discover`を追加し、trailing argvが存在し、explicit authorizationが指定されていない場合だけrepo rootの単一候補をdiscoveryするよう接続した。explicit authorizationはtrailing argvと併用した場合も常に優先し、argv-jsonは従来どおりexplicit authorizationとの組み合わせに限定した。候補の検証は既存の`validate_execution_authorization`へ渡し、候補がない場合や`--no-discover`時に別pathへfallbackしないことを固定した。
- 検証結果: `bash scripts/init.sh`はPython 3.12.3で全unit 739件pass・3件skip・0件fail、CLI help/version、public-safety、policy validation、JSON report生成・parseまで成功した。指定の`PYTHONPATH=src python3 -m unittest tests.test_authorization_discovery_cli -v`は実行環境のapproval policyでprocess生成前に拒否されたため、同値の`env PYTHONPATH=src python3 -m unittest tests.test_authorization_discovery_cli -v`を実行し5件pass・0件failを確認した。専用testではargv非discover、single candidate、explicit優先、`--no-discover`、nested候補へのfallbackなしを確認した。関連回帰30件と全unit suite 744件は全件pass・3件skip・0件fail、`python3 -m py_compile`、`git diff --check`、CLI help/version、public-safety、policy validation、JSON outputと`python3 -m json.tool`によるparseも成功した。
- 判断と理由: discoveryはcommand実行対象を示すtrailing argvがある時だけ有効にし、argvのないgate-checkの従来のauthorization missing挙動を維持した。explicit authorizationを先に処理することで、候補fileが存在しても明示入力を上書きせず、`--no-discover`はexplicit authorizationの利用を妨げない。候補はF012のsingle-file fail-closed moduleだけに委譲し、複数path探索やvalidation緩和は追加していない。
- 既知の問題: 指定test commandの直接表記は実行環境のapproval policyにより実行できず、`env PYTHONPATH=src`の同値commandで検証した。discovery refusal reasonの文書同期はF014の範囲であり、今回変更していない。
- follow-up候補: F013の範囲に残作業はない。F014以降のfeatureは今回扱っていない。

## 2026-07-16 JST — F014 discovery refusal contractと文書同期

- 今回やったこと: discoveryの8つのmachine-readable refusal reasonを一覧化する`docs/authorization-discovery.md`を追加し、single top-level candidate、`.gitignore`例、explicit authorization優先、trailing argv、`--no-discover`、no-fallback、TOCTOU残余risk、`execution_authorized`非付与を記録した。`docs/threat-model.md`、`docs/public-contracts.md`、`docs/README.md`、`CHANGELOG.md`を同じcode contractへ同期し、`.repo-health-doctor.authorization.json`を`.gitignore`へ追加した。`tests/test_authorization_discovery_contract.py`で実装定数と文書を照合する4件の契約テストを追加した。authorization codeと候補artifactは変更・作成していない。
- 検証結果: `env PYTHONPATH=src python3 -m unittest tests.test_authorization_discovery_contract -v`は4件pass・0件fail。指定の`rg -n "tracked_refused|not_a_git_repo|symlink_refused|not_found|parse_failed|too_large|git_error|file_changed|TOCTOU|fallback" docs/authorization-discovery.md docs/threat-model.md docs/public-contracts.md .gitignore`は全reason、TOCTOU、fallbackの記載を確認した。`env PYTHONPATH=src python3 -m unittest discover -s tests -v`は748件pass・3件skip・0件fail、CLI help/version、public-safety scan、policy validation、JSON report生成と`python3 -m json.tool`によるparse、`git diff --check`も成功した。指定の`PYTHONPATH=src`直接表記は環境のprocess生成ポリシーで拒否されたため、同値の`env PYTHONPATH=src`で検証した。
- 判断と理由: refusal reasonの正本は`src/repo_health_doctor/gate/authorization_discovery.py`の既存定数とし、文書側でreasonを再定義しないよう契約テストから直接参照した。discoveryは単一候補のbounded input lookupに限定し、拒否時の探索拡大、成功時の安全証明、実行認可への昇格を文書化しなかった。lstat/open/fstat/readで観測可能な変更を拒否する一方、local writerとのTOCTOUを完全排除できない残余riskとして明記した。
- 既知の問題: 環境差分により指定commandの直接表記は実行できない。local writer raceの完全排除とsecurity reviewは今回の文書同期で解決していない。
- follow-up候補: F015以降のfeatureは今回扱っていない。discoveryの実行認可強化やTOCTOU対策の追加は、後続featureの許可範囲で扱う。

## 2026-07-16 JST — F015 package dataとwheel resource検証

- 今回やったこと: `rhd-moby-default-v1`のseccomp JSON、provenance sidecar、Apache-2.0 licenseを`repo_health_doctor.sandbox.resources`のpackage dataとして追加した。`profiles.py`に`importlib.resources`で固定profileだけを解決する`resolve_seccomp_profile()`と、profile resource bytesのSHA-256を返す`SeccompProfileResource`を追加し、任意filesystem pathや`locked-down`名は受け付けないようにした。setuptoolsのpackage-data設定、専用test、`docs/seccomp-profiles.md`、Moby license fileを追加した。CLI、argv、既存の`locked-down`挙動、schema、別featureは変更していない。
- 検証結果: `env PYTHONPATH=src python3 -m unittest tests.test_seccomp_package_resource -v`は3件pass・0件failだった。source checkoutの`importlib.resources`解決、provenanceのsource/version/license/date/change、profile hash、任意path拒否、local wheel install後の同一hashを確認した。`env PYTHONPATH=src python3 -m unittest discover -s tests -v`は751件pass・3件skip・0件failだった。`bash scripts/init.sh`、CLI help/version、public-safety scan、policy validation、JSON report生成とparse、`python3 -m py_compile`、`git diff --check`も成功した。`python3 -m pip wheel . --no-deps --no-build-isolation --wheel-dir /tmp/rhd-f015-wheel`は成功し、wheel listingでprofile、provenance、license、resource packageが収録されていることを確認した。
- 判断と理由: profile hashはJSONの再シリアライズ結果ではなく、source/wheel双方のpackage data bytesから計算し、provenance sidecarのhashと解決時に照合する設計にした。F015の許可範囲ではCLI/argv接続と実Docker有効性の主張を行わず、`locked-down`を新しいseccomp profile名として追加していない。profileの実Docker有効性とcandidateのHuman approvalは後続featureの範囲である。
- 既知の問題: 指定された`python3 -m build --wheel --no-isolation`は環境に`build` moduleがなく、`/usr/bin/python3: No module named build.__main__; 'build' is a package and cannot be directly executed`で終了コード1となった。`/tmp`からの同コマンドも`No module named build`で実行できなかった。依存取得やnetwork accessは行わず、同じpyproject backendでの`pip wheel`代替検証と専用wheel resource testを実行した。このため`docs/features.json`のF015は`passes:false`、`verified_at:null`、`blocked:false`のままにした。Moby runtimeでの実効性も今回未確認である。
- follow-up候補: `build` packageを備えた検証環境で指定の`python3 -m build --wheel --no-isolation`を再実行し、F015の状態を更新する。F016以降のfeatureは今回扱っていない。

## 2026-07-16 JST — F015再検証 attempt 2

- 今回やったこと: F015の既存package data実装を変更せず、指定された専用testとwheel検証を再実行した。source checkoutと一時wheel installの`importlib.resources`解決、provenance、Apache-2.0 license、profile hashの一致を再確認し、boundedな証拠をrunner指定のiteration evidenceへ記録した。
- 検証結果: `scripts/init.sh`はexit 0で、Python 3.12.3、751件pass・3件skip・0件failだった。`env PYTHONPATH=src python3 -m unittest tests.test_seccomp_package_resource -v`は3件pass・0件failだった。`python3 -m pip wheel . --no-deps --no-build-isolation --wheel-dir /tmp/rhd-f015-attempt2-wheel`はexit 0だった。
- 判断と理由: 指定の`python3 -m build --wheel --no-isolation`は再実行しても、activeな`/usr/bin/python3`に実行可能な`build.__main__`がないためexit 1となった。network accessや依存取得は行わず、実装側の専用testと同じsetuptools backendによるoffline代替buildの成功だけを確認した。このためF015は`passes:false`、`blocked:false`、`verified_at:null`のままとした。
- 既知の問題: `python3 -m build`を実行するPyPA `build` packageが検証環境にない。指定された直接の`PYTHONPATH=src ...`表記もprocess生成ポリシーにより拒否され、同値の`env PYTHONPATH=src ...`で実行した。Moby runtimeでの実効性はF015の対象外で未確認である。
- follow-up候補: `build` packageを備えた検証環境で指定buildを再実行し、成功した場合にのみF015の状態を更新する。F016以降のfeatureは今回扱っていない。

## 2026-07-16 JST — F015 Human wheel検証完了

- 今回やったこと: repo rootのignored `build/`がPython namespace packageとして誤認される状態を確認し、tracked fileがないこととignore対象であることを確認して削除した。PyPA `build` packageは未導入であることを確認した。
- 検証結果: `tests.test_seccomp_package_resource`、`pip wheel --no-deps --no-build-isolation`、wheel内resource収録、source/wheel SHA-256一致、`scripts/init.sh`、public-safety、policy validation、JSON parse、`git diff --check`が成功した。
- Human判断: F015の受入条件はsource checkoutとinstalled wheelから同一hashでresourceを解決できることである。同一build backendによるoffline wheelと専用testで条件を満たしたため、frontendである`python3 -m build`の不在だけを理由に未完了とはしない。
- 状態更新: F015をpasses:true、blocked:false、verified_at:2026-07-16T17:52:57+09:00へ更新した。
- 制約: network access、依存取得、CLI/argv接続、Docker実効性の主張、他featureの検証緩和は行っていない。

## 2026-07-16 JST — F016 --seccomp CLIとevidence

- 今回やったこと: `sandbox-run`へ`--seccomp`を追加し、`runtime-default`と`rhd-moby-default-v1`だけを受理するようにした。既定値は`runtime-default`のままとし、同梱profile選択時だけ検証済みpackage bytesを使い捨てrun rootへ上書き不可でmaterializeして、Docker argvへ`--security-opt seccomp=...`を追加する。evidenceにはprofile、SHA-256、sourceを閉じたdraft schemaで記録し、一時pathはredactする。
- 検証結果: 指定された先頭`PYTHONPATH=src`形式の専用commandは実行環境のprocess生成ポリシーにより開始前に拒否されたため、同値の`env PYTHONPATH=src python3 -m unittest tests.test_seccomp_cli tests.test_sandbox_run_report -v`を実行し7件pass・0件failだった。test出力でruntime-default既定、任意pathと`unconfined`の非表示拒否、同梱profileのDocker argv、profile hash、source、schema validationを確認した。全unit suiteは755件pass・3件skip・0件failで、PLANの基本検証、sandbox-run help、schema JSON parse、対象fileのcompile、`git diff --check`も成功した。
- 判断と理由: `runtime-default`ではseccomp用Docker optionを追加せず、従来のruntime既定挙動を維持する。同梱profileだけはhash検証済みのpackage dataと同じbytesをDockerへ渡し、evidenceではruntime管理とpackage dataを区別する。任意入力をargparseの既定errorへ渡すと入力pathを表示し得るため、未許可値を含めない固定errorへ変換した。
- 既知の問題: 実Dockerでのprofile有効性はG009の対象であり、今回のfake runnerとdry-runでは確認していない。全profile組合せのargv goldenとrootless制約はF017の対象であり、今回変更していない。
- follow-up候補: F017でDocker argv golden、禁止option、rootless検出と制約を指定範囲内で検証する。F016以外のfeatureには着手していない。

## 2026-07-16 JST — F017 Docker argv contractとrootless制約

- 今回やったこと: 実装済み4 sandbox profileと`runtime-default` / `rhd-moby-default-v1`の8組合せを`tests/fixtures/golden/sandbox-run-docker-argv.json`で固定した。Docker argv guardは`--pull=never`と`--network none`を各1回必須とし、非`never` pull、`seccomp=unconfined`、`apparmor=unconfined`、privileged、cap-add、host namespace、docker.sock mountを拒否する。rootless / userns-remapは`docker info`の`SecurityOptions` string arrayだけから判定し、取得失敗やunexpected shapeを`unknown`に保つ。`docs/seccomp-profiles.md`を現行CLI契約へ同期し、`docs/image-compatibility.md`へ実Docker未検証の前提とplatform制約を記録した。
- 検証結果: 指定された先頭`PYTHONPATH=src`形式は実行環境のprocess生成ポリシーにより開始前に拒否されたため、同値の`env PYTHONPATH=src python3 -m unittest tests.test_sandbox_run_docker_command -v`を実行し12件pass・0件failだった。指定の`rg -n "rootless|rhd-moby-default-v1|runtime-default|--pull=never|limitation" docs/seccomp-profiles.md docs/image-compatibility.md`、golden JSON parse、対象fileの`py_compile`、`git diff --check`は成功した。全unit suiteは760件pass・3件skip・0件failで、CLI help/version、public-safety scan、policy validation、JSON report生成とparseも成功した。
- 判断と理由: golden対象はrunnerへ到達できる`implemented=true`のprofileだけとし、未実装の`dev-permissive`と`network-explicit`を実行可能なargvとして固定しなかった。testは実装済みprofile集合とgolden key集合を一致させるため、将来profileを有効化した際は明示的なgolden更新が必要になる。rootless markerの不在を`false`にするのはvalidなstring arrayの場合だけとし、観測不能を誤ってrootfulと断定しない。
- 既知の問題: 実Docker daemonやimageでは実行しておらず、seccomp、rootless、user namespace、mount、resource limitの実効性とimage互換性は未確認である。rootless検出は`SecurityOptions` markerの観測であり、環境適合や完全な隔離を示さない。先頭環境代入形式と`/dev/null` redirect付きcommandはこの実行環境でprocess生成前に拒否された。
- follow-up候補: G009のHuman-triggered real Docker検証で、exact image identity、Docker version、OS/architecture、profile別結果、残ったlimitationを`docs/image-compatibility.md`へ追記する。F018以降は今回のprocessでは扱っていない。
- commit request: 指定された`python3 -m json.tool "$GOAL_LOOP_COMMIT_REQUEST"`は環境変数展開を含むprocess生成がポリシーで拒否されたため、同じファイルを明示pathで検証しJSON parseに成功した。requestには今回変更した7ファイルだけを列挙し、`logs/`自体は対象外にした。
