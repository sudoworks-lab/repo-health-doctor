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

## 2026-07-16 JST — F018 subject binding T0、refusal reason台帳、expiry CLI

- 今回やったこと: 現行gate decision subjectの算出経路を調査し、`repo=<repo>`、`commit=null`、`tree_hash=null`、`binding_kind=path_bound`で、dirty fieldとsandbox-run workspace copy前の直接Git照合が存在しないことを`docs/authorization-contract.md`へT0根拠として記録した。authorization validatorの27 refusal reasonとdiscoveryの8 refusal reasonに加え、gate-check / sandbox-run統合reasonを台帳化した。`authorization draft`へ相互排他の`--expires-in-minutes`と`--expires-at`を追加し、未指定時は従来の`expires_at:null`を維持してapproval前の設定を求めるlimitationを付けた。
- 検証結果: 指定testと同値の`env PYTHONPATH=src python3 -m unittest tests.test_execution_authorization_expiry -v`は8件pass・0件failで、相互排他、正の分数、60分を固定上限にしないこと、不正ISO 8601、期限切れ拒否、従来null、refusal reason文書同期、T0根拠を確認した。指定の`rg -n "repo|commit|tree|dirty|binding_kind|expires-in-minutes|expires-at|refusal" docs/authorization-contract.md`は必要な全項目を確認した。関連回帰30件とfull suite 768件は全件pass・3件skip・0件failだった。CLI helpと実draft JSON parse、PLANのdocs/fixture一覧、AGENTS 77行、CLI help/version、public-safety、policy validation、default JSON report parse、`py_compile`、`git diff --check`も成功した。新規文書とtestを明示指定したpublic-text検査は2 files・0 findingsだった。
- 判断と理由: expiry option未指定は0.1-draftの従来shapeを保ち、null artifactを実行可能にはせず`expires_at_required`でfail-closedにする。`--expires-in-minutes`の60分以内は推奨に留め、正の整数以外の固定policyを追加しない。T0調査で未実装と確認したdirect repo / commit / tree / dirty bindingをF018へ先取り実装せず、現行のpath-bound制約を明示した。
- 既知の問題: 現行authorization subjectはrepository identity、HEAD commit、HEAD tree、dirty statusを直接照合しない。image binding、single-use reservation、workspace copy前のworktree direct bindingは今回の許可範囲外で未実装である。指定test commandの先頭`PYTHONPATH=src`形式はprocess生成前に実行環境のapproval policyで拒否されたため、同値の`env PYTHONPATH=src`形式で実行した。
- follow-up候補: 後続の指定featureでimage binding、single-use、worktree direct bindingをそれぞれ実装・検証する。F018以外のfeatureには着手していない。

## 2026-07-16 JST — F019 authorization 0.2-draft image binding

- 今回やったこと: authorization validatorを`0.1-draft`互換と`0.2-draft`へ拡張し、version別allowed field、optionalな`approved_image`、digest-pinned `requested_reference`、full local `resolved_image_id`を追加した。runtime referenceとlocal image IDを別々にexact比較し、`RepoDigests`をlocal image IDの代替にしないpure shape checkを追加した。旧artifactは`authorization_not_image_bound` limitation付きで受理し、0.1 artifactへの0.2専用field追加は拒否するschema、golden fixture、test、契約文書、CHANGELOGを同期した。
- 検証結果: `env PYTHONPATH=src python3 -m unittest tests.test_execution_authorization_image_binding tests.test_execution_authorization -v`は15件pass・0件fail、`python3 -m json.tool schemas/execution-authorization.schema.json`はexit 0、expiryと関連CLI回帰25件はpass、full unit suiteは774件pass・3件skip・0件failだった。終了時基本検証のCLI help/version、public-safety、policy validation、JSON report生成・parse、`git diff --check`も成功した。指定featureの状態を`passes:true`、`blocked:false`、`verified_at:2026-07-16T19:15:54+09:00`へ更新した。
- 判断と理由: `approved_image`は0.2-draftでoptionalとし、image bindingなしの旧artifactを壊さずに受理する一方、fieldが存在する場合はreference mismatch、digest unpinned、runtime ID unresolved、ID mismatchをfail-closedで返す。実Docker daemonへのinspectやimage取得は行わず、runtimeから供給されるreferenceとlocal IDの契約検証に限定した。schema versionを拡張したため、既存schema inventory testのversion期待値だけをF019の契約同期として更新した。
- 既知の問題: 実Dockerでの`docker image inspect`取得、command起動直前のruntime接続、single-use reservation、worktree direct bindingは今回の範囲外で未実装・未検証である。指定commandの先頭`PYTHONPATH=src`形式と`>/dev/null`付き形式はprocess生成前に環境ポリシーで拒否されたため、同値の`env PYTHONPATH=src`と出力抑制なしで検証した。`scripts/init.sh`も同ポリシーで実行できなかった。
- follow-up候補: F020でsingle-use reservation、F021でworktree direct bindingを扱う。F019以外のfeatureには着手していない。

## 2026-07-16 JST — F020 single-use authorization atomic reservation

- 今回やったこと: `reserve_execution_authorization()`を追加し、authorization artifact隣接の`.reserved` markerを`O_CREAT|O_EXCL`（利用可能時は`O_NOFOLLOW`も併用）、mode `0600`でcommand起動直前にatomic作成するよう`sandbox-run`へ接続した。既存marker、marker作成・書込み・同期失敗はfail-closedでrunnerを起動せず、部分markerを削除しないため同じauthorizationを再利用できない。reservation後のDocker failureでもmarkerを残し、dry-runではmarkerを作らず、gate-checkは従来どおりvalidatorだけを実行する契約を文書化した。専用test 4件を追加した。
- 検証結果: 指定の`PYTHONPATH=src python3 -m unittest tests.test_execution_authorization_single_use -v`は環境のprocess生成ポリシーにより開始前に拒否されたため、同値の`env PYTHONPATH=src python3 -m unittest tests.test_execution_authorization_single_use -v`を実行し4件pass・0件failを確認した。test出力で初回atomic reservation、再利用拒否、write failure時のrunner未起動、Docker起動失敗後の消費、dry-run/gate-check非消費を確認した。認可・expiry・image binding・sandbox report/CLI回帰33件はpass、全unit suiteは778件pass・3件skip・0件failだった。終了時のCLI help/version、public-safety scan、policy validation、JSON report生成・`python3 -m json.tool` parse、docs/fixture一覧、`wc -l AGENTS.md`、`git diff --check`も成功した。開始時の`bash scripts/init.sh`も実行し、実装前の全unit suiteは774件pass・3件skip・0件failだった。
- 判断と理由: reservationはworkspace copy、Docker argv生成、dry-run判定、Docker availability/image availability確認の後、`runner.run()`の直前に限定した。markerの存在を再利用拒否に使い、書込み失敗後もmarkerを残すことで、失敗を理由にreservationを削除して再実行可能にする抜け道を作らない。markerには固定kindとschema versionだけを保存し、authorization値、command、pathは保持しない。schema version、既存rule_id、CLI既定挙動は変更していない。
- 既知の問題: reservationはlocal filesystem内の非分散制御であり、central revocationやdistributed lockではない。実Docker daemon/imageでのlive runは実施しておらず、Docker failureはFakeDockerRunnerで予約消費契約を検証した。指定commandの直接`PYTHONPATH=src`表記は環境差分で実行できず、同値の`env PYTHONPATH=src`で代替検証した。
- follow-up候補: F021でauthorization subjectとworktreeのrepo、HEAD commit、HEAD tree、dirty statusのcommand開始前直接照合を扱う。F020以外のfeatureは今回扱っていない。

## 2026-07-16 JST — F021 sandbox-run worktree direct binding

- 今回やったこと: `sandbox-run`のworkspace copy前に、対象pathからGitのrepo root、`HEAD` commit、`HEAD^{tree}`、`status --porcelain`を直接取得するprobeを追加し、authorization subjectのrepo、commit、treeと照合するよう接続した。対象pathがnon-git、repo root不一致、Git値 unresolved、subject mismatch、dirtyの場合はcommandとworkspace copyを開始しない。reportは判定状態と固定reasonだけを保持し、raw path、commit、tree、status outputは保存しない。dirty緩和flagは追加していない。F020のsingle-use testは新しいGit top-level必須契約に合わせて一時Git repository fixtureへ更新し、sandbox approval testをunittestで実行可能な形へ同期した。
- 検証結果: `env PYTHONPATH=src python3 -m unittest tests.test_execution_authorization_worktree_binding tests.test_sandbox_run_approval -v`は6件pass・0件failで、matched、mismatch、unresolved、dirty、non-git拒否、command開始前判定、dirty緩和flag不在を確認した。F020回帰は4件pass・0件fail、全unit suiteは784件pass・3件skip・0件failだった。`python3 -m py_compile`、`git diff --check`、docs/fixture一覧、`wc -l AGENTS.md`、CLI help/version、public-safety scan、policy validation、JSON report生成と`python3 -m json.tool` parseも成功した。`scripts/init.sh`開始時はPython 3.12.3で全unit 778件pass・3件skip・0件failを確認し、実装後のfull suiteも同じ契約を再確認した。
- 判断と理由: direct Git値はfile-inventory fingerprint、gate subject、workspace copy後のsnapshotで代用せず、`runner.run()`より前に取得する。既存のredactedな`<repo>` subjectは対象pathがGit top-levelであることと照合し、commit/treeは直接取得したobject IDとexact比較する。dirtyは常に拒否し、dry-runはcommandを開始しないためreservationとworktree bindingを消費しない既存契約を維持した。schema version、既存rule_id、CLI既定挙動は変更していない。
- 既知の問題: 実Docker daemon/imageでのlive commandは実施していない。指定された先頭`PYTHONPATH=src`形式のcommandは環境のprocess生成ポリシーにより開始前に拒否されたため、同値の`env PYTHONPATH=src`で専用testとfull suiteを実行した。これはtest失敗ではなく環境差分である。
- follow-up候補: F022でsandbox-run reportのevidence normalizerとbinding signalのgate連携を扱う。F021以外のfeatureは今回扱っていない。

## 2026-07-16 JST — F022 sandbox-run evidence normalizer

- 今回やったこと: `normalize_sandbox_run_evidence(report)`と公開exportを追加し、run ID、report fingerprint、subject、policy、gate fingerprint、生成時刻、runner種別、実行状態、timeout、cleanup、observer、worktree binding、seccomp/image、workspace diff件数だけをbounded evidenceへ正規化した。`successful_execution_is_not_safety`は`informational_notes`へ固定し、policy block、binding mismatch、timeout、cleanup failure、observer degraded、fake/dry-run、invalid、stale、truncatedを`decision_signals`へ分離した。raw preview/stdout/stderr、host path、command内容は出力へコピーしない。専用testとgolden fixtureを追加し、gate verdictとCLI接続はF023/F024の範囲として変更していない。
- 検証結果: `env PYTHONPATH=src python3 -m unittest tests.test_sandbox_evidence_normalizer -v`は3件pass・0件failで、golden一致、成功noteのinformational扱い、raw preview/stdout/stderr/path非保持、timeout/policy/cleanup/observer/binding/fakeのsignal分類を確認した。`bash scripts/init.sh`はPython 3.12.3で全unit 787件pass・3件skip・0件fail、CLI help/version、public-safety scan、policy validation、JSON report生成・parseまで成功した。`python3 -m py_compile`、`git diff --check`も成功した。
- 判断と理由: source reportの構造不備は成功扱いにせず`sandbox_evidence_invalid`へ分類し、fake runnerとdry-runも`not_real_execution_evidence`として実行証拠から分離した。normalizerはgate verdictを変更せず、後続featureがdecision signalだけを利用できる形に限定した。出力の安定性を保つため、入力limitationsの自由文は保持せず固定limitationだけを記録した。
- 既知の問題: 指定された先頭`PYTHONPATH=src`形式の専用commandは実行環境のprocess生成ポリシーにより開始前に拒否されたため、同値の`env PYTHONPATH=src`で検証した。実Dockerでのlive executionやgateへのevidence接続はF022の対象外で未実施である。
- follow-up候補: F023でこのnormalized evidenceをgateへ合流し、successではverdictを改善せず、invalid/stale/mismatch/over-budgetを悪化方向へ扱う。F022以外のfeatureは今回扱っていない。

## 2026-07-16 JST — F023 sandbox evidence gate mapping

- 今回やったこと: `evaluate_gate_decision()`へoptionalなnormalized sandbox evidence入力を追加し、`decision_signals`だけを既存の`strongest_verdict`候補へ合流させた。成功evidenceはverdict候補を追加せず、policy blockとsubject binding mismatchはblock、cleanup failureはquarantine、timeout、observer degraded、fake/dry-run、invalid、stale、truncated、over-budgetはunknown方向へだけ作用する。normalized evidenceのkind、version、signal shapeが不正な場合は`sandbox_evidence_invalid`として扱い、黙ってskipしない。sandbox evidence未指定時は既存の結果オブジェクト全体を維持する。
- 検証結果: 指定された`PYTHONPATH=src python3 -m unittest tests.test_sandbox_evidence_gate_mapping -v`は実行環境のprocess生成ポリシーにより開始前に拒否されたため、同値の`env PYTHONPATH=src python3 -m unittest tests.test_sandbox_evidence_gate_mapping -v`を実行し3件pass・0件failを確認した。test出力でsuccessがallow_limited、warn、unknown、quarantine、blockの全段階で不変、invalid、stale、mismatch、over-budgetが各段階で同値または悪化、evidence未指定と明示的な空入力で既存出力が一致することを確認した。normalizerとgate evaluatorの関連回帰25件、`py_compile`、`git diff --check`は成功した。`scripts/init.sh`はPython 3.12.3で全unit 790件pass・3件skip・0件fail、CLI help/version、public-safety scan、policy validation、JSON report生成・parseまで成功した。
- 判断と理由: sandboxの成功をverdict reasonにも候補にも加えず、問題signalだけを既存verdictへ追加する構造にしたため、成功による改善と問題signalによる左方向への移動を防げる。gate decisionへ入力evidenceのraw fieldを埋め込まず、固定の`sandbox_evidence:<index>`だけをblocking/warning evidenceへ記録する。CLI、schema、既存`rule_id`、default scan contractは変更していない。
- 既知の問題: `--sandbox-evidence` CLI、file count、file size、total bytes、age、duplicate fingerprint、subject/policy/gate fingerprint検証、evidence reference出力はF024の範囲であり、今回未実装である。実Docker executionは実施していない。
- follow-up候補: F024でboundedなCLI入力検証とgate/sandbox fingerprint・run IDの相互参照を接続する。F024以降のfeatureは今回扱っていない。
- 検証件数の訂正: 上記の「全unit 790件pass・3件skip」は「全unit 790件実行・787件pass・3件skip・0件fail」が正しい。unittestの`Ran 790 tests`はskipを含む総実行件数である。

## 2026-07-16 JST — F024 bounded sandbox evidence CLIと相互参照

- 今回やったこと: `gate-check`へrepeatableな`--sandbox-evidence`を追加し、report数16件、1 file 256 KiB、合計1 MiB、生成後24時間、future skew 5分を上限としてsandbox-run reportを検証するようにした。closed schema、canonical fingerprint、run ID、gate decision fingerprint、subject、policy version、重複をfail-closedで照合し、gate decisionの`evidence_refs`にはboundedな識別子とvalidation結果だけを格納する。`sandbox-run`のJSON reportにはcanonical `report_fingerprint`を付け、gate経由の実行では元gate fingerprint、subject、policy versionを相互参照用に記録する。schema、専用test、公開契約、sandbox運用文書、CHANGELOGを同期した。
- 検証結果: 指定された先頭`PYTHONPATH=src`形式の専用commandは実行環境のprocess生成ポリシーにより開始前に拒否されたため、同値の`env PYTHONPATH=src python3 -m unittest tests.test_sandbox_evidence_cli -v`を実行し6件pass・0件failを確認した。CLI、両schema、count、file size、total bytes、age、duplicate、invalid schema、omission compatibility、fingerprintとrun IDの相互参照を確認した。関連回帰24件は全件pass、full unit suiteは796件実行・793件pass・3件skip・0件failだった。指定のdocs `rg`、schema JSON parse、`py_compile`、`git diff --check`、CLI help/version、public-safety scan、policy validation、default JSON report生成・parseも成功した。
- 判断と理由: sandbox evidenceと既存external evidenceの合計も16件に制限し、raw report、command、path、stdout、stderrはgate decisionへ保持しない。sandbox reportのfingerprint fieldは既存のprogrammatic report shapeを壊さないためschema上optionalとし、CLIが出力するJSONには常に付与する。successful executionは安全性やgate verdictを改善せず、fake/dry-run、invalid、stale、mismatch、over-budgetなどの問題だけをF023の悪化方向signalへ渡す。
- 既知の問題: 実Docker daemonとlocal imageによるlive executionは実施しておらず、dry-runで生成したschema-valid reportとunit testで相互参照契約を検証した。これは後続のreal Docker検証featureの範囲である。指定commandの直接`PYTHONPATH=src`表記は環境差分で実行できず、同値の`env PYTHONPATH=src`で代替した。
- follow-up候補: real Dockerのcases検証はrunnerが別processで指定する後続featureで扱う。F024以外のfeatureには着手していない。

## 2026-07-16 JST — F025 real Docker cases 1〜7 test path追加、daemon accessでblocked

- 今回やったこと: `tests/test_real_docker_verification.py`へ`RHD_REAL_DOCKER_TEST=1`でだけ有効になる`RealDockerBoundaryCasesOneToSeven`を追加した。固定の無害な`python3 -c`だけを使い、case 1は正常実行とworkspace diff、case 2は外部requestなしのnetwork interface観測、case 3はroot mountのread-only flag、case 4はwritableな`/tmp` tmpfs、case 5はnon-root UID/GID、case 6はtimeout、case 7はDocker run前のcopy budget blockを検証する。各caseはoriginal synthetic repoのfingerprint不変、使い捨てrun rootの削除、sandbox evidence schemaを共通確認し、実行caseでは`--pull=never`と`--rm`を確認する。imageの取得、pull、repo由来command、外部service request、workflow変更は行っていない。
- 検証結果: 開始時`bash scripts/init.sh`は796件実行・793件pass・3件skip・0件failで成功した。追加testをopt-inなしで実行すると7件すべてが意図どおりskipとなり、`python3 -m py_compile`と`git diff --check`は成功した。指定の先頭環境代入形式はprocess生成前に実行環境ポリシーから拒否された。同値の`env RHD_REAL_DOCKER_TEST=1 PYTHONPATH=src python3 -m unittest tests.test_real_docker_verification.RealDockerBoundaryCasesOneToSeven -v`は、accessible local Docker daemon不在の`setUpClass` errorでexit 5となり、0件実行・1件errorだった。終了時full suiteは803件実行・793件pass・10件skip・0件failで、`scripts/init.sh`によるCLI help/version、public-safety、policy validation、JSON report生成・parseも成功した。
- 判断と理由: opt-in時にdaemonまたはlocal imageが利用できない環境をskipやfake runnerでgreenにするとreal Docker受入条件を満たしたことにならないため、前提不足を明示的なerrorにした。今回のprocessはDocker CLIを検出したがDocker APIへ接続できず、local imageの存在確認とcases 1〜7の実測を行えないため、F025は`passes:false`、`verified_at:null`を維持し、`blocked:true`へ更新した。
- 既知の問題: cases 1〜7は実Dockerで0件実行であり、固定commandの実行結果、境界の実効性、container cleanup、schema-validなreal evidenceは未確認である。test path自体とopt-in gateはfull suiteで構文・discover可能性を確認したが、real Docker greenの代替証拠ではない。
- follow-up候補: HumanがこのprocessからDocker APIへ接続できる実行環境と、既にlocalに存在する`python:3.12-slim`または`RHD_REAL_DOCKER_IMAGE`で選ぶ互換imageを用意し、image取得なしでF025の指定testを再実行する。7件すべてがpassした場合だけF025のblockedを解除してpassesとverified_atを更新する。F026以降は今回扱っていない。

## 2026-07-16 JST — F026 real Docker cases 8〜10 test path追加、local image未指定でblocked

- 今回やったこと: `tests/test_real_docker_verification.py`へ`RHD_REAL_DOCKER_TEST=1`でだけ有効になる`RealDockerBoundaryCasesEightToTen`を追加した。case 8は`rhd-moby-default-v1`を実Dockerへ適用し、case 9はdigest-pinned requested referenceと実daemonのfull local image IDを一致・不一致で別々に検証し、case 10はofflineでbuild・installしたwheelのpackage resourceから同じseccomp profileを解決して実Dockerを起動する。固定の無害な`python3 -c`、`--pull=never`、original repo不変、使い捨てrun rootのcleanup、schema-valid evidenceを確認する。local-onlyの実行前提とcases 8〜10を`docs/real-docker-verification.md`へ記録した。
- 検証結果: 開始時`bash scripts/init.sh`は803件実行・793件pass・10件skip・0件failで、CLI help/version、public-safety、policy validation、JSON report生成・parseまで成功した。opt-inなしの専用classは3件すべて意図どおりskipとなり、指定docs `rg`、`python3 -m py_compile`、`git diff --check`は成功した。指定の先頭環境代入形式はprocess生成前に実行環境ポリシーから拒否された。同値の`env RHD_REAL_DOCKER_TEST=1 PYTHONPATH=src ...`は`RHD_REAL_DOCKER_IMAGE`未指定を`setUpClass`で明示し、exit 5、0件実行・1件errorとなった。
- 判断と理由: Docker 29.5.3のdaemonには接続できたが、既定の`python:3.12-slim`はlocalに存在せず、digest-pinned local imageも指定されていない。imageを取得したりtag-only referenceへ緩和したりせず前提不足をfail-closedで示したため、F026は`passes:false`、`verified_at:null`を維持し、`blocked:true`へ更新した。
- 既知の問題: cases 8〜10は実Dockerで0件実行であり、同梱profileのruntime適用、実local image ID binding、installed wheel resourceによるlive run、original repo不変、cleanup、schema-validなreal evidenceは未確認である。opt-in gate、test discovery、構文、local手順は確認したがreal Docker greenの代替証拠ではない。
- follow-up候補: HumanがPython 3を実行できるdigest-pinned imageをlocal daemonへ事前に用意し、そのexact referenceを`RHD_REAL_DOCKER_IMAGE`へ設定してF026の指定testを再実行する。3件すべてがpassした場合だけF026のblockedを解除し、passesとverified_atを更新する。F026以外のfeatureは今回扱っていない。
- 終了時検証追記: `bash scripts/init.sh`は806件実行・793件pass・13件skip・0件failで、CLI help/version、public-safety、policy validation、JSON report生成・parseまで成功した。PLANのdocs/fixture一覧、`wc -l AGENTS.md`、指定docs `rg`、`git diff --check`も成功した。

## 2026-07-16 JST — F027 workflow_dispatch real Docker検証契約

- 今回やったこと: `workflow_dispatch`だけで起動する`real-docker-verification.yml`を追加した。Humanが指定するdigest-pinned image referenceを独立したacquisition stepで形式検証してpullし、後続の固定test stepはsandboxの`--pull=never`契約とreal Docker cases 1〜10だけを実行する。成否にかかわらずDocker server version、runner OS、architectureをstep summaryへ記録する。static contract test、real Docker検証手順、image compatibilityのpre-verification境界、CHANGELOGを同期した。
- 検証結果: 指定された先頭`PYTHONPATH=src`形式はprocess生成前に実行環境ポリシーから拒否されたため、同値の`env PYTHONPATH=src python3 -m unittest tests.test_real_docker_workflow_contract -v`を実行し4件pass・0件failだった。test出力でworkflow_dispatch以外のtrigger不在、digest形式検証、独立acquisition、固定cases、sandbox `--pull=never`、Docker version、OS、architecture summaryを確認した。YAML parserによる構文確認も成功した。終了時`bash scripts/init.sh`は810件実行・797件pass・13件skip・0件failで、CLI help/version、public-safety、policy validation、JSON report生成・parseまで成功した。`git diff --check`も成功した。
- 判断と理由: workflow inputはimage referenceだけに限定し、command inputを追加しなかった。image取得とtest実行をstepで分離し、test stepからpullまたはbuildを行えないことをstaticに固定した。Hosted workflowを実行せずに受入条件を検証できたため、F027を`passes:true`、`blocked:false`としてJSTの検証日時を記録した。
- 既知の問題: Hosted workflowはこのprocessでは起動しておらず、実image、Docker runtime、OS、architectureの組合せによるgreen runと互換性は未確認である。green runも一般的な安全性や完全な隔離の証明にはならない。固定名`/tmp/repo-health-doctor-result.json`への直接出力はsandbox policyでprocess生成前に拒否されたが、`scripts/init.sh`の一時JSON生成とparseは成功した。
- follow-up候補: HumanがPython 3を実行できるdigest-pinned image referenceを指定してworkflow_dispatchを実行し、対象commit、run metadata、Docker version、OS、architectureを確認する。F027以外のfeatureには着手していない。
- 記録の補足: 上記の「test stepからpullまたはbuildを行えない」は、image pullまたはDocker image buildを行わないという意味である。case 10が行うoffline wheel buildは固定testの一部として維持している。

## 2026-07-16 JST — F028 Seccomp Human review packet

- 今回やったこと: Moby v28.3.3由来の`rhd-moby-default-v1`がSHA-256固定の276 syscall allowlistであり、sandbox固有の最小化をしていないことをbaselineにした。削減候補を`chroot`、`mknod`/`mknodat`、`fanotify_mark`、`io_uring` 3 syscall、POSIX message queue 4 syscallの5組へ小分けし、候補ごとの根拠、cases 1〜6/8/10の回帰条件、cases 7/9がruntime非実行であること、未確認runtime、却下条件、残riskをJSONとMarkdownのHuman review packetへ対応付けた。candidate artifact、製品path接続、default変更、Human approvalは行っていない。
- 検証結果: `python3 -m json.tool docs/human-review/seccomp-review-packet.json`はexit 0でparseに成功した。指定の`>/dev/null`付き形式はprocess生成前に環境ポリシーから拒否された。指定の先頭`PYTHONPATH=src`形式も同じく拒否されたため、同値の`env PYTHONPATH=src python3 -m unittest tests.test_seccomp_review_packet -v`を実行し8件pass・0件failだった。終了前の`bash scripts/init.sh`は818件実行・805件pass・13件skip・0件failで、CLI help/version、public-safety、policy validation、JSON report生成とparseまで成功した。PLANのdocs/fixture一覧、`wc -l AGENTS.md`、`git diff --check`も成功した。未追跡3 fileへの`git diff --no-index --check`は差分存在を示すexit 1で、whitespace警告はなかった。
- 判断と理由: network noneだけを理由にsocket syscallを削除せず、case 2のinterface列挙で使う可能性がある`socket`、`ioctl`、`getsockname`を維持した。Python、libc、process/thread起動への影響が大きい`clone`、`clone3`、`execve`、`execveat`、`futex`もstatic根拠だけでは削減しない。今回の候補はbaseline allowlistに実在し、各1〜4 syscallで独立して却下できる単位に限定した。
- 既知の問題: candidate profileとcandidate runtime evidenceはまだ存在しない。rootful Docker、rootless/userns-remap、image/libc差、x86_64以外、Docker以外のOCI runtimeは未確認である。cases 1〜10が将来greenでも、任意のauthorized commandや一般的な安全性、完全な隔離を保証しない。F025/F026のreal Docker実測は前提不足のままである。
- follow-up候補: runnerが別processで後続featureを指定した場合に限り、packetの削減候補からHuman未承認candidate artifactを作成し、その後の専用real Docker regressionで全case結果と全failureをpacketへ記録する。各候補のapprove/reject/reviseと最終profile hashはHumanが判断する。F028以外のfeatureには着手していない。

## 2026-07-16 JST — F029 Human未承認seccomp candidate artifact

- 今回やったこと: `rhd-moby-default-v1`の276 syscall allowlistから、F028 packetのSC-001〜SC-005に対応する`chroot`、`mknod`/`mknodat`、`fanotify_mark`、`io_uring` 3 syscall、POSIX message queue 4 syscallの計11 syscallだけを除き、265 syscallの`rhd-locked-down-v1.candidate.json`をHuman未承認review artifactとして作成した。artifact bytesのSHA-256 `1860f395ed5ddde5f50fd2c3c779568b62421c0368f9fc3c706fa5f9d8e961a5`、削減candidate ID、削除syscall、未実測、製品非接続をreview packetのJSONとMarkdownへ対応付けた。package data、schema、CLI、Docker argvは変更していない。
- 検証結果: `python3 -m json.tool docs/human-review/rhd-locked-down-v1.candidate.json`はexit 0でparseに成功した。指定の`>/dev/null`付き形式はprocess生成前に環境ポリシーから拒否された。指定の先頭`PYTHONPATH=src`形式も同じく拒否されたため、同値の`env PYTHONPATH=src python3 -m unittest tests.test_seccomp_candidate_contract tests.test_seccomp_review_packet -v`を実行し14件pass・0件failだった。専用test 6件でcandidate hash、baselineから11 syscallだけを引いた形、packet対応、Human未承認・未実測状態、package/schema/CLI/Docker argv非接続、`verified`表現不在を確認した。full suiteは824件実行・811件pass・13件skip・0件failで、CLI help/version、public-safety、policy validation、default JSON report生成・parse、PLANのdocs/fixture一覧、`wc -l AGENTS.md`、tracked diffの`git diff --check`も成功した。未追跡2 fileへの`git diff --no-index --check`は差分存在を示すexit 1で、whitespace警告はなかった。
- 判断と理由: candidateは後続のlocal real Docker regressionが直接使用できるseccomp JSON形状にしたが、docs/human-review配下だけに置いた。製品resource lookupとCLI choiceには追加せず、schema enumにもDocker argv builderにも接続しないことで、Human approval前の実行選択肢化を防いだ。F028時点の境界を表す既存`review_scope`は保持し、F029のartifact状態は独立した`candidate_artifact`記録へ追加した。
- 既知の問題: candidate real Docker regressionとHuman reviewは未実施であり、runtime互換性、削減可否、最終profile hashは未承認である。candidateの存在は安全性、完全隔離、production利用可能性を示さない。F025/F026のreal Docker実測も前提不足のままである。
- follow-up候補: runnerが別processでF030を指定した場合に限り、既存local Docker daemonとdigest-pinned imageを使うcandidate専用回帰を実行し、全case結果と全failureをpacketへ記録する。F029以外のfeatureには着手していない。

## 2026-07-16 JST — F030 candidate専用local Docker regression記録

- 今回やったこと: Human未承認の`rhd-locked-down-v1.candidate.json`をreview専用pathから直接指定し、既存local imageだけをcontent digestへ解決して`--pull=never`、network none、capability drop、no-new-privileges、non-root、read-only rootfs、tmpfs、resource limitでcases 1〜6、8、10を順番に試行する`run_candidate_seccomp_review.py`を追加した。環境、candidate bytesのSHA-256、case別status、全failureを`candidate_local_regression`としてJSONとMarkdownへ記録し、raw stdout/stderr、host path、container名は保存しない。package data、schema、CLI、製品Docker argv、default選択肢は変更していない。
- 検証結果: 指定の先頭環境代入形式はprocess生成前に環境ポリシーから拒否されたため、同値の`env RHD_REAL_DOCKER_TEST=1 PYTHONPATH=src python3 -m unittest tests.test_candidate_seccomp_real_docker -v`を実行し3件pass・0件failだった。test processからDocker daemonとlocal imageを参照できず、recordは`preflight_failed`、8 casesすべて`not_run`となったが、環境failure 6件と各caseの`preflight_blocked` 8件を省略なく記録した。candidate/review packet回帰16件はpass、full suiteは827件実行・813件pass・14件skip・0件failだった。`python3 -m json.tool docs/human-review/seccomp-review-packet.json`、`py_compile`、CLI help/version、public-safety、policy validation、default JSON report生成・parse、PLANのdocs/fixture一覧、`wc -l AGENTS.md`、`git diff --check`は成功した。指定のJSON parseにある`>/dev/null`付き形式はprocess生成前に拒否されたため、出力抑制なしで同じfileをparseした。新規fileの`git diff --no-index --check`は差分存在を示すexit 1で、whitespace警告はなかった。
- 判断と理由: F030の受入対象はcandidate互換性の成功ではなく、既存local Dockerを使う専用test pathがlocal実測結果またはfailureを全case分review packetへ記録できることである。今回はpreflight failure経路と全case記録を専用testで確認でき、製品非接続も既存candidate contractを含む16件で維持したため、F030を`passes:true`、`blocked:false`、検証日時をJSTで記録した。candidateのHuman approval、削減可否、安全性、一般互換性は成功扱いにしていない。
- 既知の問題: このprocessではcandidate配下のruntime commandは1件も開始しておらず、Docker version、OS、architecture、kernel、image digestはpacket上`unknown`である。rootful/rootless、userns-remap、image/libc、architecture、Docker以外のruntimeは未確認で、Human判断もpendingである。F025/F026のblocked状態は今回の許可範囲外なので変更していない。
- follow-up候補: HumanがDocker daemonへ接続でき、Python 3を実行できるdigest-pinned imageが既にlocalにあるprocessで同じopt-in testを再実行し、F030 sectionを実測環境、case結果、全failureで更新してHuman reviewへ渡す。F031以降は今回のprocessでは扱っていない。

## 2026-07-16 JST — F031 canonical AI Agent Contract

- 今回やったこと: `docs/agent-contract.md`を追加し、`real-scan --fail-on-degraded`、external evidence付きgate、Human-controlled authorization、`sandbox-run`、sandbox evidence還流を一意の正準flowとして定義した。exit 0だけが次の定義済み段階へ進め、exit 1、exit 2、signal、unknown exit codeは停止する。gate decisionとexecution authorizationを分離し、authorization不足の初回gateはtarget commandを実行せずHumanへ引き渡す停止点とした。external-evidence gateとsandbox内部gateのfingerprintが異なる場合はauthorization artifactを流用しない現行CLI境界も明記した。
- 検証結果: 指定の先頭`PYTHONPATH=src`形式はprocess生成前に実行環境ポリシーから拒否されたため、同値の`env PYTHONPATH=src python3 -m unittest tests.test_agent_contract_docs -v`を実行し5件pass・0件failだった。指定の`rg -n "exit 0|exit 1|exit 2|unknown|real-scan|external-evidence|authorization|sandbox-run|sandbox-evidence" docs/agent-contract.md`はexit 0で正準flow、exit表、各境界を確認した。full suiteは832件実行・818件pass・14件skip・0件failだった。CLI help/version、public-safety、policy validation、default JSON report生成・parse、PLANのdocs/fixture一覧、`wc -l AGENTS.md`、`git diff --check`も成功した。
- 判断と理由: 非zeroを一律停止にしつつ、`sandbox-run`のpolicy block exit 2と開始済みtarget command自身のexit 2はreportとstderr prefixで区別する。どちらも自動継続は許可しない。gate decisionやscanner finding 0件、sandbox successはauthorizationまたは安全性の証明に昇格させず、次commandには新しいexact bindingとHuman controlを要求する。
- 既知の問題: `sandbox-run`はexternal evidenceを直接受け取らず内部gateを生成するため、external-evidence gate用artifactとsandbox内部gate用artifactはfingerprintが異なる場合に流用できない。文書は別artifactと再reviewを要求し、差異を隠していない。指定test commandの先頭環境代入形式はこの実行環境では未実行であるが、同値commandはgreenである。
- follow-up候補: F032のtool別bindingとF033のREADME、docs index、public contract、CHANGELOG同期は各指定featureのprocessで行う。F031では変更していない。

## 2026-07-17 JST — F032 公式source packetに基づくtool別binding

- 今回やったこと: Human提供の`docs/human-review/agent-binding-official-sources.md`をread-onlyかつofflineで参照し、Codex、Claude Code、Cursorのbinding文書へ`verified-as-of: 2026-07-16 JST`、公式source URL、確認済み事項、未確認事項、instruction-based limitationを記録した。CodexはAGENTS.md instruction chain、Claude Codeは`PreToolUse`のdecisionとevent別exit behavior、CursorはRules、Hooks、CLIの公式page存在までに根拠を限定した。source packet、account設定、tool設定は変更せず、network accessも行っていない。
- 検証結果: `test -f docs/human-review/agent-binding-official-sources.md`はexit 0だった。指定の先頭`PYTHONPATH=src`形式はprocess生成前に実行環境ポリシーから拒否されたため、同値の`env PYTHONPATH=src python3 -m unittest tests.test_agent_binding_docs -v`を実行した。初回は見出しの大小文字比較だけを原因として5件中1件failし、test側の比較を修正後に5件pass・0件failとなった。関連するAI agent integrationとcanonical contractの10件もpassし、全unit suiteは837件実行・823件pass・14件skip・0件failだった。PLANのdocs/fixture一覧、AGENTS.md 77行、`git diff --check`、CLI help/version、public-safety、policy validation、JSON report生成も成功した。JSON parseの`>/dev/null`付き形式はprocess生成前に拒否されたため、出力抑制なしの`python3 -m json.tool`で同じreportをparseしexit 0を確認した。
- 判断と理由: source packetで確認されていない強制機構やexit semanticsは推測せず、CodexとCursorはinstruction-based limitationとして明示した。Claude Codeの`PreToolUse`は強制surface候補としたが、この作業では設定をinstallせず、Human review前の有効化済み表現を避けた。専用検証と基本検証がすべてgreenになったため、F032を`passes:true`、`blocked:false`としてJSTの検証日時を記録した。
- 既知の問題: verified-as-of以後の公式仕様変更には自動追随しない。Codexのcommand実行前の強制hook、Claude Codeの対象環境での設定状態と完全な設定schema、Cursorのhook event名、decision schema、exit code block契約、project ruleおよびnon-interactive CLIの強制契約は未確認である。
- follow-up候補: F033の別processでREADME、docs index、public contract、CHANGELOGとのcross-linkと表示commandの非実行smokeを同期する。F032以外のfeatureには着手していない。

## 2026-07-17 JST — F033 agent contract文書統合

- 今回やったこと: README、docs index、public contracts、CHANGELOGをAI Agent Canonical ContractとCodex、Claude Code、Cursorの3 bindingへ接続した。public contractsへreal-scan、gate、Human-controlled authorization、sandbox、evidence還流の正準flowとexit表を同期し、agent contractから各bindingへ戻るcross-linkを追加した。専用testへ対象文書のlocal link解決、中央文書とbindingの相互参照、plan-only demoが表示対象commandを実行しないsmoke、public contractsと正準flow・exit表の同期検査を追加した。製品code、agent設定、target commandは変更または実行していない。
- 検証結果: 指定testと同値の`env PYTHONPATH=src python3 -m unittest tests.test_ai_agent_integration_docs tests.test_agent_contract_docs -v`は13件pass・0件failだった。smokeでは表示対象の一時commandが作成するmarkerが存在しないこと、`Target command executed: false`、exit 2を確認した。指定の`rg -n "agent-contract|integration-codex|integration-claude-code|integration-cursor|exit 0" README.md docs/README.md docs/public-contracts.md CHANGELOG.md`は4文書すべての同期を確認した。終了時full suiteは840件実行・826件pass・14件skip・0件failだった。PLANのdocs/fixture一覧、AGENTS.md 77行、`git diff --check`、CLI help/version、public-safety、policy validation、default JSON report生成とparseも成功した。
- 判断と理由: tool別bindingの確認済み強制範囲はF032のまま変更せず、正準契約と中央文書の導線・exit解釈だけをF033で同期した。agent orchestrationのexit表は各CLI固有のexit semanticsを置き換えず、exit 0だけが次の定義済み段階へ進み、exit 1、exit 2、unknown、target commandのnonzeroは停止する境界を維持した。全local link解決と非実行smokeを専用testで固定できたため、F033を`passes:true`、`blocked:false`としてJSTの検証日時を記録した。
- 既知の問題: 指定testの先頭`PYTHONPATH=src`形式は実行環境ポリシーによりprocess生成前に拒否されたため、同値の`env PYTHONPATH=src`形式で実行した。JSON parseの`>/dev/null`付き形式も同様に拒否されたため、出力抑制なしで同じfileをparseした。verified-as-of以後のtool仕様変更と各bindingの未確認強制機構はF032記録どおり残る。
- follow-up候補: F034以降のfeatureは今回扱っていない。次featureの選択と新process起動はhost runnerに委ねる。

## 2026-07-17 JST — F034 full local verification

- 今回やったこと: F001〜F033を支える全unit、schema、public contract、CLI、public-safety、redaction、docs、diff整合をlocalで再検証した。製品codeと既存contractは変更せず、F034の状態更新と本記録だけを行った。
- 検証結果: `bash scripts/init.sh`はexit 0だった。独立したfull suiteは840件実行・826件pass・14件skip・0件fail、schema/public contract専用testは8件pass・0件failだった。CLI help/version、public-safety self-scanの12件pass・0件warn・0件block、policy validation、JSON report生成とparse、docs/fixture一覧、AGENTS.md 77行、`git diff --check`はすべて成功した。先頭の`PYTHONPATH=src`形式と`>/dev/null`付きJSON parseはprocess生成前に実行環境ポリシーで拒否されたため、それぞれ同値の`env PYTHONPATH=src`形式と出力抑制なしのparseで検証した。
- 判断と理由: full suite、F034専用test、PLANの基本検証がgreenで、redactionとdocs contractもfull suite内で通過したため、F034を`passes:true`、`blocked:false`としてJSTの検証日時を記録した。14件のskipは明示opt-inが必要なreal Docker cases 1〜10、candidate回帰、任意のlive scannerまたはDocker integrationであり、未完了の外部実測をlocal成功へ読み替えていない。
- 既知の問題: Hosted workflow_dispatchは未実行で、`docs/human-review/final-security-gates.json`は存在しない。F025/F026は前提不足により`passes:false`、`blocked:true`のままである。seccomp review packetは`pending_human_decision`、candidate runtime regressionは`preflight_failed`かつ全case `not_run`で、Human seccomp approvalは未完了である。
- follow-up候補: Humanが別processでHosted workflow_dispatchのgreen run metadataとseccomp approvalをmachine-readable evidenceとして提供した後、runnerがF035を検証する。F035以降は今回のprocessでは扱っていない。

## 2026-07-17 JST — F035 Human Gate validatorとevidence待ち

- 今回やったこと: Hosted `workflow_dispatch`のgreen run、Git履歴から到達可能な対象commit、Docker server version、runner OS、architecture、Humanによるseccomp削減承認、承認者、承認日時、`rhd-locked-down-v1` candidate bytesと一致するapproved profile SHA-256を閉じたmachine-readable schemaで検証するvalidatorを追加した。validatorは64 KiB上限、symlink拒否、未知field拒否を行い、入力値やpathを出力せず固定reason codeだけを返す。Human evidence自体、workflow、candidate、製品path、F036は変更していない。
- 検証結果: `python3 scripts/validate_final_security_gates.py docs/human-review/final-security-gates.json`はevidence不在を`evidence_missing`としてmachine-readableに返し、exit 1だった。指定された先頭`PYTHONPATH=src`形式の専用testはprocess生成前に実行環境ポリシーから拒否されたため、同値の`env PYTHONPATH=src python3 -m unittest tests.test_final_security_gates -v`を実行し6件pass・0件failだった。full suiteは846件pass・14件skip・0件failで、schema JSON parse、Python compile、CLI help/version、public-safety、policy validation、default JSON report生成・parse、docs/fixture一覧、AGENTS.md 77行、`git diff --check`も成功した。JSON parseの`>/dev/null`付き形式は同じ実行環境ポリシーで拒否されたため、出力抑制なしで同じfileをparseした。
- 判断と理由: `docs/human-review/final-security-gates.json`が存在せず、Hosted runとHuman approvalを検証できないため、F035は`passes:false`、`verified_at:null`を維持して`blocked:true`へ変更した。validatorのlocal test成功をHuman Gate成功へ読み替えていない。
- 既知の問題: Hosted workflowのrun IDまたはrun URL、対象commit、Docker server version、runner OS、architecture、およびHuman seccomp approvalは未提供である。validatorは入力されたrun metadataの閉じた契約、対象commitのlocal履歴到達性、candidate hash一致を検証するが、network accessを行わないためGitHub側runの真正性確認はHuman reviewに残る。
- follow-up候補: HumanがGitHub-hosted runnerで`.github/workflows/real-docker-verification.yml`を`workflow_dispatch`実行してgreen結果を確認し、run IDまたはrun URL、runのhead SHA、Docker server version、runner OS、architectureを記録する。Humanがseccomp syscall削減をreviewして承認する場合は、承認者、timezone付き承認日時、profile名、candidate bytesと一致するSHA-256を`docs/human-review/final-security-gates.json`として提供する。その後、Human判断でF035のblocked解除とrunner再実行を行う。F035以外のfeatureには着手していない。

## 2026-07-17 JST — F035検証件数の訂正

- 訂正: 直前のF035記録にある「full suiteは846件pass・14件skip・0件fail」は件数表現が誤っていた。正しくは846件実行・832件pass・14件skip・0件failである。検証のgreen判定、F035のblocked判断、既知の問題、必要なHuman操作に変更はない。

## 2026-07-17 JST — F036 Human Gate前提未達によるblocked終了

- 今回やったこと: F036の実装前提としてF035の状態と`docs/human-review/final-security-gates.json`を再確認した。F035は`passes:false`、`blocked:true`で、Human evidenceも不在だったため、`rhd-locked-down-v1`のpackage、schema、CLI、Docker argv、image compatibility、public contracts、CHANGELOGへの接続は行わず、F036を`passes:false`、`verified_at:null`のまま`blocked:true`へ変更した。
- 検証結果: `python3 scripts/validate_final_security_gates.py docs/human-review/final-security-gates.json`は`valid:false`、reason code `evidence_missing`を返してexit 1だった。開始時の`bash scripts/init.sh`と独立したPLAN基本検証ではfull suiteが846件実行・832件pass・14件skip・0件failとなり、CLI help/version、public-safety 12件pass・0件warn・0件block、policy validation、JSON report生成・parse、docs/fixture一覧、AGENTS.md 77行、`git diff --check`が成功した。出力抑制付きJSON parseだけは実行ポリシーで拒否されたため、同じfileを出力抑制なしでparseしてexit 0を確認した。F036専用testと終了時full verificationは、PLANがHuman Gate達成時だけ実行すると定めているため実行していない。
- 判断と理由: approved profile hashを検証できず、F035も完了していないため、Human未承認candidateを正式な明示選択肢へ接続することは禁止される。開始時smokeの成功をHuman Gate成功またはF036完了へ読み替えていない。
- 既知の問題: Hosted `workflow_dispatch`のgreen run metadata、対象commit、Docker server version、runner OS、architecture、Human seccomp approval、承認者、timezone付き承認日時、candidate bytesと一致するapproved profile SHA-256が未提供である。F036のimage compatibility、public contracts、CHANGELOG同期とfull verificationは未実施である。
- follow-up候補: Humanが`.github/workflows/real-docker-verification.yml`のgreen `workflow_dispatch`結果とseccomp削減承認を`docs/human-review/final-security-gates.json`として提供し、内容をreviewしたうえでF035とF036のblocked解除およびrunner再実行を明示判断する。runnerはF035を先に再検証して`passes:true`、`blocked:false`にした後、別processでF036を再実行する。

## 2026-07-17 JST — seccomp baseline statx compatibility repair

- Human実機証拠: Docker Desktop 4.79.0、Docker Engine 29.5.3、runc 1.3.6、linux/amd64、`python@sha256:d764629ce0ddd8c71fd371e9901efb324a95789d2315a47db7e4d27e78f1b0e9`のHuman shellで、修正前package baselineを使うreal cases 8/10がcontainer init時の`statx`拒否により失敗した。修正前profileの一時copyへ`statx`だけを追加した277 syscall profileではminimal runとread-only、tmpfs、non-root、capability drop、no-new-privilegesを含むsandbox boundary runが成功した。
- 今回やったこと: `rhd-moby-default-v1`のSCMP_ACT_ALLOW groupへ`statx`だけを追加し、276 syscallから277 syscallへ更新した。baseline bytesのSHA-256は`7cb8f61c6f90a7f0491194c5e3e3ac41f0d4e65e9494a0afca1575cbb43b86a2`から`cd7d83a312f51451d6942e5fdbfdd651a1cbebdff6debb8ff85a352a3be439d6`へ変わった。defaultAction、architecture contract、profile名、default selection、resolverの固定選択肢は変更していない。
- candidate同期: Human判断で維持した既存11 syscall削除集合だけを修正後baselineから除き、candidateを265 syscallから266 syscallへ再生成した。`statx`はcandidateにも1件残り、candidate bytesのSHA-256は`1860f395ed5ddde5f50fd2c3c779568b62421c0368f9fc3c706fa5f9d8e961a5`から`92e6b1e40f330e36af92a3e0ac06a8406f0dba367d15032fbf5c7c7fcc9a5543`へ変わった。candidateにbaseline外syscallはなく、package、schema、CLI、Docker argv、defaultへ接続していない。
- provenanceとreview packet: provenanceへ277 syscall、statxだけのlocal compatibility delta、Human実測日、runtime version、image digest、一時profileのminimal/boundary結果、一般的なruntime互換性や安全性を示さない制限を同期した。review packet JSON/Markdownへold/new hashとcount、修正前cases 8/10 failure、一時profileの結果、修正後real Docker再検証待ち、Human未承認・製品非接続状態を同期した。candidate_local_regressionは新artifact hashへ同期し、全caseを`human_reverification_required`として記録した。
- 検証結果: JSON 4 fileはparseに成功した。seccomp package/review/candidate専用testは18件pass・0件failだった。opt-inなしのreal Docker 2 moduleはcontract test 2件pass、real Docker test 11件skip、0件failとなり、このCodex processではDocker runtime成功を確認していない。source checkoutと専用wheel testは同一hash、277 syscall、`statx` 1件、provenance、license、installed wheelからの`importlib.resources`解決、任意path拒否を確認した。
- 未確認事項: 修正後package baselineのF025/F026とreal cases 8/10、再生成candidateのF030はHuman shellでの再検証待ちである。POSIX message queueの削除集合は、library interface名とLinux syscall名の対応、およびsend、receive、notifyのcoverageを最終Human approval前に別途reviewする。今回のrepairでは既存candidate削除集合を変更していない。
- feature状態と外部操作: `docs/features.json`を変更せず、F025/F026/F035/F036の`passes:false`、`blocked:true`を維持した。F029/F030/F034の既存pass状態も変更していない。Goal Loop、push、tag、Release、Human seccomp approvalの代行は実行していない。
- 次のHuman操作: F025、F026、F030をhost-side real Dockerで再検証し、修正後package baseline cases 8/10と再生成candidateの全case結果を別のHuman-directed stepで反映する。
- full verification: `bash scripts/init.sh`と独立full suiteはいずれも847件実行・833件pass・14件skip・0件failだった。CLI help/version、public-safety 12件pass・0件warn・0件block、policy validation、default JSON report生成・parse、docs/fixture一覧、AGENTS.md 77行、`git diff --check`も成功した。14件skipは明示opt-inのreal Dockerまたはlive integrationであり、修正後runtime成功へ読み替えていない。

## 2026-07-17 JST — Human実機Docker再検証完了

- 実行対象HEAD: `835f6ef066294b5a618abd19ef69d618bb590263`。
- 実行環境: Docker Desktop 4.79.0、Docker Engine 29.5.3、runc 1.3.6、linux/amd64。
- local image: `python@sha256:d764629ce0ddd8c71fd371e9901efb324a95789d2315a47db7e4d27e78f1b0e9`。image取得は行わず、`--pull=never`契約を維持した。
- F025結果: real Docker cases 1〜7を7件実行し、7件pass、0件failだった。normal execution、network none、read-only rootfs、writable tmpfs、non-root、bounded timeout、copy budgetの境界を確認した。
- F026結果: real Docker cases 8〜10を3件実行し、3件pass、0件failだった。修正後の`rhd-moby-default-v1`適用、local image identity binding、installed wheel resourceによる実行を確認した。
- F030再検証: candidate専用cases 1〜6、8、10を8件実行し、8件pass、failure 0だった。review packetへ実測環境とcase別結果を記録した。
- 状態更新: F025とF026を`passes:true`、`blocked:false`、`verified_at:2026-07-17T16:18:09+09:00`へ更新した。
- 維持した境界: candidateは`human_unapproved`かつ製品経路から`disconnected`のままである。成功結果は一般的な互換性、安全性、完全な隔離を示さない。
- 未完了: POSIX message queue削除集合の名称とcoverageに関するHuman review、Hosted workflow、F035、F036、candidateの最終Human判断。
- 外部操作: push、tag、Release、image pullは行っていない。

## 2026-07-17 JST — POSIX message queue syscall contract repair

- 発見した不整合: 修正前baselineは`mq_send`を含む一方、実kernel syscallの`mq_getsetattr`、`mq_timedreceive`、`mq_timedreceive_time64`、`mq_timedsend`、`mq_timedsend_time64`を欠いていた。`mq_send`と`mq_receive`はLinuxのlibrary interfaceであり、system callの対応先は`mq_timedsend`と`mq_timedreceive`である。
- upstream contract: Human確認済みのMoby v28.3.3公式profileにある`mq_getsetattr`、`mq_notify`、`mq_open`、`mq_timedreceive`、`mq_timedreceive_time64`、`mq_timedsend`、`mq_timedsend_time64`、`mq_unlink`の8 syscallへbaselineを正規化した。`statx`も同じupstream profileに存在しており、local固有の追加ではない。
- baseline差分: `mq_send`だけを削除し、欠けていた5 syscallだけをcanonicalな位置へ追加した。defaultAction、architecture contract、上記以外のsyscall集合は変更していない。allowlistは277から281 syscallとなり、SHA-256は`cd7d83a312f51451d6942e5fdbfdd651a1cbebdff6debb8ff85a352a3be439d6`から`83e021f30d3fbbdabcc4db55bb760d5947e135491ef214d241d9eda5b0f8f2e8`へ変わった。
- candidate再生成: baselineから`chroot`、`fanotify_mark`、`io_uring_enter`、`io_uring_register`、`io_uring_setup`、`mknod`、`mknodat`と8件のmqueue syscall、合計15 syscallを除外した。candidateは266 syscall、`statx`は1件、mqueue syscallは0件、baseline外syscallは0件である。
- candidate hash: 全8件のmqueue syscallを除外すると再生成後のallowlist bytesは旧candidateと同一になるため、old/new SHA-256はいずれも`92e6b1e40f330e36af92a3e0ac06a8406f0dba367d15032fbf5c7c7fcc9a5543`である。hashが同じでも、旧candidateのreal Docker 8/8結果は旧baseline provenanceと旧SC-005 contractの履歴に限定し、今回の成功証拠へ流用しない。
- provenanceとreview packet: baseline 281、candidate 266、新baseline hash、再計算したcandidate hash、upstream contractへの正規化、library interfaceとsystem call名の差、Docker Engine 29.5.3 / runc 1.3.6の既存実測、一般的な互換性や安全性を示さない制限を同期した。SC-005はtime64 variantsを含む8件をprofileのarchitecture contractで一貫して除外する。
- runtime evidence: `candidate_local_regression`を`pending_human_reverification`へ戻し、cases 1〜6、8、10をすべて`not_run`とした。candidateは`human_unapproved`、product connectionは`disconnected`のままである。
- feature状態: F025は`passes:true`、`blocked:false`、既存`verified_at`を維持した。artifact contract変更によりF026とF030を`passes:false`、`blocked:true`、`verified_at:null`へ戻した。F035/F036は`passes:false`、`blocked:true`、`verified_at:null`のままで、全体は32 passed / 4 blocked / 0 pendingである。
- 検証結果: JSON 5件はparse成功、seccomp package/review/candidate専用testは18件pass・0件fail、opt-inなしのreal Docker 2 moduleはcontract 2件pass・実Docker11件skip・0件failだった。`bash scripts/init.sh`と独立full suiteはいずれも847件実行・833件pass・14件skip・0件failだった。public-safetyは12件pass・0件warn・0件block、policy validation、機械的なsyscall/hash/count/feature照合、`git diff --check`も成功した。
- 次のHuman操作: 既存local digest-pinned imageと`--pull=never`契約のまま、F026の`RealDockerBoundaryCasesEightToTen`とF030の`CandidateSeccompRealDockerTests`をHuman shellで再実行し、新しいcase別結果をpacketへ記録する。
- 外部操作: Goal Loop、Human approvalの代行、candidateの製品接続、default変更、push、tag、Releaseは行っていない。

## 2026-07-17 JST — mqueue契約修正後のHuman実機再検証

- 実行対象HEAD: `6c638833d230735e6c8d0aeac4b240cfdcabd9aa`。
- 実行環境: Docker Desktop 4.79.0、Docker Engine 29.5.3、runc 1.3.6、linux/amd64。
- local image: `python@sha256:d764629ce0ddd8c71fd371e9901efb324a95789d2315a47db7e4d27e78f1b0e9`。image取得は行わず、`--pull=never`を維持した。
- baseline contract: 281 syscall。POSIX message queueの実system call 8件を含み、`mq_send`は含まない。
- candidate contract: 266 syscall。baselineから指定15 syscallを除外し、`mq_` syscallを含まない。candidate SHA-256は`92e6b1e40f330e36af92a3e0ac06a8406f0dba367d15032fbf5c7c7fcc9a5543`である。
- F026結果: real Docker cases 8〜10を3件実行し、3件pass、0件failだった。
- F030結果: candidate専用cases 1〜6、8、10を8件実行し、8件pass、failure 0だった。review packetへ実測環境とcase別結果を記録した。
- 状態更新: F026とF030を`passes:true`、`blocked:false`、`verified_at:2026-07-19T15:51:05+09:00`へ更新した。
- F025維持: 既存の`passes:true`、`blocked:false`、`verified_at:2026-07-17T16:18:09+09:00`を変更していない。
- 維持した境界: candidateは`human_unapproved`かつ製品経路から`disconnected`のままである。実測結果は記録されたruntime、image、OS、architectureに限定され、一般的な互換性や安全性を示さない。
- 未完了: Hosted workflow、F035、F036、candidateの最終Human判断。
- 外部操作: push、tag、Release、image pullは行っていない。
