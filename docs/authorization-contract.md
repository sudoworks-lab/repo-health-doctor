# Execution Authorization Contract

この文書はexperimentalなexecution authorization `0.1-draft`互換と`0.2-draft`の現行実装を記録する。gate decisionは単独では実行を認可せず、authorizationもexact scope、argv、policy、gate decision、expiryの検証をすべて通過した場合だけ`execution_authorized=true`になる。

## T0 subject binding根拠

F018開始時点の算出経路は次のとおりである。ここに記録する値は、将来の直接Git bindingが既に存在するという主張ではない。

| 項目 | 現行の算出元と値 | 現行契約への影響 |
| --- | --- | --- |
| `repo` | `src/repo_health_doctor/evidence/v3_adapter.py`の`_repo()`が常に`<repo>`を返し、`build_gate_decision_candidate_from_v3_report()`がgate subjectへ入れる。v3 reportの表示用`repo_path`はauthorization identityとして使わない。 | private pathを保持しない一方、repository identityの直接照合ではない。 |
| `commit` | v3 adapterが`null`を設定する。`git rev-parse HEAD`はこのsubject生成経路では実行しない。 | clean commitへのbindingを主張できない。 |
| `tree_hash` | v3 adapterが`null`を設定する。HEAD treeもworktree content digestもこの経路では算出しない。 | treeへのbindingを主張できない。 |
| `dirty` | gate decision subjectとauthorization `approved_scope`にはfield自体がなく、この経路ではdirty worktreeを取得しない。 | clean/dirtyをauthorization validatorだけで区別できない。 |
| `binding_kind` | v3 adapterが`path_bound`を設定する。`src/repo_health_doctor/gate/evaluator.py`の`_decision_subject()`は明示subjectを優先して、この値を正規化する。 | `commit_bound`または`tree_bound`ではない。 |

`src/repo_health_doctor/gate/authorization.py`の`_gate_subject()`はgate decisionの`repo`、`commit`、`tree_hash`、`binding_kind`を`approved_scope`へ写す。artifact内の`subject`は0.1-draft互換の`repo`、`commit`、`tree_hash`だけを持つ。validatorは`approved_scope`を4 fieldすべてで、`subject`を3 fieldすべてでgate decisionとexact比較するが、上流に存在しないGit情報を補完しない。

`gate-check`と`sandbox-run --authorization`は、対象repoのv3 scanから上記gate decisionを作り、command argvとともに同じvalidatorへ渡す。`sandbox-run`は、認可artifactの実行認可が成立した場合に限り、workspace copy前に対象pathからGitのrepo root、`HEAD` commit、`HEAD^{tree}`、`status --porcelain`を直接取得してsubjectと比較する。対象pathがGit top-levelでない場合、Git値を取得できない場合、subjectが一致しない場合、またはdirtyの場合はcommandを開始しない。直接取得値はfile-inventory fingerprint、gate subject、workspace copy結果で代用しない。

`src/repo_health_doctor/cli.py`の`_external_evidence_subject()`はexternal scanner evidenceの入力検証用に`git rev-parse HEAD`と`git status --short`からcommitとdirty stateを取得するが、その結果はauthorization gate subjectの算出元ではなく、tree hashも取得しない。scanner evidenceのbindingとexecution authorizationのbindingを同一視してはならない。

## Expiry CLI

`authorization draft`は次のexpiry optionを持つ。

```text
repo-health-doctor authorization draft --gate-decision gate.json --argv-json argv.json --expires-in-minutes 60
repo-health-doctor authorization draft --gate-decision gate.json --argv-json argv.json --expires-at 2026-07-16T12:00:00Z
```

- `--expires-in-minutes N`と`--expires-at ISO8601`は相互排他である。
- `--expires-in-minutes`は正の整数だけを受理し、現在のUTCからN分後を秒精度の`expires_at`として出力する。60分以内は運用上の推奨であり、固定policyまたは上限ではない。
- `--expires-at`はISO 8601としてparseできる値をそのまま`expires_at`へ入れる。過去時刻のdraft生成自体は可能だが、validatorは`authorization_expired`で拒否する。
- どちらも未指定なら従来どおり`expires_at: null`を出力し、`expires_at_must_be_set_before_approval` limitationを付ける。validatorはnullを`expires_at_required`で拒否する。
- draftはexpiryの有無にかかわらず`approved=false`であり、Human approvalや実行認可を生成しない。

## Image bindingと0.2-draft

authorization artifactは`0.1-draft`と`0.2-draft`を受理する。0.1-draftのallowed field集合は変更せず、0.1 artifactへ`approved_image`を追加した場合はunknown fieldとして拒否する。0.2-draftでは`approved_image`がoptionalで、存在する場合のfield集合は次の2つだけである。

```json
"approved_image": {
  "requested_reference": "python:3.12-slim@sha256:<registry-manifest-digest>",
  "resolved_image_id": "sha256:<local-image-config-id>"
}
```

- `requested_reference`はHumanが承認したexact referenceであり、`sandbox-run --image`のruntime referenceと完全一致し、registry manifest digestでpinされていなければならない。
- `resolved_image_id`はcommand開始前にlocal Docker image inspectから得る`.Id`相当のfull local image IDであり、`requested_reference`のmanifest digestとは別値としてexact一致させる。
- `RepoDigests`の値をlocal image IDの代わりには使わない。runtime image IDが未解決、referenceが不一致、またはIDが不一致ならfail-closedである。
- `approved_image`のない旧artifactは後方互換として受理するが、validation resultに`authorization_not_image_bound` limitationを付ける。これはimage identityを検証済みという意味ではない。

## Single-use reservation

`sandbox-run --authorization`で実行認可が有効な場合、workspace copy、Docker argv生成、dry-run判定を終えた後、runnerの`run`呼び出し直前にだけsingle-use reservationを作る。reservation markerは認可artifactの隣に`<authorization filename>.reserved`として作成し、`O_CREAT|O_EXCL`（利用可能な場合は`O_NOFOLLOW`も併用）、mode `0600`でatomicに確保する。markerの内容は固定のkindとschema versionだけで、認可artifactの値、command、pathは保存しない。

- markerが既に存在する場合は`authorization_single_use_reservation_exists`で拒否する。markerを削除して再利用可能にする処理はない。
- markerの作成または固定内容の書込み・同期に失敗した場合は`authorization_single_use_reservation_write_failed`で拒否する。部分的に作成されたmarkerも安全側の消費済み状態として残す。
- reservation後のDocker未起動、起動失敗、timeout、command failureでもmarkerは残るため、同じauthorizationは再利用できない。
- `gate-check`は認可validatorだけを実行し、reservationを作らない。`sandbox-run --dry-run`もmarkerを作らず、`consumed: false`を維持する。
- reservationはlocal filesystem内の非分散制御であり、central revocationやdistributed lockではない。

Image bindingのrefusal reasonは次のとおりである。

| refusal reason | 拒否条件 |
| --- | --- |
| `authorization_approved_image_invalid` | approved imageのfield集合またはobject shapeが不正である。 |
| `approved_image_reference_mismatch` | requested referenceとruntime image referenceがexact一致しない。 |
| `approved_image_digest_unpinned` | requested referenceがdigest-pinnedではない。 |
| `runtime_image_id_unresolved` | local image IDが未解決またはfull ID shapeではない。 |
| `approved_image_id_mismatch` | approved imageのresolved IDとruntime local image IDが一致しない。 |

## Refusal reason台帳

reasonはraw入力値やpathを含まないmachine-readable tokenである。artifact validatorが返す正本は`AUTHORIZATION_REFUSAL_REASONS`、discoveryが返す正本は`AUTHORIZATION_DISCOVERY_REFUSAL_REASONS`であり、testがこの文書との同期を確認する。

### Authorization artifact validator

| refusal reason | 拒否条件 |
| --- | --- |
| `authorization_must_be_object` | 入力がJSON objectではない。 |
| `authorization_top_level_required_or_unknown_field` | top-levelのrequired/allowed field集合が0.1-draftと一致しない。 |
| `authorization_kind_unsupported` | `authorization_kind`が未対応である。 |
| `authorization_schema_version_unsupported` | schema versionが未対応である。 |
| `approval_missing` | `approved`が`true`ではない。 |
| `approved_must_be_boolean` | `approved`がbooleanではない。 |
| `limitations_empty` | limitationが空または不正である。 |
| `residual_risks_empty` | residual riskが空または不正である。 |
| `approved_scope_mismatch` | repo、commit、tree、`binding_kind`を含むapproved scopeがgate subjectと一致しない。 |
| `approved_argv_mismatch` | approved argvが実行対象argvとexact一致しない。 |
| `approved_policy_version_mismatch` | approved policy versionがgate decisionと一致しない。 |
| `based_on_gate_decision_required_or_unknown_field` | gate referenceのfield集合が一致しない。 |
| `based_on_gate_decision_mismatch` | decision kind、schema、verdict、fingerprintが一致しない。 |
| `authorization_subject_required_or_unknown_field` | 0.1-draft subjectのrepo、commit、tree field集合が一致しない。 |
| `authorization_subject_mismatch` | 0.1-draft subjectがgate subjectのrepo、commit、treeと一致しない。 |
| `expires_at_required` | expiryがnullまたは空である。 |
| `expires_at_invalid` | expiryをISO 8601としてparseできない。 |
| `authorization_expired` | expiryが検証時刻以前である。 |
| `approved_by_required` | approved artifactにapprover識別子がない。 |
| `approved_at_required` | approved artifactにapproval時刻がない。 |
| `approved_at_invalid` | approval時刻をISO 8601としてparseできない。 |
| `gate_verdict_block_cannot_be_authorized` | gate verdictがblockである。 |
| `gate_verdict_quarantine_cannot_be_authorized` | gate verdictがquarantineである。 |
| `gate_verdict_unknown_cannot_be_authorized` | gate verdictがunknownである。 |
| `gate_verdict_invalid_for_authorization` | verdictが認可対象の既知値ではない。 |
| `authorization_contains_forbidden_raw_pattern` | artifact内に保持禁止patternがある。 |
| `authorization_contains_raw_host_path` | artifact内にraw host pathがある。 |

warn verdictの`warn_verdict_authorization_requires_explicit_human_acceptance`はwarningであり、単独のrefusal reasonではない。

### Worktree direct binding

`authorization subject`の`repo`、`commit`、`tree_hash`は、sandbox-run開始直前の直接Git観測と照合する。既存のredactedな`<repo>` subjectは、対象pathがGit top-levelであることを照合対象とする。`binding_kind`が`commit_bound`または`tree_bound`でないartifact、Git値が解決できないartifact、対象pathとrepo rootが一致しないartifactは実行不可である。Gitのstatusが空でない場合は`authorization_worktree_dirty`で拒否し、dirtyを許可する緩和flagは存在しない。

| refusal reason | 拒否条件 |
| --- | --- |
| `authorization_worktree_binding_mismatch` | 直接取得したrepo、HEAD commit、またはHEAD treeがauthorization subjectと一致しない。 |
| `authorization_worktree_binding_unresolved` | Git値、subject、またはbinding kindを解決できない。 |
| `authorization_worktree_not_git` | 対象pathからGit top-levelを取得できない。 |
| `authorization_worktree_dirty` | 直接取得したGit statusがcleanではない。 |

reportには`matched`、`mismatch`、`unresolved`、`dirty`の判定状態と固定reasonだけを記録し、raw repo path、commit、tree、status outputは記録しない。dry-run、gate-check、authorization不成立時はこのcommand-start binding checkを実行認可へ昇格させず、sandbox-runのcommandは開始しない。

### Authorization discovery

| refusal reason | 拒否条件 |
| --- | --- |
| `tracked_refused` | repository-root候補がGit trackedである。 |
| `not_a_git_repo` | 対象が要求されたGit top-levelではない。 |
| `symlink_refused` | 候補がsymlinkまたはsymlinkとしてopenされた。 |
| `not_found` | 単一候補が存在しない。 |
| `parse_failed` | bounded read結果がJSON objectではない。 |
| `too_large` | 候補が64 KiB上限を超える。 |
| `git_error` | boundedなGit確認を完了できない。 |
| `file_changed` | lstat、open、fstat、readの間に候補の同一性または状態を確認できない。 |

discovery refusalは別候補へのfallbackを行わず、成功時もartifact validatorを迂回しない。

### Gate-checkとsandbox-runの統合reason

| refusal reason | 拒否条件 |
| --- | --- |
| `authorization_missing` | validation対象のauthorizationがない。 |
| `authorization_invalid` | validation結果が認可せず、より具体的なblocking errorもない場合のfail-closed fallbackである。 |
| `gate_verdict_block` | 選択した`--fail-on-gate` thresholdがblock verdictを拒否する。 |
| `gate_verdict_quarantine` | 選択したthresholdがquarantine verdictを拒否する。 |
| `gate_verdict_warn` | 選択したthresholdがwarn verdictを拒否する。 |
| `gate_verdict_unknown` | 選択したthresholdがunknown verdictを拒否する。 |

argparseによるexpiry option相互排他や不正なCLI値はusage errorとしてexit 2になり、artifactの`blocking_errors`には入らない。
