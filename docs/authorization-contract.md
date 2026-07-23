# Execution Authorization Contract

この文書はexperimentalなexecution authorization `0.1-draft`、
`0.2-draft`互換と、Verified Snapshot Boundary v1用のcurrent
`0.3-draft`を記録する。gate decisionは単独では実行を認可しない。
authorizationもexact repository、commit、tree、snapshot、argv、image、
policy、gate decision、expiryを検証し、Human approvalとsingle-use reservationが
成立した場合だけreal Docker executionへ進める。

## Verified Snapshot subject binding

`gate-check`と`sandbox-run`はauthorizationを読む前にbounded
`VerifiedSnapshot`を作る。static scanはlive targetではなくsnapshot workspaceを
読み、gate subjectは次の値へbindされる。

| field | 算出元 | 契約 |
| --- | --- | --- |
| `repo` | absolute local repository pathをdomain-separated SHA-256へ変換したredacted identity | raw host pathをartifactへ保存せず、別local repository pathとの置換を検出する。upstream ownershipの証明ではない。 |
| `commit` | sanitized Git plumbingで解決した`HEAD^{commit}` | direct `.git` repositoryかつexact commit snapshotでなければreal executionを認可しない。 |
| `tree_hash` | sanitized Git plumbingで解決した`HEAD^{tree}` | snapshot作成前後で同一であり、authorizationとexact一致しなければならない。 |
| `snapshot_id` | copy policy、schema、canonical manifestをdomain separationしてSHA-256化 | scan、gate、authorization、Docker workspace、evidenceの共通subject identityである。 |
| `manifest_fingerprint` | canonical manifestのSHA-256 | snapshotに実際に書かれたpath、type、mode、size、content hashをbindする。 |
| `binding_kind` | Git exact snapshotなら`snapshot_bound`、non-Git static snapshotなら`path_bound` | real executionは`snapshot_bound`だけを受け入れる。 |

Git snapshotはcommit blobを64 KiB chunkでexportし、object IDと実際に書いたbytesを
同じstreamで検証する。そのmanifestをbounded live worktree manifestと比較し、
HEAD commit/treeを再確認する。`git status`は使用しない。dirty、untracked、
symlink/submodule、unsupported layout、mutation、budget超過はfail-closedである。
non-Git repositoryはstatic scanできるが、real execution authorizationは
unresolvedとして拒否する。

`0.3-draft` validatorはgate subject、authorization `approved_scope`、
authorization `subject`、runtime snapshotの`snapshot_id`と
`manifest_fingerprint`をexact比較する。gate decision fingerprintはsnapshot
subjectを含むdecision全体から計算されるため、subject fieldの置換はgate
fingerprint mismatchにもなる。

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

authorization artifactは`0.1-draft`、`0.2-draft`、`0.3-draft`を受理する。
0.1-draftのallowed field集合は変更せず、0.1 artifactへ`approved_image`を追加した
場合はunknown fieldとして拒否する。0.2-draftと0.3-draftでは
`approved_image`がoptionalで、存在する場合のfield集合は次の2つだけである。

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

## Snapshot bindingと0.3-draft

`0.3-draft`は`approved_scope`へ次を追加し、`subject`にも同じ2 fieldを要求する。

```json
{
  "snapshot_id": "sha256:<64-lowercase-hex>",
  "manifest_fingerprint": "sha256:<64-lowercase-hex>"
}
```

両fieldはgate subject、authorizationの2箇所、runtime snapshotでexact一致する。
`binding_kind`は`snapshot_bound`、commitとtreeはnon-nullでなければならない。
missing、不正shape、non-Git/path-bound subjectは
`authorization_snapshot_binding_unresolved`、validな別値は
`authorization_snapshot_binding_mismatch`で拒否する。

0.1-draftと0.2-draftはhistorical artifactのvalidation互換を保つが、
snapshot fieldを持たないためreal Docker executionには使用できない。validatorを
通ることとruntime execution authorizationを同一視しない。

## Single-use reservation

`sandbox-run --authorization`で実行認可が有効な場合、snapshot binding、
Docker argv生成、dry-run判定を終えた後、runnerの`run`呼び出し直前にだけ
single-use reservationを作る。reservation後にsnapshot integrityをもう一度検証し、
mismatchならreservationを消費済みのままDockerを起動しない。reservation markerは
認可artifactの隣に`<authorization filename>.reserved`として作成し、
`O_CREAT|O_EXCL`（利用可能な場合は`O_NOFOLLOW`も併用）、mode `0600`でatomicに
確保する。markerの内容は固定のkindとschema versionだけで、認可artifactの値、
command、pathは保存しない。

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
| `authorization_top_level_required_or_unknown_field` | top-levelのrequired/allowed field集合がartifact versionと一致しない。 |
| `authorization_kind_unsupported` | `authorization_kind`が未対応である。 |
| `authorization_schema_version_unsupported` | schema versionが未対応である。 |
| `approval_missing` | `approved`が`true`ではない。 |
| `approved_must_be_boolean` | `approved`がbooleanではない。 |
| `limitations_empty` | limitationが空または不正である。 |
| `residual_risks_empty` | residual riskが空または不正である。 |
| `approved_scope_mismatch` | repo、commit、tree、snapshot fields、`binding_kind`を含むversion別approved scopeがgate subjectと一致しない。 |
| `approved_argv_mismatch` | approved argvが実行対象argvとexact一致しない。 |
| `approved_policy_version_mismatch` | approved policy versionがgate decisionと一致しない。 |
| `based_on_gate_decision_required_or_unknown_field` | gate referenceのfield集合が一致しない。 |
| `based_on_gate_decision_mismatch` | decision kind、schema、verdict、fingerprintが一致しない。 |
| `authorization_subject_required_or_unknown_field` | version別subject field集合が一致しない。 |
| `authorization_subject_mismatch` | subjectがgate subjectのversion別fieldと一致しない。 |
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
| `authorization_snapshot_binding_mismatch` | shape-validなsnapshot IDまたはmanifest fingerprintがgate/runtime snapshotと一致しない。 |
| `authorization_snapshot_binding_unresolved` | snapshot field、snapshot-bound gate、Git commit/tree、またはruntime snapshotを解決できない。 |

warn verdictの`warn_verdict_authorization_requires_explicit_human_acceptance`はwarningであり、単独のrefusal reasonではない。

### Legacy worktree reason compatibility

Verified Snapshot Boundary v1のreal execution pathはhigh-level Git statusに依存せず、
上記snapshot reasonを使用する。次の旧reasonはhistorical validation/reportとの
互換のためregistryに残すが、dirty worktreeをclean扱いにするfallbackではない。

| refusal reason | 拒否条件 |
| --- | --- |
| `authorization_worktree_binding_mismatch` | legacy direct worktree bindingのrepo、HEAD commit、またはHEAD treeがsubjectと一致しない。 |
| `authorization_worktree_binding_unresolved` | legacy worktree bindingのGit値、subject、またはbinding kindを解決できない。 |
| `authorization_worktree_not_git` | legacy worktree binding対象がGit repositoryではない。 |
| `authorization_worktree_dirty` | legacy worktree bindingがdirty stateを観測した。 |

current reportの`worktree_binding`は`superseded_by_snapshot_binding`であり、
`snapshot_binding`がrepo、commit、tree、snapshot、manifest、gate一致を記録する。
raw repo path、raw Git output、file contentsは記録しない。

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
