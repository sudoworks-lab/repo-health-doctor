# Seccomp Human review packet

このpacketはF028の分析資料を正本とし、F029でHuman未承認candidate artifact、F030で
candidate専用local real Docker regressionの結果またはfailure記録を追加したものである。
Moby default相当の
`rhd-moby-default-v1`とrepo-health-doctorのsandbox用途を比較し、
`rhd-locked-down-v1`で検討するsyscall削減候補をHuman reviewへ渡す。
F028の`review_scope`が示すとおり同featureではcandidate artifactを作成しなかった。
F029で作成したcandidateは製品pathへ接続せず、defaultも変更しない。Human判断は未完了である。

機械可読な正本は
[`seccomp-review-packet.json`](seccomp-review-packet.json)であり、以下のcandidate ID、
syscall、case、未確認runtime、却下条件はJSONと対応する。

## Baselineとsandbox用途の比較

baselineはMoby `v28.3.3`由来の`rhd-moby-default-v1`である。resource SHA-256は
`7cb8f61c6f90a7f0491194c5e3e3ac41f0d4e65e9494a0afca1575cbb43b86a2`、
`defaultAction`は`SCMP_ACT_ERRNO`、allow groupは1個、allowlisted syscallは276個である。
upstream default policyからsyscallは削減していない。これは汎用container互換性のbaselineで、
repo-health-doctor固有の固定caseへ最小化したprofileではない。

sandbox用途はHuman authorization後のbounded commandを、network none、capability drop、
no-new-privileges、non-root、resource limit、使い捨てworkspaceと組み合わせて実行する。
candidate profileのruntime regression対象はcases 1〜6、8、10である。case 7はDocker開始前の
copy budget block、case 9はauthorization bindingの検証であり、candidate syscallを実行しない。

この比較はstaticな根拠である。F025とF026のreal Docker casesは環境前提不足で未実測であり、
F027で完了したのはworkflowのstatic contractである。したがって、削減候補は実測とHuman
reviewに通るまで削除決定ではない。

## Human未承認candidate artifact

F029で[`rhd-locked-down-v1.candidate.json`](rhd-locked-down-v1.candidate.json)を
review専用artifactとして作成した。artifact bytesのSHA-256は
`1860f395ed5ddde5f50fd2c3c779568b62421c0368f9fc3c706fa5f9d8e961a5`である。
baselineの1 allow groupからSC-001〜SC-005に対応する11 syscallだけを除き、
265 syscallを維持する。追加したsyscallはない。

除いたsyscallは`chroot`、`mknod`、`mknodat`、`fanotify_mark`、
`io_uring_setup`、`io_uring_enter`、`io_uring_register`、`mq_open`、
`mq_notify`、`mq_send`、`mq_unlink`である。F029作成時点ではcandidateはHuman未承認かつ
runtime回帰未実施だった。このF029状態はJSONの`candidate_artifact`と
`candidate_runtime_results`に履歴として残し、F030の結果は`candidate_local_regression`へ
分離している。candidateはpackage data、schema、CLI、Docker argvの選択肢には接続していない。

## 削減候補

### SC-001 — `chroot`

根拠: container rootとmountはDocker側で構成され、固定caseのPython commandはcontainer内で
root変更を要求しない。根拠sourceはE-BASELINE、E-CASES、E-BOUNDARIESである。

case影響: cases 1〜6、8、10がすべてgreenのままでなければならない。cases 7、9はcandidate
syscallを実行しない。影響なしという仮説であり、candidate real Docker regression前は
未確認である。

未確認runtime: UR-ROOTFUL、UR-ROOTLESS、UR-IMAGE、UR-ARCH、UR-OCI。

却下条件:

- 必須runtime regression caseが`chroot`拒否を原因として1件でも失敗する。
- 対応対象imageのentrypointまたはbootstrapがseccomp適用後の`chroot`を必要とする。
- Human reviewでbounded sandbox commandに`chroot`を許可する運用要件が確認される。

### SC-002 — `mknod`、`mknodat`

根拠: 固定caseが作成するのはworkspaceまたはtmpfs上の通常fileだけであり、capabilityは
すべてdropされ、device nodeやspecial file作成の要件はない。根拠sourceはE-BASELINE、
E-CASES、E-BOUNDARIESである。

case影響: cases 1〜6、8、10がすべてgreenのままでなければならない。cases 7、9はcandidate
syscallを実行しない。特にcase 1と4の通常file作成が維持されることを確認する。

未確認runtime: UR-ROOTFUL、UR-ROOTLESS、UR-IMAGE、UR-ARCH、UR-OCI。

却下条件:

- case 1または4を含む必須runtime regressionが`mknod`または`mknodat`拒否で失敗する。
- 対応対象imageのentrypointがseccomp適用後にspecial fileを作成する。
- Human reviewでFIFOまたはdevice node作成をbounded sandboxの必要機能として認める。

### SC-003 — `fanotify_mark`

根拠: 固定caseのfile観測は通常のread、stat、mountinfo参照で行い、fanotifyによる
filesystem監視を開始しない。根拠sourceはE-BASELINE、E-CASESである。

case影響: cases 1〜6、8、10がすべてgreenのままでなければならない。cases 7、9はcandidate
syscallを実行しない。observerやimage初期化処理による間接利用は実測前の未確認事項である。

未確認runtime: UR-ROOTFUL、UR-ROOTLESS、UR-IMAGE、UR-ARCH、UR-OCI。

却下条件:

- 必須runtime regressionが`fanotify_mark`拒否を原因として失敗する。
- 対応対象のobserverまたはimage entrypointがfanotifyを必要とする。
- 将来の必須file observationがfanotifyに依存し、別方式では契約を満たせない。

### SC-004 — `io_uring_setup`、`io_uring_enter`、`io_uring_register`

根拠: 固定caseはPython standard libraryの同期file、procfs、socket、sleep処理だけを明示し、
io_uring APIを直接使用しない。3 syscallは一組で評価する。根拠sourceはE-BASELINE、
E-CASESである。

case影響: cases 1〜6、8、10がすべてgreenのままでなければならない。cases 7、9はcandidate
syscallを実行しない。libc、Python build、image実装による間接利用は未確認である。

未確認runtime: UR-ROOTFUL、UR-ROOTLESS、UR-IMAGE、UR-ARCH、UR-OCI。

却下条件:

- 必須runtime regressionがio_uring syscall拒否を原因として失敗する。
- 対応対象のPython、libc、image entrypointがio_uringを間接利用する。
- Human reviewでio_uringをbounded sandbox workloadの必要機能として維持すると判断する。

### SC-005 — `mq_open`、`mq_notify`、`mq_send`、`mq_unlink`

根拠: 固定caseはPOSIX message queueを作成、通知、送信、削除せず、case間のIPCも行わない。
4 syscallは一組で評価する。根拠sourceはE-BASELINE、E-CASESである。

case影響: cases 1〜6、8、10がすべてgreenのままでなければならない。cases 7、9はcandidate
syscallを実行しない。image entrypointや追加libraryによる間接利用は未確認である。

未確認runtime: UR-ROOTFUL、UR-ROOTLESS、UR-IMAGE、UR-ARCH、UR-OCI。

却下条件:

- 必須runtime regressionがPOSIX message queue syscall拒否を原因として失敗する。
- 対応対象imageのentrypointまたは必須libraryがPOSIX message queueを使用する。
- Human reviewでprocess間message queueをbounded sandboxの必要機能として認める。

## 今回は維持するsyscall

`socket`、`ioctl`、`getsockname`はcase 2のnetwork interface列挙で使う可能性がある。
network noneはsocket syscall自体が不要という意味ではない。
`clone`、`clone3`、`execve`、`execveat`、`futex`はPython、libc、process/thread
起動への影響が大きく、static確認だけでは削減根拠が不足する。
基本file I/Oの`read`、`write`、`openat`、`newfstatat`、`getdents64`も維持する。

## 未確認runtime

- UR-ROOTFUL: rootful Docker daemonへcandidate profileを適用した実行。
- UR-ROOTLESS: rootless Dockerとuserns-remap。
- UR-IMAGE: digest-pinned Python image以外のentrypoint、Python build、libc。
- UR-ARCH: x86_64以外のarchitectureとkernel version差。
- UR-OCI: Podman、containerd直接利用、gVisor、KataなどDocker以外のruntime。

## 残riskとHuman判断

F028/F029時点ではcandidate runtime evidenceは存在しなかった。F030の実測結果または
preflight failureは末尾の専用sectionに分離して記録する。cases 1〜10がgreenでも、任意の
authorized command、image entrypoint、library、kernel pathとの互換性は保証されない。
結果は記録されたDocker version、OS、architecture、kernel、image digestに限定される。syscall削減はkernel、
container runtime、image、ほかのsandbox境界のriskを除去せず、安全性や完全な隔離を
証明しない。

Humanは各candidateについてapprove、reject、reviseを判断し、candidate real Docker
regressionの全case結果と全failure、tested runtime、未確認runtime、image digest、profile
hashを確認する必要がある。candidate artifactの存在だけでは製品path接続、default変更、
Human approvalのいずれも成立しない。

<!-- F030_CANDIDATE_REGRESSION_START -->
## F030 candidate専用local real Docker regression

観測日時は`2026-07-16T14:38:52+00:00`、実行状態は`preflight_failed`である。
candidate bytesのSHA-256は`1860f395ed5ddde5f50fd2c3c779568b62421c0368f9fc3c706fa5f9d8e961a5`である。
このtest pathはreview専用であり、candidateをpackage data、schema、CLI、
Docker argvの製品選択肢またはdefaultへ接続しない。Human判断は引き続きpendingである。

環境:

- Docker server: `unknown`
- Docker OS / architecture: `unknown` / `unknown`
- Kernel: `unknown`
- Rootless / userns-remap: `unknown` / `unknown`
- Existing local image digest: `unknown`
- Existing local image ID: `unknown`
- Image selection source: `default_local_tag`

case別結果:

| case | status | expected | exit code | timeout | failure codes |
|---:|---|---|---:|---|---|
| 1 | `not_run` | `completed_exit_0` | null | `false` | `preflight_blocked` |
| 2 | `not_run` | `completed_exit_0` | null | `false` | `preflight_blocked` |
| 3 | `not_run` | `completed_exit_0` | null | `false` | `preflight_blocked` |
| 4 | `not_run` | `completed_exit_0` | null | `false` | `preflight_blocked` |
| 5 | `not_run` | `completed_exit_0` | null | `false` | `preflight_blocked` |
| 6 | `not_run` | `timed_out` | null | `false` | `preflight_blocked` |
| 8 | `not_run` | `completed_exit_0` | null | `false` | `preflight_blocked` |
| 10 | `not_run` | `completed_exit_0` | null | `false` | `preflight_blocked` |

全failure:

- preflight: `docker_daemon_unavailable`
- preflight: `docker_os_unavailable`
- preflight: `docker_architecture_unavailable`
- preflight: `docker_kernel_unavailable`
- preflight: `docker_security_options_unavailable`
- preflight: `local_image_unavailable`
- case 1: `preflight_blocked`
- case 2: `preflight_blocked`
- case 3: `preflight_blocked`
- case 4: `preflight_blocked`
- case 5: `preflight_blocked`
- case 6: `preflight_blocked`
- case 8: `preflight_blocked`
- case 10: `preflight_blocked`

結果は記録されたlocal Docker環境とimage digestにだけ限定され、一般的な互換性、
安全性、完全な隔離、Human approvalを示さない。raw stdout/stderr、host path、
container名はpacketへ保存していない。
<!-- F030_CANDIDATE_REGRESSION_END -->
