# Seccomp Human review packet

このpacketはF028の分析資料を正本とし、F029でHuman未承認candidate artifact、F030で
candidate専用local real Docker regressionの結果またはfailure記録を追加したものである。
Moby default相当の
`rhd-moby-default-v1`とrepo-health-doctorのsandbox用途を比較し、
`rhd-locked-down-v1`で検討するsyscall削減候補をHuman reviewへ渡す。
F028の`review_scope`が示すとおり同featureではcandidate artifactを作成しなかった。
F029で作成したcandidateは製品pathへ接続せず、defaultも変更しない。Human判断は未完了である。
2026-07-17 JSTのstatx repair後、Human reviewでPOSIX message queue syscall名の不整合が
確認された。今回のrepairではMoby v28.3.3公式profileに存在する`statx`と8件の実mqueue
syscallをbaselineへ復元・正規化し、SC-005をその8件すべての除外contractへ修正した。

機械可読な正本は
[`seccomp-review-packet.json`](seccomp-review-packet.json)であり、以下のcandidate ID、
syscall、case、未確認runtime、却下条件はJSONと対応する。

## Baselineとsandbox用途の比較

baselineはMoby `v28.3.3`由来の`rhd-moby-default-v1`である。resource SHA-256は
`83e021f30d3fbbdabcc4db55bb760d5947e135491ef214d241d9eda5b0f8f2e8`、
`defaultAction`は`SCMP_ACT_ERRNO`、allow groupは1個、allowlisted syscallは281個である。
upstream default policyからsyscallは削減せず、local compatibility additionもない。
これは汎用container互換性のbaselineで、repo-health-doctor固有の固定caseへ最小化した
profileではない。

sandbox用途はHuman authorization後のbounded commandを、network none、capability drop、
no-new-privileges、non-root、resource limit、使い捨てworkspaceと組み合わせて実行する。
candidate profileのruntime regression対象はcases 1〜6、8、10である。case 7はDocker開始前の
copy budget block、case 9はauthorization bindingの検証であり、candidate syscallを実行しない。

この比較はstaticな根拠である。statx repair後の旧baselineと旧SC-005 contractに対する
F026/F030のHuman shell実測は完了していたが、その結果を今回のcontract repairへ流用しない。
その後、正規化後contractをHuman shellで改めて実行し、F026 cases 8〜10は3/3 pass、F030
candidate cases 1〜6、8、10は8/8 pass、failure 0で完了した。F027で完了したのはworkflowの
static contractであり、Hosted workflowは未実行である。candidateのHuman final decisionは
pendingであり、削減候補はHuman reviewを通るまで削除決定ではない。

## statx compatibility repairのbounded evidence

2026-07-17 JST、Docker Engine 29.5.3、runc 1.3.6、linux/amd64、
`python@sha256:d764629ce0ddd8c71fd371e9901efb324a95789d2315a47db7e4d27e78f1b0e9`
のHuman shell実測では、修正前baseline
`7cb8f61c6f90a7f0491194c5e3e3ac41f0d4e65e9494a0afca1575cbb43b86a2`を使う
package real cases 8/10が、container init時の`statx`拒否で失敗した。

修正前baselineの一時copyへ`statx`だけを追加した277 syscall profile
`584ee93a7bc4a37c97c450267f524bbf96219eb176de146872325e84296441ea`では、minimal runと
read-only、tmpfs、non-root、capability drop、no-new-privilegesを含むsandbox boundary runが
成功した。repositoryのcanonical formatで生成したbaseline hashは一時profileとは異なる。

その後のHuman shellではbaseline
`cd7d83a312f51451d6942e5fdbfdd651a1cbebdff6debb8ff85a352a3be439d6`とcandidate
`92e6b1e40f330e36af92a3e0ac06a8406f0dba367d15032fbf5c7c7fcc9a5543`に対するF026/F030が
成功した。ただし、これは今回のPOSIX message queue contract repairより前の証拠であり、
新しいF026/F030結果として流用しない。上記成功は記録されたruntime、image digest、OS、
architectureだけに限定され、一般的なruntime互換性や安全性を示さない。

## POSIX message queue syscall contract repair

Moby v28.3.3公式profileでは`statx`に加え、`mq_getsetattr`、`mq_notify`、`mq_open`、
`mq_timedreceive`、`mq_timedreceive_time64`、`mq_timedsend`、`mq_timedsend_time64`、
`mq_unlink`の8 syscallがallowlistに存在する。`mq_send`と`mq_receive`はlibrary interfaceであり、
Linux上ではそれぞれ`mq_timedsend`と`mq_timedreceive`へ対応する。

元のlocal artifactは`statx`と5件の実mqueue syscallを欠き、`mq_send`を含んでいた。statx repair
後も5件の欠落と`mq_send`は残っていたため、今回`mq_send`を削除して5件をcanonicalな位置へ
復元した。baselineは277 syscallから281 syscallとなり、SHA-256は
`cd7d83a312f51451d6942e5fdbfdd651a1cbebdff6debb8ff85a352a3be439d6`から
`83e021f30d3fbbdabcc4db55bb760d5947e135491ef214d241d9eda5b0f8f2e8`へ変わった。

candidateは8件すべてを除外するため、再生成後も266 syscallで、artifact bytesとSHA-256
`92e6b1e40f330e36af92a3e0ac06a8406f0dba367d15032fbf5c7c7fcc9a5543`は変わらない。
ただし、旧8/8結果は旧baseline provenanceと旧SC-005 contractの記録としてのみ保持し、
今回のF026/F030成功証拠へ流用しなかった。正規化後contractに対するHuman shell再検証は完了し、
F026 cases 8〜10は3/3 pass、F030 candidate cases 1〜6、8、10は8/8 pass、failure 0だった。
結果は記録されたlocal runtime、image、OS、architecture、kernelに限定され、一般的な互換性、
安全性、完全な隔離を証明しない。Hosted workflowは未実行で、Human final decisionはpendingである。

## Human未承認candidate artifact

F029で[`rhd-locked-down-v1.candidate.json`](rhd-locked-down-v1.candidate.json)を
review専用artifactとして作成した。artifact bytesのSHA-256は
`92e6b1e40f330e36af92a3e0ac06a8406f0dba367d15032fbf5c7c7fcc9a5543`である。
baselineの1 allow groupからSC-001〜SC-005に対応する15 syscallだけを除き、266 syscallを
維持する。Moby v28.3.3公式profileにも存在する`statx`はcandidateへ残し、candidate固有の
追加syscallはない。

除いたsyscallは`chroot`、`mknod`、`mknodat`、`fanotify_mark`、
`io_uring_setup`、`io_uring_enter`、`io_uring_register`、`mq_getsetattr`、`mq_notify`、
`mq_open`、`mq_timedreceive`、`mq_timedreceive_time64`、`mq_timedsend`、
`mq_timedsend_time64`、`mq_unlink`である。F029作成時点ではcandidateはHuman未承認かつ
runtime回帰未実施だった。`candidate_runtime_results`はF028/F029のlegacy historical fieldとして
空配列のまま維持し、現在の詳細実測は`candidate_local_regression`を正本とする。current lifecycleは
`candidate_artifact.runtime_regression_state: completed`であるが、approvalは`human_unapproved`、
product connectionは`disconnected`である。candidateはpackage data、schema、CLI、Docker argvの
選択肢には接続していない。

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

### SC-005 — POSIX message queue 8 syscall

対象は`mq_getsetattr`、`mq_notify`、`mq_open`、`mq_timedreceive`、
`mq_timedreceive_time64`、`mq_timedsend`、`mq_timedsend_time64`、`mq_unlink`である。

根拠: 固定caseはPOSIX message queueの属性操作、作成、通知、送受信、削除を行わず、case間の
IPCも行わない。8 syscallは一組で評価する。`mq_send`と`mq_receive`はlibrary interfaceであり、
Linux上では`mq_timedsend`と`mq_timedreceive`へ対応する。time64 variantsを含め、profileの
architecture contractで一貫して除外する。根拠sourceはE-BASELINE、E-CASESである。

case影響: cases 1〜6、8、10がすべてgreenのままでなければならない。cases 7、9はcandidate
syscallを実行しない。image entrypointや追加libraryによる間接利用は未確認である。

未確認runtime: UR-ROOTFUL、UR-ROOTLESS、UR-IMAGE、UR-ARCH、UR-OCI。

却下条件:

- 必須runtime regressionがPOSIX message queue syscall拒否を原因として失敗する。
- 対応対象imageのentrypointまたは必須libraryがPOSIX message queueを使用する。
- Human reviewでprocess間message queueをbounded sandboxの必要機能として認める。

この8 syscall contractは今回のHuman判断に基づく正規化である。正規化後contractのlocal
runtime回帰は完了したが、candidate全体の最終Human判断は引き続き未完了である。

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

観測日時は`2026-07-19T06:51:05+00:00`、実行状態は`completed`である。
candidate bytesのSHA-256は`92e6b1e40f330e36af92a3e0ac06a8406f0dba367d15032fbf5c7c7fcc9a5543`である。
このtest pathはreview専用であり、candidateをpackage data、schema、CLI、
Docker argvの製品選択肢またはdefaultへ接続しない。8/8 pass、failure 0で完了したが、
Human approvalはpendingであり、Hosted workflowも未完了である。

環境:

- Docker server: `29.5.3`
- Docker OS / architecture: `Docker Desktop` / `x86_64`
- Kernel: `6.6.87.2-microsoft-standard-WSL2`
- Rootless / userns-remap: `false` / `false`
- Existing local image digest: `sha256:d764629ce0ddd8c71fd371e9901efb324a95789d2315a47db7e4d27e78f1b0e9`
- Existing local image ID: `sha256:d764629ce0ddd8c71fd371e9901efb324a95789d2315a47db7e4d27e78f1b0e9`
- Image selection source: `environment`

case別結果:

| case | status | expected | exit code | timeout | failure codes |
|---:|---|---|---:|---|---|
| 1 | `pass` | `completed_exit_0` | 0 | `false` | `none` |
| 2 | `pass` | `completed_exit_0` | 0 | `false` | `none` |
| 3 | `pass` | `completed_exit_0` | 0 | `false` | `none` |
| 4 | `pass` | `completed_exit_0` | 0 | `false` | `none` |
| 5 | `pass` | `completed_exit_0` | 0 | `false` | `none` |
| 6 | `pass` | `timed_out` | null | `true` | `none` |
| 8 | `pass` | `completed_exit_0` | 0 | `false` | `none` |
| 10 | `pass` | `completed_exit_0` | 0 | `false` | `none` |

全failure:

- なし。

結果は記録されたlocal Docker環境とimage digestにだけ限定され、一般的な互換性、
安全性、完全な隔離、Human approvalを示さない。raw stdout/stderr、host path、
container名はpacketへ保存していない。
<!-- F030_CANDIDATE_REGRESSION_END -->
