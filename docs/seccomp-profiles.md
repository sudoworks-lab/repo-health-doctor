# Seccomp profile contract

Moby v28.3.3のdefault seccomp policyをbaselineとし、公式profileに存在する`statx`と
8件のPOSIX message queue syscall名を復元・正規化したprofileを
`rhd-moby-default-v1`という固定名のpackage dataとして同梱する。これは`locked-down`を
意味しない。`sandbox-run --seccomp`で明示選択できるが、defaultは従来どおり
`runtime-default`である。

## Resource contract

profile本体、provenance、MobyのApache-2.0 licenseは
`repo_health_doctor.sandbox.resources`に収録される。`profiles.py`の
`resolve_seccomp_profile()`は任意のfilesystem pathを受け取らず、固定された
`rhd-moby-default-v1`だけを`importlib.resources`で解決する。

provenance sidecarには次を記録する。

- Moby repositoryと`profiles/seccomp/default.json`のsource
- source version/revision
- Apache-2.0と同梱license resource
- 取得日
- syscall削減とlocal compatibility additionをしていないこと、Moby v28.3.3公式profileの
  `statx`と8件のPOSIX message queue syscall名を含むこと、およびallowlistが281 syscallで
  あること
- 元のlocal artifactが`statx`と5件の実mqueue syscallを欠き、Linux seccomp syscall名では
  ない`mq_send`を含んでいたこと、および今回がupstream contractへの正規化repairであること
- 2026-07-17 JSTのHuman実測環境、対象image digest、一時profileでのboundedな成功結果、
  修正後artifactのHuman shell再検証待ち、および一般的なruntime互換性や安全性を示さない
  という制限
- profile resource bytesのSHA-256

hashはJSONを再シリアライズした値ではなく、package dataのUTF-8 bytesそのものに対する
SHA-256である。このためsource checkoutとinstalled wheelでresource bytesが一致すれば、
`SeccompProfileResource.profile_sha256`も一致する。provenance側のhash不一致は解決時に
拒否する。

## Selection and Docker argv contract

- `runtime-default`はseccomp用の追加Docker optionを生成せず、Docker runtimeのdefaultに
  委ねる。
- `rhd-moby-default-v1`はpackage bytesを使い捨てrun rootへmaterializeし、
  `--security-opt seccomp=<controlled-profile>`として渡す。
- 任意filesystem path、`seccomp=unconfined`、`apparmor=unconfined`は許可しない。
- Docker argvは常に`--pull=never`と`--network none`をそれぞれ1回だけ含む。
- privileged、cap-add、host network/PID/IPC/UTS/cgroup/user namespace、docker.sock mountを
  guardで拒否する。

実装済みsandbox profileと2つのseccomp選択の全組合せは
`tests/fixtures/golden/sandbox-run-docker-argv.json`で固定する。golden内の
`<workspace>`、`<out>`、`<seccomp-profile>`、`<container-user>`、`<image>`は、host固有値を
保存しないための論理placeholderである。

## rootless detection

`rootless_docker_detected`と`userns_remap_detected`の検出元は、Docker daemonに対する次の
read-only queryが返す`SecurityOptions`のJSON arrayである。

```text
docker info --format {{json .SecurityOptions}}
```

`name=rootless`または`name=userns`のmarkerがあれば`true`、validなstring arrayにmarkerが
なければ`false`とする。Docker commandの不在、timeout、non-zero exit、invalid JSON、
unexpected JSON shapeでは両fieldを`unknown`に保つ。raw `docker info` outputはevidenceへ
保存しない。

この検出は観測結果であり、argv、resource limit、mount、seccompをrootless向けに調整する
機能ではない。rootless Dockerやuser namespace remappingでは、UID/GID mapping、bind mount
ownership、cgroup/resource limit、seccompやLinux Security Moduleの実効性がrootful daemonと
異なる可能性がある。このlimitationは検出結果が`true`でも解消されず、全機能対応や完全な
隔離を意味しない。

## Source checkout / wheel verification

専用testはsource checkoutのresourceを解決した後、local wheelを作成して一時領域へ
installし、同じprofile name、provenance、license、profile hashを比較する。

```bash
PYTHONPATH=src python3 -m unittest tests.test_seccomp_package_resource -v
python3 -m build --wheel --no-isolation
```

このverificationはpackage dataとargv contractを確認するものであり、実Docker runtimeで
seccompが有効であること、syscall削減の妥当性、production-readyであることを示さない。
imageごとの互換性は[image compatibility](image-compatibility.md)に記録し、実Dockerでの確認は
G009、candidate profileのHuman approvalは別の後続gateで扱う。

## 2026-07-17 baseline normalization evidence

Human shellではDocker Engine 29.5.3、runc 1.3.6、linux/amd64、
`python@sha256:d764629ce0ddd8c71fd371e9901efb324a95789d2315a47db7e4d27e78f1b0e9`
の組合せで、修正前profileがcontainer init時の`statx`拒否によりreal cases 8/10を開始できない
ことを確認した。修正前profileの一時copyへ`statx`だけを追加すると、minimal runとread-only、
tmpfs、non-root、capability drop、no-new-privilegesを含むsandbox boundary runが成功した。

当時はrepositoryのprofileへ`statx`をcompatibility deltaとして追加したが、今回のHuman確認で
`statx`自体がMoby v28.3.3公式profileに存在すると判明した。そのrepository bytesを使うreal
Docker cases 8/10と、再生成したHuman未承認candidateのF030回帰は、その後のHuman shellで
成功した。ただし、その証拠はPOSIX message queue syscall名を正規化する前のbaseline hashと
SC-005 contractに対するものであり、今回の結果へ流用しない。

Moby v28.3.3公式profileでは`statx`に加え、`mq_getsetattr`、`mq_notify`、`mq_open`、
`mq_timedreceive`、`mq_timedreceive_time64`、`mq_timedsend`、`mq_timedsend_time64`、
`mq_unlink`がallowlistに存在する。`mq_send`と`mq_receive`はlibrary interfaceであり、Linux上の
対応先は`mq_timedsend`と`mq_timedreceive`である。元のlocal artifactは`statx`と5件の実mqueue
syscallを欠き、`mq_send`を含んでいた。statx repair後にも残ったmqueue不整合を今回修正し、
time64 variantsを含む8件をprofileのarchitecture contractで一貫したbaselineへ戻した。

正規化後baselineは281 syscall、Human未承認candidateは8件すべてを除外した266 syscallで
ある。candidateは全mqueue syscallを除外するためartifact bytesとSHA-256は旧candidateから
変わらないが、旧8/8結果を新しいF030成功証拠へ流用しない。新baselineのF026とcandidateの
F030はHuman shellでの再検証待ちである。この実測と今後の再検証は、記録されたruntime、
image、OS、architectureに限定され、一般的なruntime互換性や安全性を示さない。
