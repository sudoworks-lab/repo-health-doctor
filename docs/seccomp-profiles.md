# Seccomp profile contract

Mobyのdefault seccomp policyは`rhd-moby-default-v1`という固定名のpackage dataとして
同梱する。これは`locked-down`を意味しない。`sandbox-run --seccomp`で明示選択できるが、
defaultは従来どおり`runtime-default`である。

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
- syscall削減をしていないこと、およびpackage-owned nameとsidecarだけを追加したこと
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
