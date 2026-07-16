# Seccomp profile package data

F015では、Mobyのdefault seccomp policyを`rhd-moby-default-v1`という固定名の
package dataとして同梱する。これは`locked-down`を意味せず、既存のsandboxのdefault
profile、CLI、Docker argvを変更しない。CLIでのprofile選択は後続のF016で扱う。

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

## Source checkout / wheel verification

専用testはsource checkoutのresourceを解決した後、local wheelを作成して一時領域へ
installし、同じprofile name、provenance、license、profile hashを比較する。

```bash
PYTHONPATH=src python3 -m unittest tests.test_seccomp_package_resource -v
python3 -m build --wheel --no-isolation
```

このverificationはpackage dataの同一性を確認するものであり、実Docker runtimeで
seccompが有効であること、syscall削減の妥当性、malware containment、production-ready
であることを示さない。実Dockerでの確認はG009の範囲で、candidate profileのHuman
approvalは別の後続gateで扱う。
