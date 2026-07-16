# Sandbox image compatibility

## Current status

F017時点では、特定のimageとDocker daemonの組合せを実Dockerで検証した記録はない。
既定の`python:3.12-slim`はlocal development用のtag-based referenceであり、互換性を確認した
imageや固定されたidentityを意味しない。最初の実測記録はG009のHuman-triggered検証で作る。

## Pre-verification contract

- `sandbox-run`は既にlocalに存在するimageだけを`--pull=never`で使い、取得へfallbackしない。
- registry imageはdigest-pinned referenceを優先する。tagとlocal image IDは別のidentityとして
  扱う。
- containerはnon-root numeric userで起動する。image内のfile ownership、実行対象binary、
  `/workspace`と`/out`へのaccessはそのuserで成立する必要がある。
- `locked-down`、`inspect-only`、`no-network-readonly`はread-only rootfsとwritableな`/tmp`
  tmpfsを要求する。runtimeがそのmountとtmpfs optionを受理しても、image内commandの動作まで
  保証しない。
- `runtime-default`はDocker runtimeが提供するseccomp defaultを使う。
- `rhd-moby-default-v1`は同梱したMoby default相当のprofileを明示するが、imageとの実効的な
  互換性はまだ実Dockerで確認していない。

## rootless and platform limitation

rootless detectionは`docker info`の`SecurityOptions` markerを記録するだけで、compatibilityを
判定しない。rootless Docker、user namespace remapping、Docker version、host kernel、Linux
Security Module、cgroup version、runner OS/architectureの差により、UID/GID、bind mount
ownership、resource limit、seccomp、read-only rootfs、tmpfsの挙動が変わり得る。

検出値`false`はmarkerがなかったこと、`unknown`はqueryまたはparseで確定できなかったことを
表すだけである。どちらもrootful/rootless環境で全機能が動作する証拠ではない。

## G009 compatibility record

Human-triggered real Docker検証でfirst greenを得た場合だけ、次のbounded metadataをこの文書へ
追記する。

- exact image referenceとlocal image ID
- Docker version、runner OS、architecture
- verified dateとworkflow run IDまたはURL
- tested sandbox profileとseccomp selection
- case別結果と残ったlimitation

その記録は対象image、Docker version、OS、architecture、実行日に限定される。sandbox成功、
finding 0件、rootless markerの有無はいずれも一般的な安全性や完全な隔離を証明しない。
