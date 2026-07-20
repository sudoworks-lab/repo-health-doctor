# Sandbox image compatibility

## Current status

digest-pinned Python image
`sha256:d764629ce0ddd8c71fd371e9901efb324a95789d2315a47db7e4d27e78f1b0e9`に対し、
`rhd-locked-down-v1` candidateは記録済みlocal環境でcases 1、2、3、4、5、6、8、10を
8/8 passし、GitHub Hosted run `29764489485`でも8/8 passした。Hosted環境はDocker
`28.0.4`、Ubuntu `24.04.4 LTS`、`x86_64`、kernel `6.17.0-1020-azure`である。
既定の`python:3.12-slim` tagは固定identityを意味せず、これらの結果をほかのimageへ
一般化しない。

## Selection contract

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
  互換性は選択したruntime、image、commandごとに異なり得る。
- `rhd-locked-down-v1`はHuman-approvedな非defaultの明示選択肢で、15 syscallをMoby baseline
  から削減する。unknown repo実行時のattack surface低減を目的とするが、unsupported workloadは
  起動または実行に失敗する可能性がある。

## rootless and platform limitation

rootless detectionは`docker info`の`SecurityOptions` markerを記録するだけで、compatibilityを
判定しない。rootless Docker、user namespace remapping、Docker version、host kernel、Linux
Security Module、cgroup version、runner OS/architectureの差により、UID/GID、bind mount
ownership、resource limit、seccomp、read-only rootfs、tmpfsの挙動が変わり得る。

検出値`false`はmarkerがなかったこと、`unknown`はqueryまたはparseで確定できなかったことを
表すだけである。どちらもrootful/rootless環境で全機能が動作する証拠ではない。

## Bounded compatibility record

記録するbounded metadataは次のとおりである。

- exact image referenceとlocal image ID
- Docker version、runner OS、architecture
- verified dateとworkflow run IDまたはURL
- tested sandbox profileとseccomp selection
- case別結果と残ったlimitation

その記録は対象image、Docker version、OS、architecture、実行日に限定される。sandbox成功、
finding 0件、rootless markerの有無はいずれも一般的な安全性や完全な隔離を証明しない。

Hosted検証は`.github/workflows/real-docker-verification.yml`をHumanが`workflow_dispatch`から
起動する。必須の`image` inputはdigest-pinned registry referenceに限定され、独立した
acquisition stepで取得した後、固定testは`--pull=never`で同じlocal imageを使う。summaryには
Docker version、runner OS、architectureが残るが、green runをこの節の互換性記録へ自動転記
しない。run `29764489485`は正式接続前のcandidate bytesを検証した記録であり、F036後の
product path workflowはまだ再dispatchしていない。local/Hostedのgreen結果は全runtime互換性や
安全性、完全な隔離の証明ではない。
