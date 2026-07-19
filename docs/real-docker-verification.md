# Real Docker verification

この検証は明示的なlocal実行専用である。testはimageを取得せず、アクセス可能なDocker daemonと、事前にlocalへ用意されたdigest-pinned imageを使う。sandbox-runが生成するDocker argvは常に`--pull=never`を含み、前提がなければtestは成功扱いにせず理由を示して停止する。

## Local prerequisites

- `RHD_REAL_DOCKER_TEST=1`を設定する。
- `RHD_REAL_DOCKER_IMAGE`には、local daemonで既に解決できる`<registry>/<image>@sha256:<digest>`形式のreferenceを設定する。tagだけのreferenceは使用しない。
- `docker image inspect "$RHD_REAL_DOCKER_IMAGE"`が成功することを確認する。この手順で`docker pull`やbuildは行わない。
- image内で固定の無害な`python3 -c`を実行できることを確認する。repo由来commandや外部serviceへのrequestは実行しない。

```bash
RHD_REAL_DOCKER_TEST=1 \
RHD_REAL_DOCKER_IMAGE='<registry>/<image>@sha256:<digest>' \
PYTHONPATH=src python3 -m unittest \
  tests.test_real_docker_verification.RealDockerBoundaryCasesEightToTen -v
```

Human未承認candidateのF030再検証は、同じ既存local image前提で次を別に実行する。

```bash
RHD_REAL_DOCKER_TEST=1 \
RHD_REAL_DOCKER_IMAGE='<registry>/<image>@sha256:<digest>' \
PYTHONPATH=src python3 -m unittest \
  tests.test_candidate_seccomp_real_docker.CandidateSeccompRealDockerTests -v
```

POSIX message queue syscall contract repair前には、Docker Engine 29.5.3、runc 1.3.6でF026と
candidate 8/8が成功していた。しかし、その証拠は旧baseline hashと旧SC-005 contractに限定し、
正規化後baseline/candidateの成功証拠へ流用しない。新baselineのF026とHuman未承認candidateの
F030は`pending_human_reverification`で、case別結果はすべて`not_run`である。candidateは
`human_unapproved`かつ製品経路から`disconnected`のままである。

## Cases 8 to 10

- case 8はpackage dataの`rhd-moby-default-v1`を使い捨てrun rootへmaterializeし、local imageへ実際に適用する。完了、original repo不変、cleanup、schema-valid evidence、`--pull=never`を確認する。
- case 9はdigest-pinned requested image referenceと`docker image inspect`で得たfull local image IDを別々に束縛する。一致時だけauthorizationが有効になり、有効な別image IDとの不一致はfail-closedになることを確認する。
- case 10はrepositoryをofflineでwheel化し、`--no-index`で一時directoryへinstalled packageを作る。そのinstalled package resourceから同じseccomp profileを解決し、local imageを`--pull=never`で実行できることを確認する。

全caseの結果は、その時点のlocal Docker runtime、OS、architecture、digest-pinned imageにだけ適用される。成功はrepositoryやimageの一般的な安全性を証明せず、image取得、Hosted run、Human approvalの代替にもならない。

## Human-triggered Hosted verification

`.github/workflows/real-docker-verification.yml`は`workflow_dispatch`だけで起動できる。
Humanは`image` inputへ`<registry>/<image>@sha256:<64 lowercase hex>`形式のreferenceを
指定する。workflowは次の順序を固定する。

1. `Acquire digest-pinned test image` stepがreference形式を検証し、imageをpullしてlocalに
   存在することを確認する。このstepだけがimage acquisitionを行う。
2. 固定test stepがsandboxの`--pull=never`契約とreal Docker cases 1〜10を実行する。
   command inputやrepo由来commandは受け取らず、test module内の固定された無害な
   `python3 -c` commandだけを使う。
3. 成否にかかわらずsummary stepがDocker server version、runner OS、architectureを
   `$GITHUB_STEP_SUMMARY`へ記録する。

Hosted workflowの実行はHuman操作であり、local Goal Loopからは起動しない。workflowの
green resultも一般的な安全性や完全な隔離の証明ではなく、対象commit、image digest、
Docker version、OS、architecture、実行日時に限定された検証結果である。正式な互換性記録は
Humanがrun metadataを確認した後にだけ追加する。
