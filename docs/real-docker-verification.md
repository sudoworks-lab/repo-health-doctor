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

## Cases 8 to 10

- case 8はpackage dataの`rhd-moby-default-v1`を使い捨てrun rootへmaterializeし、local imageへ実際に適用する。完了、original repo不変、cleanup、schema-valid evidence、`--pull=never`を確認する。
- case 9はdigest-pinned requested image referenceと`docker image inspect`で得たfull local image IDを別々に束縛する。一致時だけauthorizationが有効になり、有効な別image IDとの不一致はfail-closedになることを確認する。
- case 10はrepositoryをofflineでwheel化し、`--no-index`で一時directoryへinstalled packageを作る。そのinstalled package resourceから同じseccomp profileを解決し、local imageを`--pull=never`で実行できることを確認する。

全caseの結果は、その時点のlocal Docker runtime、OS、architecture、digest-pinned imageにだけ適用される。成功はrepositoryやimageの一般的な安全性を証明せず、image取得、Hosted run、Human approvalの代替にもならない。
