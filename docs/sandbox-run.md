# Sandbox-Run V1 Core Runtime

`sandbox-run` is repo-health-doctor's core execution backend for
AI-agent-oriented unknown-repository work. It exists for the point after review
has decided that one bounded command should run, but should not run directly on
the host.

It provides practical strong isolation, disposable execution, default-deny
networking, redacted evidence capture, and gate / authorization binding. It is
not a proof of safety, not complete malware containment, and not unrestricted
execution authorization.

## Purpose

The v1 flow is:

1. live targetからboundedかつnon-executingな`VerifiedSnapshot`を作る。
2. immutable snapshotだけをstatic scanし、その`snapshot_id`へgate decisionをbindする。
3. gate decision、limitations、required actionsをHumanがreviewする。
4. 必要な場合だけ、同じsnapshotとexact argvへbindされたauthorizationで
   `sandbox-run`を実行する。
5. Dockerにはlive targetではなく同じsnapshotをread-only mountする。
6. 同じsnapshot identityを持つJSON evidenceで次のreview stepを判断する。

The command is passed as argv. sandbox-run does not silently convert it to a
shell string. If a shell is required, the caller must explicitly pass it as the
command, for example `sh -c "..."`.

## CLI Usage

Dry-run evidence without invoking Docker:

```bash
env PYTHONPATH=src python3 -m repo_health_doctor sandbox-run tests/fixtures/demo-repo \
  --dry-run \
  --profile locked-down \
  --evidence-output /tmp/rhd-sandbox-run-dry.json \
  -- python -c "print('hello')"
python3 -m json.tool /tmp/rhd-sandbox-run-dry.json
```

Real Docker execution:

```bash
env PYTHONPATH=src python3 -m repo_health_doctor sandbox-run tests/fixtures/demo-repo \
  --profile locked-down \
  --fail-on-gate unknown \
  --image python@sha256:<64-lowercase-hex> \
  --authorization /tmp/rhd-human-authorization.json \
  --evidence-output /tmp/rhd-sandbox-run.json \
  -- python -c "print('authorized bounded probe')"
python3 -m json.tool /tmp/rhd-sandbox-run.json
```

Non-dry-run Docker execution requires a valid Human-controlled authorization.
The authorization binds the gate decision, threshold, exact argv, digest image
reference and local image ID, policy, expiry, repository commit and tree hash,
local repository identity、`snapshot_id`、manifest fingerprint、および
single-use reservationをbindする。Missing、mismatch、unresolvedなbinding、
dirty/untracked worktree、またはinvalid
authorization, including a legacy `--approval` artifact by itself, blocks
before Docker is invoked. `--dry-run` does not invoke Docker and may be used
without authorization.

Gate-bound execution:

```bash
env PYTHONPATH=src python3 -m repo_health_doctor sandbox-run examples/demo-synthetic-supply-chain \
  --profile locked-down \
  --fail-on-gate quarantine \
  --evidence-output /tmp/rhd-sandbox-run-block.json \
  -- python -c "print('will not start when gate blocks')"
```

`--output` and `--evidence-output` both write the machine-readable JSON report.
Use one of them. Stdout still follows `--format`.

## Locked-Down Profile

`locked-down` is the v1 default profile.

It generates Docker argv with:

- `--pull=never`
- `--network none`
- a local digest-pinned image in the form `name@sha256:<64 lowercase hex>`
- `/workspace` as the working directory
- the Verified Snapshot mounted read-only at `/workspace`
- `/out` as a kernel-bounded 64 MiB, 4096-inode tmpfs; it is not a host bind
- read-only container root filesystem
- `/tmp` tmpfs
- `--cap-drop ALL`
- `--security-opt no-new-privileges`
- non-root numeric `uid:gid`
- memory, CPU, and PID limits
- fake `HOME=/tmp/home`
- minimal injected env keys only

It does not mount the original repository, host HOME, host credentials, SSH
agent, or Docker socket. It does not use privileged mode, host network, host
PID, host IPC, or capability additions.

## Image Policy

sandbox-run never pulls images automatically. Docker is invoked with
`--pull=never`, so the image must already exist locally. The default
`python:3.12-slim` reference is retained for dry-run and fake-runner
documentation compatibility only. Real Docker execution accepts only a strict
digest-pinned reference and binds it to the local image ID; mutable tags,
missing or malformed digests, option-like values, whitespace, and control
characters are rejected.

## Verified Snapshot Intake

sandbox-runはreal repository内で実行せず、live targetをDockerへ直接mountしない。
privateなdisposable run rootへ`VerifiedSnapshot`を作り、static scan、gate、
authorization validation、Docker、evidenceが同じsnapshotを参照する。snapshotは
`schemas/verified-snapshot.schema.json`の`1.0`契約を持ち、raw host pathやfile
contentsをreportへ含めない。

canonical manifestはrepo-relative UTF-8 path、entry type、canonical mode、size、
SHA-256をpath順に並べ、`schema_version`と`copy_policy_version`を含むcanonical
JSONから生成する。`snapshot_id`と`manifest_fingerprint`はdomain-separated
SHA-256である。同じmanifestは走査順に依存せず同じidentityになり、file content、
path、executable modeの変更はidentityを変える。

intakeは次のdefault budgetを適用する。

| budget | default |
| --- | ---: |
| file count | 20,000 |
| directory count（rootを含む） | 10,000 |
| directory depth | 64 |
| total copied bytes | 250 MiB |
| single-file bytes | 25 MiB |
| relative-path bytes | 4,096 |
| streaming chunk | 64 KiB |

filesystem traversalはrecursive callや`Path.read_bytes()`を使わず、directory FDを
用いたiterative traversalである。fileは`lstat`後に`O_NOFOLLOW`でopenし、
`fstat`でidentity、regular-file type、mode、size、mtime、ctimeを照合する。
hashとcopyは同じ64 KiB streamで行い、sourceを再hashしてcopy中のmutationも
検出する。directoryとsource rootもintake終了時に再照合する。symlink、FIFO、
socket、device、path swap、budget超過、partial copy cleanup失敗はvalid snapshotに
ならない。

copy policyは`.git`、`.env`、`.env.*`、credential directory、shell history、
common cache、dependency tree、virtual environment、build output、coverage
artifact、OS metadata、local IDE metadataを除外する。除外対象もfile-count
processing budgetの対象であり、大量の除外fileで上限を迂回できない。

Git repositoryのreal execution snapshotはlive worktreeをsource of bytesにしない。
Git 2.42.0以上のread-only plumbingでHEAD commit/treeを解決し、commit blobを
stream exportする。blob object IDと実際に書いたbytesを同時に検証した後、
bounded live tree manifestとのexact一致とHEAD commit/treeの再照合を行う。
dirty、untracked、symlink/submodule、linked worktree、object alternatesは
fail-closedである。non-Git repositoryはfilesystem snapshot上でstatic scanできるが、
commit/treeへbindできないためreal execution authorizationは成立しない。

budgetまたはintegrity checkが失敗した場合、sandbox-runはcommandを開始せず、
partial snapshotを破棄し、`policy_blocked=true`、`command_started=false`、exit `2`
を返す。

The real runtime does not provide a host-backed writable path to the command:
`/workspace` is read-only and `/out` is a 64 MiB, 4096-inode tmpfs. This is the
runtime write budget; it is enforced by the mount boundary rather than by a
post-run size check or a polling watchdog. The report records the limits and
whether a path is host-backed.

Docker client output is streamed in fixed 8192-byte reads. stdout and stderr
are each limited to 64 KiB, total output is limited to 128 KiB, and previews
are separately character-bounded and redacted. Full raw stdout/stderr is not
retained in memory or written to disk. Output-budget exceedance is distinct
from timeout and is fail-closed with exit `2`.

## Network Policy

The default network policy is deny. The Docker backend uses `--network none`.
Network failure inside the command is recorded as command failure evidence, not
as policy failure. Host allowlists are not implemented in v1 and are not
claimed.

## Gate And Authorization Binding

`--fail-on-gate` generates a gate decision before Docker is invoked and blocks
with exit `2` when the verdict meets the selected threshold:

- `block`: `BLOCK`
- `quarantine`: `QUARANTINE` or `BLOCK`
- `warn`: `WARN`, `QUARANTINE`, or `BLOCK`
- `unknown`: `UNKNOWN`, `WARN`, `QUARANTINE`, or `BLOCK`

For non-dry-run Docker execution, `--authorization PATH` is mandatory.
sandbox-run validates the human-controlled execution authorization artifact
against the generated gate decision and exact argv, then performs
snapshot binding and single-use reservation immediately before Docker. The
snapshot manifest is verified before Docker planning and again after
reservation immediately before `runner.run()`. A gate
decision is still not execution authorization, and product code does not
generate or approve the artifact automatically.

real executionでは次の5つが同じ値でなければならない。

- static scan対象snapshot
- gate decision subject
- authorization `approved_scope`と`subject`
- Docker `/workspace`
- sandbox-run reportとnormalized sandbox evidence

比較対象は`repository identity`、commit、tree、`snapshot_id`、
`manifest_fingerprint`である。どれかがmissing、unresolved、mismatchなら
single-use reservationまたはDocker開始より前に拒否する。

## Host Subprocess Boundary

snapshot intakeがhost上で起動できるprocessは次だけである。

- trusted absolute pathの`git --version`
- `git ... rev-parse --verify HEAD^{commit}`
- `git ... rev-parse --verify HEAD^{tree}`
- `git ... ls-tree -rz -l --full-tree <tree>`
- `git ... cat-file --batch`

Git subcommandは`rev-parse`、`ls-tree`、`cat-file`のallowlistで二重に検査する。
`shell=False`、private cwd、sanitized environment、15秒timeout、64 KiB bounded
stderrを使用し、`ls-tree` stdoutはbounded NUL record単位、blobはbounded size
単位でstreamする。callerの`PATH`からGit executableを選ばず、hooks、
fsmonitor、filter/textconvを必要とするcommand、submodule command、credential
helper、pager、editor、prompt、network protocol、lazy fetchを使用しない。
unsupported Git versionまたはlayoutはfilesystem scanへexecution権限を
fall backせず、real executionをblockする。

The legacy `--approval` artifact is still supported for exact sandbox-run
approval compatibility for non-real paths and dry-run planning. It never
authorizes a real Docker execution by itself. If supplied, mismatches block
before Docker.

## Exit Code Contract

- Policy, gate, authorization, legacy approval, or copy-budget block: exit `2`
  with stderr prefix `SANDBOX-RUN POLICY BLOCK`.
- Output byte budget exceeded: exit `2`, with the Docker client and the
  tracked container stopped and cleanup confirmed before the result is usable.
- Timeout: exit `1`; `command_start_state` is `unknown` unless command start is
  independently confirmed, and the tracked container is cleaned up.
- sandbox-run infrastructure or configuration error: exit `1` with stderr
  prefix `SANDBOX-RUN ERROR`.
- Cleanup failure or an unconfirmed tracked-container removal: exit `1` and
  report `cleanup_uncertain`.
- Command started: return the command exit code with stderr prefix
  `SANDBOX-RUN COMMAND EXIT` when nonzero.

This means a command that exits `2` is distinguishable from a policy block:
`command_started=true`, `command_exit_code=2`, and stderr uses the command-exit
prefix.

## Evidence Report

The JSON report is `schemas/sandbox-run.schema.json` with
`report_kind: sandbox_run`. It includes:

- run id, timestamps, dry-run and preserve flags
- redacted local repository identity and snapshot manifest fingerprint
- `VerifiedSnapshot` schema/version、source kind、commit/tree、file/byte count、
  copy policy、budget、integrity status
- scan、gate、authorization、workspace、evidenceのsubject consistency
- redacted argv and command cwd
- profile, backend, Docker argv, image, and network policy
- copy policy, exclusions, symlink policy, special-file policy, and copy budget
- env policy with keys only
- gate and authorization summaries
- canonical report fingerprintとrun ID、およびgate-bound reportでは元gate decisionの
  fingerprint、subject、policy version
- `policy_blocked`, `command_started`, `command_exit_code`,
  `sandbox_exit_code`, and `block_reason`
- bounded redacted stdout/stderr previews
- stdout/stderr/total observed byte counts, byte budgets, truncation flags, and
  output-budget status
- `command_start_state` (`not_started`, `confirmed`, or `unknown`)
- created / modified / deleted file summary
- container tracking, cleanup attempt/status/failure class, runtime write
  budget, and limitations

Reports must not contain raw secrets, raw host private paths, raw local
environment values, or unbounded stdout/stderr.

JSON reportは次のgateへ明示的に還流できる。

```bash
env PYTHONPATH=src python3 -m repo_health_doctor gate-check . \
  --sandbox-evidence /tmp/rhd-sandbox-run.json \
  -- <next-command>
```

`--sandbox-evidence`は最大16件、各256 KiB、合計1 MiB、生成から24時間以内に
boundedされる。gate decisionはraw reportを保持せず、sandbox report fingerprint、
run ID、元gate decision fingerprint、`snapshot_id`、manifest fingerprint、
validation status、machine-readable reasonだけを
`evidence_refs`へ残す。duplicate fingerprintはinvalid evidenceとして扱う。
successful executionは`successful_execution_is_not_safety`というinformational noteであり、
安全証明でも次のcommandのauthorizationでもなく、gate verdictを改善しない。

## Fake Runner And Dry-Run

The fake runner and `--dry-run` are test and documentation helpers. They are
useful for argv validation, policy validation, schema checks, and CI without a
local daemon. They are not substitutes for real Docker verification of the
product path.

## Non-Goals

sandbox-run v1 is not:

- a safety proof
- complete malware containment
- VM-grade isolation
- an exploit detector
- an EDR replacement
- a scanner replacement
- a remote execution service
- authorization for arbitrary unknown-repository commands

Docker daemon, kernel, image, platform, and local configuration risks remain
review boundaries. Verified Snapshotは、既に侵害されたhost、trusted Git binaryの
改変、同一userの別processによるprivate temporary directoryへの攻撃をOS-levelに
隔離するものではない。そのようなhost compromiseを疑う場合は実行せず、別の
trusted hostまたはVMでintakeからやり直す。
