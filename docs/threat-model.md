# Threat Model

This document positions repo-health-doctor as a pre-execution safety gate for
AI agents and developers reviewing unfamiliar repositories.

It does not prove safety. It prevents false confidence.

## Scope

repo-health-doctor focuses on evidence collection, evidence normalization,
limitation recording, and fail-closed gate decisions before an agent or
developer runs repository-derived commands.

Handles? values:

- `yes`: currently handled in a bounded, tested way
- `partial`: some evidence or gate exists, but coverage is incomplete
- `no`: not handled by repo-health-doctor
- `future`: designed or planned, but not implemented as a stable capability

| Threat | Handles? | How | Limitations |
| --- | --- | --- | --- |
| untrusted Git configurationによるhost code execution | yes | Verified Snapshot intakeは`git status`やindex refreshを使わない。Git 2.42.0以上に限定し、trusted absolute executable、固定argv、sanitized environment、`shell=False`、timeout、bounded pipeで`rev-parse`、`ls-tree`、`cat-file`だけを使う。`core.fsmonitor=false`、hooks、credential helper、pager、editor、protocol、lazy fetchを無効化し、sentinel testでrepositoryのfsmonitorと`PATH`上の偽Gitが起動しないことを確認する。 | Git公式もuntrusted `.git`で多くのcommandを実行しないよう警告しているため、allowlist外command、Git 2.42.0未満、linked worktree、object alternatesはfail-closedである。既に侵害されたhostやtrusted Git binary自体は境界外である。 |
| filesystem intakeのresource exhaustion | yes | file、directory、depth、total bytes、single-file bytes、relative-path bytesをcopy前から数え、iterative traversalと64 KiB固定chunkで処理する。Git tree listingもNUL record単位でstreamし、上限を超えた最初のentryで停止する。Git childはexec前にmemory/address space、CPU、file size、open file、process count、core dumpのhard limitを設定し、pack/delta cacheとthread数を固定した独立process groupで動かす。 | 上限内の入力でもhashとstatic scanのCPU・I/Oは消費する。これはmalware解析やhost全体のresource schedulerではない。 |
| scan・authorization・execution間のsubject substitution | yes | live sourceを直接実行境界へ渡さず、canonical manifestから`VerifiedSnapshot`を作る。default scan、real scanner、gate subject、authorization `0.3-draft`、Docker mount、sandbox evidenceは同じsnapshotへ収束する。runtimeはactual snapshotのrepository identity、commit、tree、`snapshot_id`、`manifest_fingerprint`をgateとauthorizationへ個別に照合する。 | 既に侵害された同一userのhost processに対するOS-level isolationは提供しない。 |
| source mutation / symlink swap during intake | yes | `lstat`、`O_NOFOLLOW` open、`fstat`、identity/type/mode/size/time検証、同一streamのhashとcopy、source再hash、directory/root再検証を行う。symlink、FIFO、socket、device、rename swap、partial copyをfail-closedにする。Git実行snapshotはcommit objectをexportし、そのmanifestとbounded live treeを比較する。 | filesystem timestampとinode semanticsを提供しないplatformは対象外である。no-followに必要なplatform機能がなければsnapshotを作らない。 |
| hardcoded secrets | partial | Native secret-like pattern checks and external scanner evidence can block or raise risk. | Native detection is heuristic. Dedicated secret scanners remain important. No finding is not proof that no secret exists. |
| raw secret leakage in reports | yes | Reports use redacted finding categories and tests cover raw-value avoidance. External scanner redaction flags block unsafe imported results. | Full raw scanner output redaction pipeline is not complete. |
| malicious postinstall | partial | Sandbox planning and unknown-repo profiling identify install/runtime candidates and require gated approval. | Static indicators and controlled probes are not complete malware analysis. |
| dependency confusion / malicious package behavior | partial | Unknown repo profile, Phase 1/1.5 planning, and external risk rules can surface dependency and install-chain signals. | Package ecosystem resolution and malicious package behavior coverage are incomplete. |
| outbound exfiltration attempt | partial | Sandbox behavior policy and observer evidence can treat network evidence as a blocker when observed. External evidence chains credential/network signals. | Observer degradation or absence prevents confidence. Network behavior not observed is not safe evidence. |
| GitHub Actions token abuse | partial | `zizmor-style` adapter foundation and risk rules cover broad permissions, unpinned actions, and CI token risk signals. The maintained CI and release workflows use immutable full commit SHA action references and a hash-locked dependency file. | Real zizmor output compatibility is version-dependent. actionlint/zizmor are not replaced, and upstream action or package provenance still requires review. |
| pull_request_target + untrusted checkout | partial | External risk rules map this chain to elevated risk and human review. | Requires suitable scanner or synthetic evidence; not a complete CI policy engine. |
| known vulnerable dependency | partial | External scanner result schema, risk rules, and the OSV imported evidence adapter can represent supplied vulnerability evidence, including redacted real-output-compatible fixtures. | Compatibility is version scoped. repo-health-doctor does not run OSV-Scanner or manage vulnerability databases. Imported evidence is not execution authorization. |
| SBOM transparency | future | External scanner mapping reserves Syft/SBOM evidence as dependency inventory input. | SBOM generation and validation are not implemented as a stable adapter. |
| Docker escape | partial | Sandbox planning and Docker command generation avoid Docker socket, host HOME, credentials, SSH agent, and direct repository mounts. The `sandbox-run` v1 runtime mounts only the verified immutable snapshot read-only and adds snapshot-bound gate / authorization, argv-only Docker execution, `--network none`, `--pull=never`, copy-budget fail-closed behavior, and bounded redacted output evidence. | Docker is not a complete malware sandbox; kernel, daemon, platform, and image trust risks remain. A successful sandbox-run is not a safety proof and is not authorization to continue. |
| host credential access | partial | Disposable workspace, redaction contracts, sandbox constraints, and readiness gates prohibit credential mounts and host HOME access. | Static checks cannot prove code will not attempt host credential access unless execution is observed under policy. |
| AI agent prompt/workflow injection | partial | Pre-execution gate encourages plan-only review before generated commands and workflow changes. | Prompt injection semantics are not fully modeled. Human review remains required for ambiguous instructions. |
| unknown behavior due to degraded observer | partial | Degraded observer state is not PASS and remains a limitation or blocker. | Absence of observation cannot prove absence of behavior. |
| scanner unavailable | partial | External scanner validators and risk mapper treat scanner failure, parse failure, unsupported version, or timeout as unknown/block rather than PASS. | Coverage depends on supplied scanner result fields and adapter maturity. |
| raw scanner output leakage | partial | External scanner schemas track raw-output flags; Docker path discards bounded raw output after normalization. | Full redaction pipeline and report UX hardening remain future work. |
| commit mismatch / unbound execution evidence | yes | Real execution requires one local repository identity hash, commit, tree, `snapshot_id`, and manifest fingerprint across scan, gate, authorization, workspace, and sandbox evidence. Dirty/untracked Git worktrees and non-Git subjects cannot receive real execution authorization. | Signature verification and remote repository provenance are not part of v1. A local path identity hash is local-machine identity, not proof of upstream ownership. |
| authorization artifact confusion or substitution | partial | Discovery、explicit authorization、runtime reload、argv JSONは同じ64 KiB bounded、`O_NOFOLLOW`、lstat/open/fstat/read/fstat readerを使う。authorizationはCLI、runtime、single-use reservation前後でdigestとfile stateを照合する。 | Local-writer races are reduced but same-user OS-level isolation is not provided. Discovery is not authorization; exact argv, subject, expiry, and runtime checks remain required. |
| unbounded Docker client stdout/stderr | yes | The real runner uses fixed-size streaming reads, per-stream and total byte budgets, bounded redacted previews, and fail-closed output-budget termination. Full raw output is not retained or persisted. | The observed byte count may include one bounded read chunk beyond a threshold; this is recorded as evidence. Preview redaction remains a bounded evidence boundary, not a secret detector. |
| timeout or output-budget container residue | yes | Each real run has a random label and controlled cidfile. Docker `Popen`成功後はoutput処理の`Exception`と`BaseException`を問わずcleanupを`finally`で実行し、label/cidfileで対象を特定してforced removalと残存確認を行う。 | Docker daemon or host failure can still prevent cleanup; the result then remains fail-closed and requires operator inspection. |
| host-backed runtime write growth | yes | `/workspace` is a read-only bind and `/out` is a 64 MiB, 4096-inode tmpfs in the real locked-down path. The report records host-backed status and limits; no post-run polling is used as enforcement. | The tmpfs consumes container/daemon resources and is not a complete filesystem or malware containment boundary. |

## Non-Goals

repo-health-doctor is not a replacement for dedicated scanners, security
review, endpoint detection, or complete malware sandboxing. It is the gate and
evidence normalizer that keeps scanner silence, missing evidence, degraded
observation, and unbound evidence from becoming false confidence or execution
authorization.

Verified Snapshot Boundary v1は、direct `.git` directoryを持つGit repositoryと
bounded filesystem snapshotを扱う。non-Git repositoryはsnapshot上でstatic scan
できるが、commit/treeへbindできないためreal Docker executionは拒否する。Git
repositoryでもdirty、untracked、unsupported object layout、symlink/special file、
budget超過、intake中のmutationがあればvalid snapshotとして扱わない。

Authorization discovery has the same bounded safety posture. Its machine-readable
refusal reasons are `tracked_refused`, `not_a_git_repo`, `symlink_refused`,
`not_found`, `parse_failed`, `too_large`, `git_error`, and `file_changed`.
The implementation performs single-file discovery only; nested or alternate
candidate fallback is not allowed; this is a no-fallback contract. The lstat/open/fstat/read sequence reduces
but cannot eliminate TOCTOU races with a local writer.
