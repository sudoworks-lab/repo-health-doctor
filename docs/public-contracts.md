# Public Contracts And Stability

This document separates stable public contract from experimental surfaces and
examples that are not public contract.

## Stable Public Contract

- Default v3 JSON output compatibility remains stable. The stable report uses
  `schema_version: 1.1` and the existing check oriented report shape.
- Default CLI behavior remains stable. Running `repo-health-doctor <path>` keeps
  the current default text report and does not emit gate sidecars or
  authorization artifacts unless explicitly requested.
- Redaction principle is stable: reports must not print raw secrets, raw scanner
  output, raw stdout or stderr, host private paths, credentials, or raw policy
  values.
- No finding is not proof of safety. Scanner silence, clean native checks, and
  missing evidence must not be described as proof that a repository is safe.
- Decision and authorization separation is stable. A gate decision is a review
  outcome, not permission to run repository derived commands.
- Gate decisions keep `execution_authorized=false`.
- Limitations must be surfaced and treated as gate inputs.
- `sandbox-run` is the v1 core execution runtime for bounded unknown-repository
  command evidence. It uses a bounded Verified Snapshot instead of a live
  repository mount, default-deny network, locked-down Docker profile, redacted
  evidence, and gate / authorization binding. It is not a safety proof and not
  complete malware containment.
- Non-dry-run Docker execution requires a valid approval artifact controlled by
  a Human;
  gate decisions and legacy approval artifacts alone do not authorize it.
- Real Docker images must be local strict digest references of the form
  `name@sha256:<64 lowercase hex>`. The product uses `--pull=never` and rejects
  option-like, mutable, malformed, whitespace, and control-character image
  values at the core boundary.
- Real execution streams stdout/stderr under per-stream, total, and preview
  budgets. Timeout, output-budget exceedance, and cleanup uncertainty are
  distinct fail-closed evidence states; full raw stdout/stderr is not retained
  or persisted.
- The real locked-down runtime mounts `/workspace` read-only and `/out` as a
  size- and inode-bounded tmpfs, and records the runtime write limits.

## Experimental

- `schemas/evidence.schema.json`
- `schemas/gate-decision.schema.json`
- `--gate-decision-output`
- `--gate-summary`
- `--fail-on-gate`
- `gate-check`
- Human-readable gate decision `explanation`
- Contextual gate explanation wording
- AI agent preflight demo script and wording
- Field research safety and reporting workflow docs wording
- Gitleaks imported evidence adapter
- OSV-Scanner imported evidence adapter
- Gitleaks real scanner adapter
- OSV-Scanner real scanner adapter
- Trivy real scanner adapter
- Sample outputs in `docs/sample-outputs/`
- `schemas/execution-authorization.schema.json`
- Execution authorization artifact and validator
- `schemas/sandbox-run.schema.json`
- `schemas/verified-snapshot.schema.json`
- Verified Snapshot Boundary v1のmanifest、copy policy、budget、subject binding
- Sandbox-run approval and report wording
- Real-output-compatible fixture coverage for Gitleaks, OSV-Scanner, and Trivy
- Docker integration CI path
- Compatibility regeneration helper scripts
- `docs/authorization-discovery.md` and the experimental authorization
  artifact discovery integration
- The [AI Agent Canonical Contract](agent-contract.md) and the tool-specific
  [Codex](integration-codex.md), [Claude Code](integration-claude-code.md), and
  [Cursor](integration-cursor.md) binding guides

The default v3 report remains the compatibility-stable output.
The evidence schema, gate decision sidecar, `--gate-summary`, human-readable
gate explanation, imported evidence adapters, real scanner adapters, and
execution authorization artifact are experimental in this version. The AI agent
preflight demo script and wording are also experimental; they do not change
global hook configuration or default CLI behavior. The field research safety
and reporting workflow docs are experimental docs-only operating protocols;
they include the protocol, field report template, synthetic example, private
candidate workflow, and publication checklist. They do not add target
collection, scanning automation, naming approval, publication automation, or
real subject research. The
real-output-compatible fixture coverage and Docker integration CI path are also
experimental; they are limited to the documented fixture, version, and CI
scope.
The sandbox-run product path is a core v1 runtime. Its report schema, legacy
approval compatibility surface, fake runner, profile wording, and contextual
report wording remain draft contract surfaces. They do not change default CLI
behavior, default v3 JSON output, or gate decision `execution_authorized=false`
semantics.
Its non-dry-run Docker path requires Human authorization, strict local digest
image binding, bounded streaming output, tracked container cleanup, and
bounded non-host-backed output storage.さらに、scan前に作成した同一の
`snapshot_id`と`manifest_fingerprint`をgate、authorization、Docker workspace、
sandbox evidenceでexact一致させる。CI and release workflow action
references are immutable full commit SHAs and their build/test tooling uses the
hash-locked `requirements-ci.lock` file. These controls do not claim complete
malware containment, VM isolation, or production safety.
Its seccomp default remains `runtime-default`. The package-owned
`rhd-moby-default-v1` and Human-approved `rhd-locked-down-v1` profiles are
available only through explicit `--seccomp` selection; arbitrary paths and
`unconfined` remain rejected. The locked-down profile removes 15 syscalls from
the Moby baseline and is intended to reduce attack surface for unknown-repository
execution, but bounded local and Hosted 8/8 results do not establish general
runtime compatibility or safety. Unsupported workloads may fail.
Contextual explanation wording may change without changing the stable default
v3 report or default CLI behavior.

### Experimental Verified Snapshot Boundary v1

gateを要求するscan、`gate-check`、`sandbox-run`は、live targetをscanとexecutionの
間で再利用しない。最初にbounded、no-follow、non-executingなsnapshotを作り、
以後のstatic scanとDockerはそのsnapshotだけを読む。default scanのstable v3
contractは変更しない。

`VerifiedSnapshot` `1.0`は次を保持する。

- canonical manifest由来の`snapshot_id`と`manifest_fingerprint`
- raw pathを出さないlocal repository identity hash
- source kind、Git commit/tree
- file count、total bytes、copy時刻、copy policy version
- file、directory、depth、total、single-file、relative-path budget
- integrity status、limitations、refusal reasons

default budgetは20,000 files、10,000 directories、depth 64、250 MiB total、
25 MiB single file、4,096 relative-path bytesである。64 KiB fixed-size stream、
iterative directory-FD traversal、`O_NOFOLLOW`、lstat/fstat、copyと同一streamの
hash、source再hash、root再照合を使用する。symlink、special file、mutation、
rename swap、budget超過、partial cleanup失敗はfail-closedである。

Git execution snapshotはGit 2.42.0以上だけを受け入れる。host subprocessは
trusted absolute Git executableの`--version`と、sanitized environmentで動く
`rev-parse`、`ls-tree`、`cat-file`のread-only plumbing allowlistだけである。
`git status`、hook、fsmonitor、filter/textconv、submodule command、credential
helper、pager、editor、prompt、network、lazy fetchをintakeに使わない。caller
`PATH`上のGit executable、linked worktree、object alternates、unsupported Gitは
real executionへfallbackしない。

Git snapshotはHEAD commit objectからexportしたbytesをmanifest化し、bounded
live treeとexact比較する。dirtyまたはuntracked repositoryはreal executionを
暗黙許可しない。non-Git repositoryはfilesystem snapshotでstatic scanできるが、
commit/tree bindingがないためreal execution authorizationは常にblockする。

execution authorizationのcurrent draftは`0.3-draft`で、
`approved_scope`と`subject`の両方へ`snapshot_id`と
`manifest_fingerprint`を追加する。`0.1-draft`と`0.2-draft`はhistorical
validation互換として残るが、snapshot bindingがないartifactはreal Docker
executionを認可しない。gate、authorization、runtime snapshot、sandbox evidence
のいずれかがmissing、unresolved、mismatchならDockerは起動しない。

snapshotのread-only modeとprivate run rootは、repository codeをhostで起動しない
前提のpre-sandbox境界である。既に侵害されたhost、trusted Git binary、または
同一userの別processに対するOS-level isolationは提供しない。

### Experimental Authorization Discovery Contract

`gate-check` may discover one untracked authorization candidate only when a
trailing command is supplied after `--`, explicit authorization is absent, and
`--no-discover` is not set. The candidate is exactly the Git-top-level
`.repo-health-doctor.authorization.json`; nested, parent, sibling, alternate
filename, and other fallback search are not allowed.

The implementation exposes these bounded refusal reasons:
`tracked_refused`, `not_a_git_repo`, `symlink_refused`, `not_found`,
`parse_failed`, `too_large`, `git_error`, and `file_changed`. A refusal is
fail-closed and is not authorization. A successful discovery result still
passes the existing authorization validator and exact command binding.

The lstat/open/fstat/bounded-read checks reduce observable replacement and
growth races, but local-writer TOCTOU remains a residual risk. Discovery does
not prove safety, bind an execution subject by itself, or set
`execution_authorized`.

### Experimental AI Agent Contract

The [AI Agent Canonical Contract](agent-contract.md) defines one operational
flow for repository-derived commands:

1. `real-scan --fail-on-degraded`
2. `gate-check --external-evidence`
3. Human review and Human-controlled authorization
4. `sandbox-run --authorization`
5. `gate-check --sandbox-evidence`

Only exit 0 permits the next defined stage. The agent interpretation is:

| Exit | Agent action |
| --- | --- |
| exit 0 | Proceed only to the next stage defined by the canonical flow. |
| exit 1 | STOP and return the redacted failure evidence for review. |
| exit 2 | STOP and return the gate, policy, authorization, usage, or target-command result for review. |
| unknown | STOP when the exit code is unrecognized, signal-based, or unavailable. |

Exit 1, exit 2, or any unknown exit code means STOP. This orchestration table
does not replace each command's detailed exit semantics below. In particular,
`sandbox-run` can return a started target command's exit code, and every
nonzero target exit also stops the canonical flow. A gate decision remains
separate from execution authorization.

The [Codex](integration-codex.md),
[Claude Code](integration-claude-code.md), and
[Cursor](integration-cursor.md) guides bind this flow only to the extent
confirmed by their Human-provided official-source packet. They do not install
agent configuration, and an instruction-based binding is not a technical
enforcement guarantee.

### Experimental Gate Exit Contract

`--fail-on-gate` connects the experimental gate decision to a machine-readable
exit code without changing the existing `--fail-on` summary contract.

- Exit `0`: the command completed and no selected failure threshold was met.
- Exit `1`: existing non-gate CLI failure semantics, including `--fail-on`
  static summary checks and authorization validation failures.
- Exit `2`: the selected gate threshold blocked execution review.

`--fail-on-gate` modes:

- `block`: `BLOCK` exits `2`.
- `quarantine`: `QUARANTINE` and `BLOCK` exit `2`.
- `warn`: `WARN`, `QUARANTINE`, and `BLOCK` exit `2`.
- `unknown`: `UNKNOWN`, `WARN`, `QUARANTINE`, and `BLOCK` exit `2`.

When a gate threshold blocks, repo-health-doctor writes redacted key reasons
and next actions to stderr. Stderr must not contain raw secrets, credentials,
private host paths, local IPs, raw environment values, or raw policy values.

`gate-check` is an experimental one-command agent surface. It generates a gate
decision, validates a specified execution authorization artifact against an
exact argv when provided, and exits `2` unless a valid authorization exists and
the selected `--fail-on-gate` threshold allows the gate verdict.

`--external-evidence PATH`は明示されたreal scanner suite reportをgateへ入力する
experimental optionで、最大16件まで繰り返し指定できる。各fileは256 KiBまで、
生成から24時間以内であることに加え、schema、fingerprint、現在のrepo commitと
dirty state、duplicate、truncationを検証する。invalid、stale、subject mismatch、
over-budget、duplicate、truncatedは黙って無視せず、verdictを改善しない
fail-closed signalとして扱う。

gate decisionへ追加するのは`evidence_refs`だけである。各referenceはreport kind、
fingerprint、生成日時、bounded subject、byte数、truncation、validation status、
machine-readable reasonに限定し、raw report、entry、normalized result、入力pathは
埋め込まない。option未指定時は`evidence_refs` field自体を追加せず、従来のgate
decision shapeを維持する。

`--sandbox-evidence PATH`は明示された`sandbox-run` JSON reportをgateへ還流する
experimental optionで、複数指定できる。sandbox evidenceは最大16件、各file
256 KiB、合計1 MiB、生成から24時間以内に制限する。external evidenceと同時に
指定する場合、`evidence_refs`は合計16件までとする。schema、canonical fingerprint、
run ID、現在のgate subjectとpolicy version、元gate decision fingerprint、duplicate、
truncationを検証し、invalid、stale、subject mismatch、policy mismatch、over-budget、
duplicate、truncatedを黙って無視しない。

sandbox evidenceのreferenceは`report_kind`、report fingerprint、run ID、元gate
decision fingerprint、`snapshot_id`、manifest fingerprint、validation status、
machine-readable reasonだけを保持する。
raw sandbox report、command、stdout/stderr preview、host pathはgate decisionへ埋め込まない。
`successful_execution_is_not_safety`はinformational noteであり、successful executionに
よってverdictを改善せず、問題signalだけを同値または悪化方向へ反映する。
`--sandbox-evidence`未指定時は従来どおりsandbox referenceを追加しない。

trailing argvは`-- <command>`で渡せるが、`gate-check`自身は実行しない。明示的な
`--authorization`がない場合、trailing argvと`--no-discover`なしを条件に、Git
top-levelの単一候補だけをdiscoveryする。明示的なauthorizationは常に優先され、
候補がない、拒否される、または既存validatorで不正な場合はauthorization missing
としてexit `2`になる。`--no-discover`はdiscoveryだけを無効にし、明示的な
authorization validationは維持する。明示的なvalidationは従来どおり
`--authorization`と`--argv-json`を組み合わせる。

Claude Code hook behavior is documented by Anthropic in the
[hooks reference](https://docs.anthropic.com/en/docs/claude-code/hooks) and
[hooks guide](https://docs.anthropic.com/en/docs/claude-code/hooks-guide).
For a `PreToolUse` hook, exit `2` blocks the tool call and stderr is fed back
to Claude. Exit `1` is a foot-gun for blocking hooks: for most hook events it is
treated as a non-blocking error and the action can proceed. Hook wrappers that
intend to block must map repo-health-doctor gate failures to exit `2` and write
only redacted feedback to stderr.

Versioning rules are documented in [versioning.md](versioning.md). Compatibility
regeneration procedures are documented in
[compatibility-regeneration.md](compatibility-regeneration.md). Future field
research publication rules are documented in
[field-research-safety-protocol.md](field-research-safety-protocol.md),
[field-report-template.md](field-report-template.md),
[private-candidate-review-workflow.md](private-candidate-review-workflow.md),
and [publication-review-checklist.md](publication-review-checklist.md).

## Not Public Contract

- Internal Python module layout
- Test helper names
- Synthetic fixtures
- Demo repository internal details
- Generated temporary files
- Compatibility regeneration scripts or local Docker image names

## Security Review Status

Third-party security review is not done. It remains external required work
before making stronger security assurance claims.
