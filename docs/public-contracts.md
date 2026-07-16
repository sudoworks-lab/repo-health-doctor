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
  command evidence. It uses a disposable workspace, default-deny network,
  locked-down Docker profile, redacted evidence, and gate / authorization
  binding. It is not a safety proof and not complete malware containment.

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
- Sandbox-run approval and report wording
- Real-output-compatible fixture coverage for Gitleaks, OSV-Scanner, and Trivy
- Docker integration CI path
- Compatibility regeneration helper scripts
- `docs/authorization-discovery.md` and the experimental authorization
  artifact discovery integration

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
Contextual explanation wording may change without changing the stable default
v3 report or default CLI behavior.

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
