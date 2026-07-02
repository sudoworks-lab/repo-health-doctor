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
- Gitleaks imported evidence adapter
- OSV-Scanner imported evidence adapter
- Sample outputs in `docs/sample-outputs/`
- `schemas/execution-authorization.schema.json`
- Execution authorization artifact and validator
- `schemas/sandbox-run.schema.json`
- Sandbox-run approval and report wording
- Real-output-compatible fixture coverage for Gitleaks and OSV-Scanner
- Docker integration CI path
- Compatibility regeneration helper scripts

The default v3 report remains the compatibility-stable output.
The evidence schema, gate decision sidecar, `--gate-summary`, human-readable
gate explanation, imported evidence adapters, and execution authorization
artifact are experimental in this version. The real-output-compatible fixture
coverage and Docker integration CI path are also experimental; they are limited
to the documented fixture, version, and CI scope.
The sandbox-run product path is a core v1 runtime. Its report schema, legacy
approval compatibility surface, fake runner, profile wording, and contextual
report wording remain draft contract surfaces. They do not change default CLI
behavior, default v3 JSON output, or gate decision `execution_authorized=false`
semantics.
Contextual explanation wording may change without changing the stable default
v3 report or default CLI behavior.

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
the selected `--fail-on-gate` threshold allows the gate verdict. It does not
auto-discover authorization artifacts in this version; callers must pass
`--authorization` and `--argv-json`.

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
[compatibility-regeneration.md](compatibility-regeneration.md).

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
