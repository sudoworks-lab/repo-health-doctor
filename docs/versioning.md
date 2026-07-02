# Versioning Policy

repo-health-doctor aims for semantic versioning, with explicit caution during
the v0.x series.

## Stable In v0.1.0

- Default v3 JSON output compatibility is stable.
- Default CLI behavior is stable.
- Redaction principles are stable.
- No finding is not proof of safety.
- Gate decisions and execution authorization remain separate.
- Gate decisions keep `execution_authorized=false`.

The stable and experimental boundary is defined in
[public-contracts.md](public-contracts.md).

## Experimental In v0.1.0

- `schemas/evidence.schema.json`
- `schemas/gate-decision.schema.json`
- `--gate-decision-output`
- `--gate-summary`
- `--fail-on-gate`
- `gate-check`
- Gate decision sidecar payloads
- Human-readable gate decision explanations
- Static supply-chain shape evidence
- `schemas/execution-authorization.schema.json`
- Execution authorization artifacts and validator behavior
- `sandbox-run`
- `schemas/sandbox-run.schema.json`
- Sandbox-run approval, profile, Docker argv, and report wording
- Imported Gitleaks and OSV-Scanner evidence adapters
- Real-output-compatible fixture coverage
- Docker integration CI path
- Compatibility regeneration helper scripts

These surfaces may change in the v0.x series when the change is documented and
does not break the stable default v3 JSON report or default CLI behavior.
Sandbox-run is an optional add-on and does not change gate decision
`execution_authorized=false` semantics or execution authorization artifact
semantics.

## Public Contract Promotion

An experimental surface can become public contract only when all of the
following are true:

- The contract is documented in [public-contracts.md](public-contracts.md).
- The schema or CLI behavior has an explicit compatibility statement.
- Tests protect backward compatibility.
- Redaction and safety boundaries are reviewed.
- Human maintainers accept the stability cost.

## Breaking Changes

Breaking changes to stable surfaces should wait for a major version once the
project leaves v0.x. During v0.x, experimental surfaces can change, but changes
must not blur these safety boundaries:

- A scanner no finding must not become safety proof.
- A gate decision must not become execution authorization.
- Raw secrets, raw scanner output, host private paths, credentials, and raw
  policy values must not be reported.
- Missing, stale, unsupported, or degraded evidence must not become confidence.

## Release Notes

Release notes live under [release-notes/](release-notes/). Each release should
state stable contracts, experimental surfaces, known limitations, and
third-party review status.

## Security Review Status

Third-party security review is not done. Versioning policy does not replace
external review of safety boundaries, redaction behavior, Docker assumptions, or
authorization separation.
