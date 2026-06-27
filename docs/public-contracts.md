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

## Experimental

- `schemas/evidence.schema.json`
- `schemas/gate-decision.schema.json`
- `--gate-decision-output`
- `--gate-summary`
- Human-readable gate decision `explanation`
- Contextual gate explanation wording
- Gitleaks imported evidence adapter
- OSV-Scanner imported evidence adapter
- Sample outputs in `docs/sample-outputs/`
- `schemas/execution-authorization.schema.json`
- Execution authorization artifact and validator
- Real-output-compatible fixture coverage for Gitleaks and OSV-Scanner
- Docker integration CI path
- Compatibility regeneration helper scripts

The default v3 report remains the compatibility-stable output.
The evidence schema, gate decision sidecar, `--gate-summary`, human-readable
gate explanation, imported evidence adapters, and execution authorization
artifact are experimental in this version. The real-output-compatible fixture
coverage and Docker integration CI path are also experimental; they are limited
to the documented fixture, version, and CI scope.
Contextual explanation wording may change without changing the stable default
v3 report or default CLI behavior.

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
