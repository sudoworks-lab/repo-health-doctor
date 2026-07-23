# Versioning Policy

repo-health-doctor aims for semantic versioning, with explicit caution during
the v0.x series.

## Release Status For This Checkout

The package metadata and documentation use version `0.1.0`. The local audit
baseline is commit `e804997f94c4e2814ad4d4ca414e2ff45f553414`
(`2026-07-10 13:08:22 +0900`), and this checkout has no local tag refs. GitHub
Release status was not verified because this audit is local-only. The
`v0.1.0` sections below describe versioned contracts and limitations; they do
not assert that a GitHub Release or package publication exists.

## Stable Contracts For v0.1.0

- Default v3 JSON output compatibility is stable.
- Default CLI behavior is stable.
- Redaction principles are stable.
- No finding is not proof of safety.
- Gate decisions and execution authorization remain separate.
- Gate decisions keep `execution_authorized=false`.
- `sandbox-run` is the v1 core runtime for bounded unknown-repository command
  evidence, without claiming proof of safety or complete containment.

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
- AI agent preflight demo script and wording
- Static supply-chain shape evidence
- `schemas/execution-authorization.schema.json`
- Execution authorization artifacts and validator behavior
- `schemas/sandbox-run.schema.json`
- `schemas/verified-snapshot.schema.json`
- Sandbox-run approval, profile, Docker argv, and report wording
- Verified Snapshot Boundary v1、copy policy、budget、subject binding
- Imported Gitleaks and OSV-Scanner evidence adapters
- Real Gitleaks, OSV-Scanner, and Trivy scanner adapters
- Real-output-compatible fixture coverage
- Docker integration CI path
- Compatibility regeneration helper scripts

These surfaces may change in the v0.x series when the change is documented and
does not break the stable default v3 JSON report or default CLI behavior.
The sandbox-run runtime is core product behavior; its schema and report wording
remain draft surfaces in the v0.x series. It does not change gate decision
`execution_authorized=false` semantics or execution authorization artifact
semantics. Verified Snapshot `1.0`は新しいinternal experimental schemaであり、
stable default v3 reportの`schema_version: 1.1`を変更しない。execution
authorization `0.3-draft`はsnapshot fieldsを追加し、0.1/0.2 artifactはhistorical
validation互換として残すがreal execution authorizationには昇格させない。

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
