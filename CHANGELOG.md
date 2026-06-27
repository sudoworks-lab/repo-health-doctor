# Changelog

All notable changes for repo-health-doctor are recorded here.

This project aims for semantic versioning, with one important v0.x caveat:
stable public contracts are protected, while experimental surfaces may still
change. See [docs/versioning.md](docs/versioning.md).

## Unreleased

### Added

- GitHub community health templates for bug reports, feature requests, security
  model review requests, and pull requests.
- Compatibility regeneration runbook and safe helper scripts for Gitleaks and
  OSV-Scanner fixture refresh work.
- Release notes and versioning policy documentation.

### Changed

- README and project metadata now align on the pre-execution safety gate
  positioning.

### Security

- Third-party security review remains not done and external required.
- Security review entry points now ask reviewers to avoid raw secrets, private
  paths, raw scanner output, and unredacted local details.

### Experimental

- Compatibility regeneration helpers are runbook aids only. They are not public
  compatibility contracts and do not authorize execution.

### Known Limitations

- Real compatibility remains limited to documented fixture, version, and scope.
- No scanner result proves a repository is safe.

## v0.1.0 - Initial Public Release

### Added

- Local-first pre-execution safety gate positioning for AI agents and
  developers reviewing unknown repositories.
- Stable default v3 JSON compatibility for the existing check-oriented report.
- Opt-in gate decision sidecar as an experimental review signal.
- Experimental evidence and gate decision schemas.
- Experimental execution authorization artifact and validator, kept separate
  from gate decisions.
- Executable safe synthetic demos and curated sample outputs.
- Imported Gitleaks and OSV-Scanner evidence adapters as experimental evidence
  import paths.
- Redacted real-output-compatible fixture coverage for Gitleaks and
  OSV-Scanner.
- Always-on fake/local Docker boundary test path for CI.
- Public contract classification for stable, experimental, and non-contract
  surfaces.

### Changed

- README, quickstart, demo runbook, threat model, and competitor positioning now
  describe repo-health-doctor as a pre-execution gate rather than a scanner
  replacement.

### Security

- Reports must not expose raw secrets, raw scanner output, raw stdout or stderr,
  host private paths, credentials, or raw policy values.
- Scanner no finding is documented as scoped evidence only, not proof of safety.
- Gate decisions keep `execution_authorized=false`.

### Experimental

- `schemas/evidence.schema.json`
- `schemas/gate-decision.schema.json`
- `--gate-decision-output`
- Imported Gitleaks and OSV-Scanner evidence adapters
- `schemas/execution-authorization.schema.json`
- Execution authorization artifact and validator
- Real-output-compatible fixture coverage
- Docker integration CI path

### Known Limitations

- Third-party security review is not done.
- Real compatibility is limited to documented fixture, version, and scope.
- Docker is not a complete malware sandbox.
- External adapters are evidence import paths, not scanner replacements.
- Public contract migration for experimental surfaces requires future human
  review.
