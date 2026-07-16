# Changelog

All notable changes for repo-health-doctor are recorded here.

This project aims for semantic versioning, with one important v0.x caveat:
stable public contracts are protected, while experimental surfaces may still
change. See [docs/versioning.md](docs/versioning.md).

## Publication Status

- The package metadata and documentation use version `0.1.0`.
- The local audit baseline is commit
  `e804997f94c4e2814ad4d4ca414e2ff45f553414` (`2026-07-10 13:08:22 +0900`).
- No local tag refs are present in this checkout.
- GitHub Release status was not verified because this audit is local-only. The
  versioned entries below are not evidence that a GitHub Release or package
  publication exists.

## Unreleased

### Added

- Experimental `gate-check --sandbox-evidence`の複数入力、count・file size・
  total bytes・age・duplicate検証を追加した。gate decisionはraw sandbox reportを
  埋め込まず、report fingerprint、run ID、元gate decision fingerprintだけを
  boundedな`evidence_refs`として相互参照し、successful executionではverdictを
  改善しない。
- Experimental execution authorization `0.2-draft` image bindingを追加した。`0.1-draft` artifactは後方互換として受理し、`approved_image`ではdigest-pinned requested referenceとlocal image IDを別値としてexact検証する。`RepoDigests`とlocal image IDは同一視しない。
- Gitleaks `8.27.2`、OSV-Scanner `2.0.3`、Trivy `0.69.3`の対称な
  `Tested Versions`表、追加compatibility scenario、`Not Covered`、
  regeneration手順、matrix testを追加した。fixture exact versionだけを
  `tested`とし、`compatible_family_unverified`、`unsupported`、`denylisted`、
  `unparseable`をtested coverageから分離した。
- Experimental `gate-check --external-evidence`の複数入力、subject・age・size・
  fingerprint・duplicate・truncation検証、raw reportを含まないboundedな
  `evidence_refs` gate schema記録を追加した。
- Experimental `gate-check` authorization discoveryを追加した。trailing argvが
  ある場合だけGit top-levelの単一untracked candidateを読む。explicit
  authorizationを優先し、拒否理由、no-fallback、TOCTOU残余riskを文書化した。
- Experimental `real-scan` finding and report budgets with explicit offline
  CI smoke, local live opt-in, truncation and omitted-count reporting, and
  `--fail-on-degraded`.
- Experimental `--fail-on-gate` exit-2 gate contract and `gate-check`
  one-command authorization gate for agent integrations.
- General static supply-chain shape evidence for arbitrary repository names,
  covering lifecycle hooks, Python build-hook candidates, environment
  enumeration, credential-path references, outbound network target shape,
  workflow write-risk, and obfuscated eval candidates.
- Claude Code integration guide with PreToolUse hook examples and redacted
  sample blocked output.
- PyPI Trusted Publishing release workflow scaffolding and CI self-scan
  dogfooding gate.
- GitHub community health templates for bug reports, feature requests, security
  model review requests, and pull requests.
- Compatibility regeneration runbook and safe helper scripts for Gitleaks and
  OSV-Scanner fixture refresh work.
- Release notes and versioning policy documentation.
- Docker sandbox-run v1 core runtime with gate / authorization binding,
  locked-down profile, deterministic argv execution, disposable workspace copy,
  copy-budget fail-closed behavior, bounded redacted output previews, and a
  draft `schemas/sandbox-run.schema.json` report.

### Changed

- Synthetic supply-chain demo wording now states the fixture boundary and the
  current generalized static-shape scope.
- Agent workflow docs now distinguish repo development instructions from
  external Claude Code integration.
- README and project metadata now align on the pre-execution safety gate
  positioning.
- Public launch docs now make the sandbox-run v1 runtime boundary, local image
  requirement, and execution-authorization separation more visible.
- README opening now centers first-time-user positioning: run the gate before
  AI agents or developers execute commands from unfamiliar repositories.
- Sandbox-run `--output` now writes machine-readable JSON regardless of stdout
  format, and Docker infrastructure failures include bounded redacted
  diagnostics when a report can be produced.

### Security

- Third-party security review remains not done and external required.
- Security review entry points now ask reviewers to avoid raw secrets, private
  paths, raw scanner output, and unredacted local details.

### Experimental

- `--fail-on-gate`, `gate-check`, and static supply-chain shape evidence are
  experimental contracts in this version.
- Compatibility regeneration helpers are runbook aids only. They are not public
  compatibility contracts and do not authorize execution.
- Sandbox-run is the core unknown-repo execution runtime. It is not a complete
  malware sandbox, not a safety proof, and not unrestricted execution
  authorization.
- A successful sandbox-run is documented as bounded evidence only, not safety
  and not authorization to continue.

### Known Limitations

- `gate-check` discovery is narrow and experimental: it reads only the
  untracked Git-top-level `.repo-health-doctor.authorization.json` when
  trailing argv is present. It has no nested or alternate-path fallback, and
  discovery remains separate from execution authorization. Local-writer TOCTOU
  risk remains.
- Real compatibility remains limited to documented fixture, version, and scope.
- No scanner result proves a repository is safe.

## v0.1.0 - Versioned Baseline (Publication Unverified)

### Added

- Local-first pre-execution safety gate positioning for AI agents and
  developers reviewing unfamiliar repositories.
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
