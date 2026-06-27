# Requirements

This document captures the public product requirements for
`repo-health-doctor`.

## Product Requirement

`repo-health-doctor` is a local-first pre-execution safety gate and evidence
normalizer for AI agents and developers reviewing unfamiliar repositories.

## Must Preserve

- Default CLI behavior stays stable unless a maintainer approves a contract change
- Default v3 JSON output stays backward compatible
- Reports stay redacted and do not print raw secret-like values or private host paths
- Policy validation remains separate from repository scanning
- Missing or degraded evidence must not become safety proof or execution authorization
- Gate decisions keep execution authorization separate

## Public Documentation Requirement

The public repository should keep:

- `README.md` as the main entrypoint
- Maintainer and agent guides
- Security and evaluation model docs
- Policy and CI usage docs
- Public contract and versioning docs

Internal working files and push-log material are not part of the public
documentation contract.
