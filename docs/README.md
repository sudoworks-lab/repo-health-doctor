# Docs

This directory contains the public documentation set for `repo-health-doctor`.

## Core Guides

- `quickstart.md`: first-run commands and demo flow
- `demo-runbook.md`: safe synthetic demo walkthrough
- `maintainer-guide.md`: maintainer workflow and review boundaries
- `agent-guide.md`: coding-agent workflow and guardrails
- `architecture.md`: product scope and design boundaries
- `security-model.md`: redaction rules, limits, and sandbox boundary
- `evaluation-model.md`: tests, fixtures, and regression expectations
- `rules.md`: stable `rule_id` and severity meanings
- `policy.md`: policy files, `validate-policy`, and `list-allows`
- `ci-integration.md`: CI usage and GitHub Step Summary examples
- `release-checklist.md`: release verification checklist
- `public-contracts.md`: stable versus experimental surfaces
- `versioning.md`: compatibility and experimental-surface versioning
- `roadmap.md`: future work that still fits the public product boundary

## Additional Reference

- `threat-model.md`: threat assumptions and non-goals
- `compatibility-regeneration.md`: safe regeneration workflow for compatibility fixtures
- `release-notes/v0.1.0.md`: initial public release notes
- `security-review-needed.md`: third-party security review status
- `sandbox-unknown-repo-workflow.md`: plan-only unknown-repo workflow
- `sandbox-behavior-policy.md`: expected behavior policy contract
- `sandbox-image-distribution.md`: image lock and image policy design
- `sandbox-approval-transition.md`: approval artifact transition design
- `sandbox-observer-evidence-contract.md`: normalized observer evidence contract
- `sandbox-t3-exception-policy.md`: T3 exception review boundary
- `sandbox-runner-preflight-design.md`: non-executing runner preflight design
- `sandbox-single-command-live-gate-design.md`: controlled live gate design boundary

## Sample Outputs

- `sample-outputs/`: safe synthetic v3 reports and gate decision sidecars

## Schemas And Policies

- `../schemas/policy-config.schema.json`
- `../schemas/public-safety-report.schema.json`
- `../schemas/release-check-report.schema.json`
- `../schemas/evidence.schema.json`
- `../schemas/gate-decision.schema.json`
- `../schemas/execution-authorization.schema.json`
- `../schemas/sandbox-report.schema.json`
- `../schemas/sandbox-unknown-repo-profile.schema.json`
- `../schemas/external-scanner-result.schema.json`
- `../schemas/external-scanner-plan.schema.json`
- `../policies/external-scanner-execution-policy.v0.1.json`

Use the repository root [README.md](../README.md) for the main entrypoint.
