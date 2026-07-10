# Docs

This directory contains the public documentation set for `repo-health-doctor`.

## Core Guides

- `quickstart.md`: first-run commands and demo flow
- `ai-agent-preflight.md`: plan-only preflight demo for Claude Code / Codex / Cursor style agents via `scripts/demo_agent_preflight.py`
- `field-research-safety-protocol.md`: C-0 protocol for future field research, evidence wording, and publication review
- `field-report-template.md`: C-1 synthetic field report template for observed evidence and limitations
- `examples/synthetic-field-report.md`: C-2 internal-only synthetic field report example
- `private-candidate-review-workflow.md`: C-3 private candidate intake and review workflow
- `publication-review-checklist.md`: C-4 publication gate and public write-up checklist
- `demo-runbook.md`: safe synthetic demo walkthrough
- `maintainer-guide.md`: maintainer workflow and review boundaries
- `agent-development-guide.md`: coding-agent workflow and guardrails for this repo
- `integration-claude-code.md`: Claude Code pre-execution gate integration
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
- `sandbox-run.md`: Docker sandbox-run v1 core runtime
- `sandbox-roadmap.md`: sandbox-run hardening roadmap

## Additional Reference

- `demo.md`: legacy simple offline demo flow
- `requirements.md`: public product requirements and scope
- `threat-model.md`: threat assumptions and non-goals
- `compatibility-regeneration.md`: safe regeneration workflow for compatibility fixtures
- `external-scanner-adapter-design.md`: external scanner adapter design boundary
- `docker-integration-ci.md`: Docker integration CI boundary
- `real-scanner-suite.md`: Gitleaks / OSV-Scanner / Trivy real adapter suite
- `real-gitleaks-compatibility.md`: real Gitleaks compatibility scope
- `real-osv-compatibility.md`: real OSV-Scanner compatibility scope
- `real-trivy-compatibility.md`: real Trivy compatibility scope
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
- `sample-outputs/gate-check-blocked.txt`: redacted hook-style blocked gate output

## Schemas And Policies

- `../schemas/policy-config.schema.json`
- `../schemas/public-safety-report.schema.json`
- `../schemas/release-check-report.schema.json`
- `../schemas/evidence.schema.json`
- `../schemas/gate-decision.schema.json`
- `../schemas/execution-authorization.schema.json`
- `../schemas/sandbox-report.schema.json`
- `../schemas/sandbox-run.schema.json`
- `../schemas/sandbox-unknown-repo-profile.schema.json`
- `../schemas/external-scanner-result.schema.json`
- `../schemas/external-scanner-plan.schema.json`
- `../policies/external-scanner-execution-policy.v0.1.json`

Use the repository root [README.md](../README.md) for the main entrypoint.
