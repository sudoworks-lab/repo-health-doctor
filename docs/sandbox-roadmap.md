# Sandbox-Run Roadmap

The Docker sandbox-run add-on stays secondary to repo-health-doctor's primary
identity: a local-first pre-execution safety gate and evidence normalizer.

The roadmap below is personal-OSS-grade hardening. It is not an enterprise
multi-tenant execution roadmap, not a Kubernetes plan, and not a claim that
Docker makes unknown code safe.

## S-002: Profile Hardening

- Expand `no-network-readonly` coverage and image compatibility notes.
- Add optional rootless Docker guidance.
- Continue non-root default hardening.
- Refine read-only rootfs and tmpfs behavior.
- Expand Docker argv contract tests.
- Document unsupported platform and boundary cases.

## S-003: Stronger Approval Binding

- Strengthen target fingerprinting.
- Add clearer image digest pinning guidance.
- Explore one-time-use or shorter-expiry approval guidance.
- Add more machine-readable refusal reasons.
- Improve the human review flow for approval creation.

## S-004: Execution Evidence Integration

- Import sandbox-run reports into the evidence and gate model without implying
  execution authorization.
- Propagate timeout, cleanup failure, observer degraded, and boundary mismatch
  as evidence limitations.
- Link gate decision sidecars and sandbox-run evidence.
- Keep artifacts redacted by default.

## S-005: AI Agent Contract

- Provide ready-to-copy instructions for Codex, Claude Code, Cursor-like
  agents, and similar tools.
- Keep the rule: never run repository-derived commands on host by default.
- Use gate first, sandbox-run second.
- Require human approval before command execution.
- Fail closed on unknown, degraded, or mismatched evidence.

## S-006: Optional Real Docker Verification

- Keep fake runner tests as the default.
- Add optional real Docker CI only with safe synthetic fixtures.
- Do not pull images by default.
- Document Docker version and scope.
- Keep sample outputs reproducible and redacted.

## S-007: External Security Review Readiness

- Maintain a threat-model checklist.
- Track known bypasses and non-goals.
- Update third-party review issue templates if needed.
- Require external review before stronger security assurance claims.
