# Sandbox-Run Roadmap

`sandbox-run` is the core execution backend for AI-agent-oriented unknown-repo
work. The roadmap below tracks hardening beyond v1. It is not an enterprise
multi-tenant execution roadmap, not a Kubernetes plan, and not a claim that
Docker proves safety for repository-derived code.

## V1 Contract

Implemented v1 scope:

- disposable workspace execution instead of running in the real repo
- secret, cache, history, credential, dependency, build, and `.git` exclusions
- symlink, path traversal, unsupported-file, and copy-budget protections
- copy-budget fail-closed behavior before command start
- locked-down Docker profile with `--network none`, `--pull=never`, read-only
  rootfs, `/tmp` tmpfs, non-root uid/gid, dropped capabilities, no-new-privileges,
  and resource limits
- minimal env injection with no wholesale host environment pass-through
- argv command handling without implicit shell wrapping
- gate / authorization binding and exit `2` policy blocks
- command exit `2` distinguished from policy exit `2` in stderr and evidence
- bounded redacted stdout/stderr previews and workspace diff evidence

## S-002: Profile Hardening

- Add rootless Docker guidance and platform caveats.
- Expand image compatibility notes for read-only rootfs and non-root users.
- Add optional seccomp profile guidance when it can stay local-first.
- Expand Docker argv contract tests and real Docker smoke coverage.
- Document unsupported platform and boundary cases.

## S-003: Stronger Authorization Binding

- Strengthen target fingerprinting and commit/tree binding.
- Add clearer image digest pinning guidance.
- Explore one-time-use or shorter-expiry authorization guidance.
- Add more machine-readable refusal reasons.
- Improve the human review flow for authorization creation.

## S-004: Execution Evidence Integration

- Import sandbox-run reports into the evidence and gate model without implying
  execution authorization.
- Preserve the rule that successful execution does not mean safe and does not
  mean authorization to continue.
- Propagate timeout, cleanup failure, observer degraded, boundary mismatch, and
  policy block as evidence limitations.
- Link gate decision sidecars and sandbox-run evidence.
- Keep artifacts redacted by default.

## S-005: AI Agent Contract

- Provide ready-to-copy instructions for Codex, Claude Code, Cursor-like
  agents, and similar tools.
- Keep the rule: never run repository-derived commands on host by default.
- Use gate first, sandbox-run second.
- Require explicit authorization when gate policy requires it.
- Fail closed on unknown, degraded, mismatched, or over-budget evidence.

## S-006: Real Docker Verification

- Keep fake runner tests only as CI and unit-test support.
- Add optional real Docker CI only with safe synthetic fixtures.
- Use local images only; do not pull images by default.
- Preserve `--pull=never` in runtime examples and tests.
- Document Docker version and scope.
- Keep sample outputs reproducible and redacted.

## S-007: External Security Review Readiness

- Maintain a threat-model checklist.
- Track known bypasses and non-goals.
- Update third-party review issue templates if needed.
- Require external review before stronger security assurance claims.
