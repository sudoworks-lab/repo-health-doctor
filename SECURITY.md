# Security Policy

## Supported Versions

- `main`
- The latest tagged release, when one exists

## Reporting

- Do not post suspected vulnerabilities in public issues.
- Do not include raw secrets, tokens, private paths, local IPs, or unredacted policy values.
- Include reproduction steps, impacted files or flows, and expected impact.
- Best-effort response only. No SLA is promised.

For public security model review requests that do not include sensitive details,
use [.github/ISSUE_TEMPLATE/security-model-review.yml](.github/ISSUE_TEMPLATE/security-model-review.yml).

## Scope Notes

`repo-health-doctor` is a local-first pre-execution safety gate and evidence
normalizer. It is not a complete secret scanner, security platform, malware
sandbox, or permission system for repository-derived commands. A `PASS`, gate
decision, imported scanner no-finding result, or completed `sandbox-run` report
does not prove repository safety or authorize additional execution.

Third-party security review is not done. See
[docs/security-review-needed.md](docs/security-review-needed.md).

## Sandbox Hardening Boundary

Real `sandbox-run` execution is fail-closed unless a Human-controlled
authorization validates against the exact gate decision, argv, policy, expiry,
repository commit/tree and clean state, local image ID, worktree, and
single-use reservation. Dry-run does not invoke Docker. Real images must be
strict digest-pinned references and already local; the product never pulls an
image implicitly.

The runtime streams stdout/stderr under bounded per-stream, total, and preview
budgets. Timeout or output-budget termination tracks only the current run's
label/cidfile and confirms cleanup; cleanup uncertainty is an infrastructure
failure. `/workspace` is read-only and `/out` is a size- and inode-bounded
tmpfs, so the locked-down real path does not expose a host-backed writable
mount to the command. These controls reduce exposure but do not provide
complete malware containment, VM isolation, or a safety proof.

CI and release workflows use immutable full commit SHA action references and a
hash-locked dependency file. This constrains repository-controlled workflow
drift; it does not replace review of upstream releases, the runner, Docker,
the kernel, or package provenance.
