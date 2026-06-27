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

`repo-health-doctor` helps detect obvious pre-publish issues, but it is not a complete secret scanner or security platform.

Third-party security review is not done. See
[docs/security-review-needed.md](docs/security-review-needed.md).
