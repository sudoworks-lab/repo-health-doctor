# Security Review Needed

Third-party security review is not done.

This repository has local tests, public-safety checks, policy validation,
schema parse checks, imported evidence compatibility fixtures, and an
authorization artifact validator. These are not a substitute for external
security review.

## External Required Work

- Review redaction boundaries.
- Review gate decision and execution authorization separation.
- Review imported scanner compatibility assumptions.
- Review Docker scanner boundary assumptions.
- Review experimental sandbox-run approval, Docker argv, workspace, redaction,
  and report boundary assumptions.
- Review documentation for overclaims.

Use the public security model review issue template for non-sensitive review
requests:

```text
.github/ISSUE_TEMPLATE/security-model-review.yml
```

Do not include raw secrets, private paths, raw scanner output, credentials, or
unredacted local details in public issues.

Until that review happens, the correct status is:

```text
third-party security review: not_done / external_required
```
