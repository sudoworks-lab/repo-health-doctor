# Evaluation Model

## Layers

| Layer | Purpose |
| --- | --- |
| unit tests | CLI logic and contract regression checks |
| fixtures | reusable repository examples for common scenarios |
| golden outputs | drift detection for text and JSON output |
| smoke commands | README and CI command validation |
| public-safety scan | publish-before-share gate |
| policy validation | allow / ignore policy integrity |

## Fixture Strategy

Inspect `tests/fixtures/` before creating anything new. Extend an existing fixture when it can trigger the same detection scenario.

Current minimum fixture set:

- `demo-repo`: clean repo that passes
- `missing-metadata-repo`: missing basic repository metadata
- `secret-like-repo`: secret-like content with redacted reporting
- `public-safety-repo`: restricted term, private path, or local IP detection
- `tracked-artifact-repo`: tracked log, cache, output, or env artifact detection
- `policies/` and `policy-valid-repo`: invalid policy, expired allow, unknown rule_id, and valid policy coverage

## Acceptance Criteria For Rule Changes

- Stable `rule_id`
- Documented severity
- Fixture reuse first, new fixture only when required
- Test or golden update
- Docs update
- Redaction preserved
- Required verification passes

## Smoke Contract

The README, demo doc, release checklist, and CLI help should all describe commands that run on the current codebase.
