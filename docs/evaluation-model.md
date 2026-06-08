# Evaluation Model

## Layers

| Layer | Purpose |
| --- | --- |
| unit tests | CLI logic and contract regression checks |
| fixtures | reusable repository examples for common scenarios |
| golden outputs | drift detection for text, Markdown, and JSON output |
| smoke commands | README and CI command validation |
| public-safety scan | publish-before-share gate |
| policy validation | allow / ignore policy integrity |
| report diff | before/after report regression and redaction-safe comparison |

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

## Markdown Report Smoke

Maintain at least one smoke path for Markdown output so CI-facing formatting drift is visible.

```bash
PYTHONPATH=src python3 -m repo_health_doctor . --public-safety --format markdown --output /tmp/repo-health-doctor-summary.md
test -s /tmp/repo-health-doctor-summary.md
grep -E "Repo Health Doctor|PASS|WARN|BLOCK|Checks" /tmp/repo-health-doctor-summary.md
```

## Report Diff Smoke

Maintain at least one test path for `diff-reports` so maintainer review output does not drift away from the redacted scan contract.

- compare two existing JSON reports instead of rescanning when the review question is "what changed since last run"
- cover added finding, resolved finding, unchanged count, severity change, and check status change
- verify text, JSON, and Markdown diff output do not introduce raw values or input report paths
