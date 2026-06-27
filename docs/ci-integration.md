# CI Integration

Use JSON for machine gating and Markdown for maintainer-readable summaries.

## Minimal Commands

```bash
repo-health-doctor . --strict --public-safety --format json --output /tmp/repo-health-doctor-result.json
repo-health-doctor . --strict --public-safety --format markdown --output /tmp/repo-health-doctor-summary.md
repo-health-doctor list-allows . --fail-on expiring-soon --format json --output /tmp/repo-health-doctor-allows.json
cat /tmp/repo-health-doctor-summary.md >> "$GITHUB_STEP_SUMMARY"
```

## Notes

- `--strict` fails on both `WARN` and `BLOCK`
- `list-allows --fail-on expiring-soon` can be a separate stale-allow gate
- Markdown is useful for GitHub Step Summary and review logs
- JSON is useful for artifacts and downstream automation
- Reports must remain redacted and must not include raw secrets, raw policy
  values, or private host paths
