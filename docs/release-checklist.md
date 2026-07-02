# Release Checklist

Use this checklist before publishing a new public version.

## Offline Local Verify

- `git status --short` shows only expected changes
- `PYTHONPATH=src python3 -m unittest discover -s tests -v`
- `PYTHONPATH=src python3 -m repo_health_doctor --help`
- `PYTHONPATH=src python3 -m repo_health_doctor --version`
- `wc -l AGENTS.md`
- `PYTHONPATH=src python3 -m repo_health_doctor . --fail-on warn --public-safety`
- `PYTHONPATH=src python3 -m repo_health_doctor . --public-safety --fail-on-gate quarantine --gate-decision-output /tmp/repo-health-doctor-self.gate.json`
- `PYTHONPATH=src python3 -m repo_health_doctor validate-policy .`
- `PYTHONPATH=src python3 -m repo_health_doctor release-check . --format markdown --output /tmp/release-check.md`
- `python3 -m json.tool /tmp/release-check.md` is not required; JSON outputs should be parsed separately

## Packaging Verify

- `python3 -m build` when the `build` package is available
- `python3 -m pip install -e .`
- `repo-health-doctor --help`
- `repo-health-doctor --version`
- `repo-health-doctor validate-policy .`

If packaging stops in a network-restricted environment before build
dependencies are available, treat offline local verify as the local baseline and
run packaging verify in CI or another environment with build dependencies
resolved.

## PyPI Trusted Publishing Setup

These steps require human maintainer action and are not performed by agents:

- Create or claim the `repo-health-doctor` project on PyPI.
- Configure PyPI Trusted Publishing for the GitHub repository and the
  `release.yml` workflow.
- Review the release workflow in `.github/workflows/release.yml`.
- Create a signed release commit or approved release branch.
- Push the release tag only after final human review.
- Confirm the GitHub `pypi` environment, protection rules, and PyPI project URL.

Do not configure manual PyPI tokens for this workflow. The release job expects
OIDC Trusted Publishing.

## Command Expectations

- `--public-safety` scans repository content for publish-blocking findings
- `validate-policy` checks policy structure and expiration without scanning the repo
- `release-check` combines scan, policy validation, allow inventory, and optional diff reporting
- `--fail-on-gate quarantine` exits `2` for `QUARANTINE` or `BLOCK` gate decisions
- `gate-check` requires explicit authorization and argv artifacts in this version

## Redaction And Contract Checks

- No raw detected values in text, JSON, or Markdown reports
- No raw policy values or private host paths in output
- `AGENTS.md` stays a short working contract
- README, docs, and workflow examples remain aligned with current CLI behavior
