# Maintainer Guide

## Purpose

`repo-health-doctor` helps maintainers decide whether a repository is ready to share, publish, or hand to automation after AI-assisted edits.

## Pre-Agent And Post-Agent Gate

- Pre-agent: `PYTHONPATH=src python3 -m repo_health_doctor . --fail-on block --public-safety`
- Post-agent: run unittest, `--public-safety`, and `validate-policy`
- Release gate: `PYTHONPATH=src python3 -m repo_health_doctor . --fail-on warn --public-safety`

Stop on any `BLOCK`. Treat `WARN` as a maintainer review item unless the release gate is configured to fail on warn.

## Merge Criteria

Merge candidates should satisfy all of the following:

- Purpose and impact are explained
- Fixture or golden output shows the change
- Redaction contract is not weakened
- Schema compatibility is explicit
- Raw secrets or private values do not appear in the diff, PR text, or test output
- Required verification passes
- Relevant docs are updated

## Policy Decisions

- Prefer fixing repo content over adding policy exceptions
- Keep `allow_findings` narrow by path and `rule_id`
- Require an owner, reason, and expiration
- Re-run `validate-policy` and `--public-safety` after policy edits

## Community Health Files

- Contribution flow: [../CONTRIBUTING.md](../CONTRIBUTING.md)
- Security reporting: [../SECURITY.md](../SECURITY.md)
- Conduct expectations: [../CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md)

## Document Map

- Agent instructions: [agent-guide.md](agent-guide.md)
- Safety boundary: [security-model.md](security-model.md)
- Rule contract: [rules.md](rules.md)
- Evaluation model: [evaluation-model.md](evaluation-model.md)
