# Agent Development Guide

## What Agents May Do

- Edit Python source, docs, fixtures, and tests inside this repo
- Add small policy entries when they are justified and scoped
- Run the required local verification commands
- Update golden outputs only when behavior changes intentionally and redaction is preserved

## What Agents Must Not Do

- Add network calls
- Exfiltrate or print raw secrets, tokens, private paths, local IPs, or policy raw values
- Weaken redaction
- Change `schema_version`, existing `rule_id`, or CLI behavior without explicit maintainer instruction
- Commit generated reports, caches, or local-only policy files
- Publish, release, or trigger external actions without human approval

## Gates

### Pre-Agent

`PYTHONPATH=src python3 -m repo_health_doctor . --fail-on block --public-safety --fail-on-gate quarantine`

Stop if the result is `BLOCK`, `QUARANTINE`, or exit `2`.

### Post-Agent

- `PYTHONPATH=src python3 -m unittest discover -s tests -v`
- `PYTHONPATH=src python3 -m repo_health_doctor . --fail-on block --public-safety --fail-on-gate quarantine`
- `PYTHONPATH=src python3 -m repo_health_doctor validate-policy .`

### Release

`PYTHONPATH=src python3 -m repo_health_doctor . --fail-on warn --public-safety`

## Reading The JSON Report

- `overall_status` is the gate result for the whole run
- `summary` contains pass / warn / block counts
- `checks` are stable per-check sections
- `findings` contain `rule_id`, `severity`, `file`, `pattern`, and `redacted`
- `allowed: true` means a finding matched scoped policy and remained redacted

## Rule Addition Flow

1. Inspect `tests/fixtures/` first.
2. Reuse an existing fixture if it can trigger the same scenario.
3. Add or update tests.
4. Update [rules.md](rules.md) and any affected docs.
5. Re-check golden outputs if public-safety or redaction behavior changed.

## False Positive Fix Flow

1. Decide whether the repo content should change instead of policy.
2. If policy is justified, add the smallest possible `allow_findings` entry.
3. Re-run `validate-policy` and the public-safety scan.
4. Confirm that reports still avoid raw values.

## Final Report Format

Use this heading order when summarizing work for the maintainer:

- `STATUS`
- `CHANGES`
- `WHY`
- `VERIFY`
- `RISKS`
- `NEXT`
- `META`
