# Architecture

`repo-health-doctor` is intentionally small: a local-first pre-execution safety
gate and evidence normalizer for unfamiliar repositories.

## Core Shape

- Static repository checks for README, LICENSE, CI, tests, docs, and scripts
- Redacted public-safety checks for secret-like values, private paths, local
  IPs, tracked artifacts, cache candidates, and env-file candidates
- Policy validation and allow inventory commands that keep raw policy values out
  of reports
- Plan-first sandbox surfaces that keep execution disabled unless later gated
  by explicit approval

## Output Model

The tool renders bounded review evidence as human-readable text and
machine-readable JSON. Reports keep stable `schema_version`, stable `rule_id`
values, stable severities, and redacted findings.

## Deliberate Non-Goals

- Replacing dedicated secret scanners or vulnerability scanners
- Proving a repository is safe
- Authorizing execution from missing evidence or scanner silence
- Acting as a full malware sandbox
- Depending on network access for the default review path

## Sandbox Boundary

Sandbox-related commands remain plan-first by default. Unknown-repository live
execution is not the default operating mode. Approval artifacts, behavior
policies, image locks, and observer evidence exist to keep future execution
paths fail-closed rather than permissive.
