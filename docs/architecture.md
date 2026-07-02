# Architecture

`repo-health-doctor` is intentionally small: a local-first pre-execution safety
gate and evidence normalizer for unfamiliar repositories.

## Core Shape

- Static repository checks for README, LICENSE, CI, tests, docs, and scripts
- Redacted public-safety checks for secret-like values, private paths, local
  IPs, tracked artifacts, cache candidates, and env-file candidates
- Policy validation and allow inventory commands that keep raw policy values out
  of reports
- `sandbox-run` core runtime for one bounded command in a disposable,
  locked-down Docker workspace after gate / authorization policy is evaluated

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

`sandbox-run` is the live execution boundary for unknown-repository command
evidence. It does not run in the real repository. It copies allowed files to a
disposable workspace, excludes secrets and local state, blocks on copy-budget
overflow, uses Docker `--network none` by default, avoids host HOME and Docker
socket mounts, and records redacted evidence.

The runtime remains fail-closed: gate, authorization, legacy approval, copy
policy, image availability, and Docker infrastructure checks can stop execution
before the command starts. This is practical strong isolation for review
evidence, not a safety proof or complete malware sandbox.
