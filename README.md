# repo-health-doctor

[![CI](https://github.com/sudoworks-lab/repo-health-doctor/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/sudoworks-lab/repo-health-doctor/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-blue)
![Version](https://img.shields.io/badge/version-0.1.0-blue)

repo-health-doctor is a local-first pre-execution safety gate and evidence
normalizer for people and AI agents working with unfamiliar repositories.

It does not prove safety.
It prevents false confidence.

Before an agent or developer runs `npm install`, `pip install`, `pytest`,
`make`, or a generated script, repo-health-doctor collects bounded evidence,
surfaces limitations, and keeps missing or degraded evidence from becoming a
green light.

## Who Should Use This

Use repo-health-doctor when you want a small, reviewable gate before touching a
repository you do not fully trust:

- maintainers reviewing AI-generated or external repository changes
- developers doing a first pass over an unfamiliar local checkout
- coding agents that need a fail-closed pre-execution check
- CI workflows that need redacted PASS / WARN / BLOCK reports

## 5-Minute Demo

Run these from a local checkout. They do not install Gitleaks, OSV-Scanner, or
any other host scanner, and they do not contact a network.

1. Check the command is available from the checkout:

```bash
env PYTHONPATH=src python3 -m repo_health_doctor --help
```

2. Run the no-finding-but-degraded demo and read the opt-in gate summary:

```bash
env PYTHONPATH=src python3 -m repo_health_doctor examples/demo-no-finding-but-degraded \
  --public-safety \
  --gate-summary \
  --format json \
  --output /tmp/rhd-demo-no-finding.v3.json \
  --gate-decision-output /tmp/rhd-demo-no-finding.gate.json
python3 -m json.tool /tmp/rhd-demo-no-finding.gate.json
```

3. Run the synthetic supply-chain demo:

```bash
env PYTHONPATH=src python3 -m repo_health_doctor examples/demo-synthetic-supply-chain \
  --public-safety \
  --gate-summary \
  --format json \
  --output /tmp/rhd-demo-supply-chain.v3.json \
  --gate-decision-output /tmp/rhd-demo-supply-chain.gate.json
python3 -m json.tool /tmp/rhd-demo-supply-chain.gate.json
```

The terminal summary is the demo's main readout: static health can be `PASS`
while the gate decision remains `UNKNOWN`, `WARN`, `QUARANTINE`, `BLOCK`, or
limited. It also keeps `execution_authorized=false` and explains that no
scanner finding is not proof of safety. The no-finding demo calls out missing
or degraded observer evidence; the synthetic supply-chain demo calls out the
postinstall, credential/environment, outbound target, workflow, and eval-like
signals. The sidecar JSON is available when you want to inspect the
experimental gate details.

`--gate-summary` is opt-in and intended as a human-readable demo / review aid.
It does not change the default v3 report contract. The gate decision sidecar,
human-readable explanation, and contextual wording are experimental. Even
`allow_limited` is not a safety proof or unrestricted execution permission.

More detail is in [docs/quickstart.md](docs/quickstart.md) and
[docs/demo-runbook.md](docs/demo-runbook.md).

## Experimental Sandbox-Run Add-on

The default workflow remains pre-execution gate first. `sandbox-run` is an
optional experimental Docker add-on for a human-reviewed command when the goal
is to avoid running that repository-derived command directly on the host.

It runs one explicitly approved argv in a constrained Docker container, using a
disposable workspace copy, and emits bounded redacted execution evidence. It is
not a complete malware sandbox, not a safety proof, and not unrestricted
execution authorization.

```bash
env PYTHONPATH=src python3 -m repo_health_doctor sandbox-run examples/demo-synthetic-supply-chain \
  --approval examples/approvals/demo-sandbox-run-approval.json \
  --image python:3.12-slim \
  --profile no-network-default \
  --runner fake \
  --format json \
  --output /tmp/rhd-sandbox-run.json \
  -- python3 -c "print('hello from sandbox')"
```

For `sandbox-run`, `--output` writes the machine-readable JSON report. Stdout
uses `--format`, so you can keep the terminal summary human-readable while
writing JSON to the report path.

Real Docker mode omits `--runner fake`. It never pulls images automatically;
the approved image must already exist locally, and a completed sandbox-run is
still bounded execution evidence only.

See [docs/sandbox-run.md](docs/sandbox-run.md) and
[docs/sandbox-roadmap.md](docs/sandbox-roadmap.md).

## Contributing Welcome

Issues and pull requests are welcome. This project is intentionally small and
local-first, and good contributions are reviewable, redacted, and
fixture-backed.

Do not paste secrets, private paths, raw scanner output, credentials, or
unredacted local details into issues, pull requests, fixtures, reports, or
docs. If a report involves sensitive details, follow [SECURITY.md](SECURITY.md)
instead of opening a public issue.

Good First Contributions:

- improve quickstart wording or shorten demo explanations
- add or simplify redacted fixture cases
- improve docs around limitations and public contracts
- add compatibility notes for imported scanner outputs
- add tests for fail-closed edge cases
- improve redaction checks and fixture-backed examples
- review threat-model wording for overclaiming

Prefer docs, demos, fixtures, evidence adapters, gate rules, redaction checks,
and tests that preserve fail-closed behavior. This project does not aim to
reimplement dedicated scanners.

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, test, rule-change, and
security-reporting guidance.

## What This Is Not

repo-health-doctor is not:

- a replacement for Gitleaks, TruffleHog, OSV-Scanner, Grype, Syft, zizmor,
  actionlint, Falco, Tracee, or an EDR
- a complete malware sandbox
- a dependency vulnerability database
- proof that a repository is safe
- permission to run repository-derived commands

That boundary is deliberate. A clean scanner result is scoped evidence only. A
failed scanner is not PASS. A degraded observer is not confidence. External
scanner evidence can raise risk, but it does not authorize live execution.

## Stability And Public Contracts

The default v3 report remains the compatibility-stable output. The default CLI
behavior, redaction principle, no-finding limitation, decision versus
authorization separation, gate decision `execution_authorized=false`, and
surfaced limitations are stable public contract.

The evidence schema, gate decision sidecar, `--gate-summary`, human-readable
gate explanation, imported evidence adapters, sample outputs, execution
authorization artifact, and `sandbox-run` approval/report surfaces are
experimental in this version. Real-output-compatible fixture coverage and the
Docker integration CI path are also experimental and limited to documented
fixture, version, and CI scope.

See [docs/public-contracts.md](docs/public-contracts.md) and
[docs/versioning.md](docs/versioning.md).

## Security Review Status

Third-party security review is not done. Internal tests, public-safety checks,
policy validation, schema checks, and compatibility fixtures are not a
substitute for external review. Security model review is welcome; use the
public template for non-sensitive review and avoid raw sensitive data.

See [docs/security-review-needed.md](docs/security-review-needed.md) and
[docs/threat-model.md](docs/threat-model.md).

## Quick Local Checks

For local development, run the offline local verify from the repository root
with `PYTHONPATH=src`:

```bash
env PYTHONPATH=src python3 -m unittest discover -s tests -v
env PYTHONPATH=src python3 -m repo_health_doctor --version
env PYTHONPATH=src python3 -m repo_health_doctor . --fail-on block --public-safety
env PYTHONPATH=src python3 -m repo_health_doctor validate-policy .
env PYTHONPATH=src python3 -m repo_health_doctor . --public-safety --format json --output /tmp/repo-health-doctor-result.json
python3 -m json.tool /tmp/repo-health-doctor-result.json >/dev/null
```

Editable install is optional and belongs to packaging verify. It can stop in a
network-restricted environment before build-system dependencies are resolved,
so keep offline local verify as the local baseline and maintain packaging
verify in CI or another environment with build dependencies resolved.

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .
repo-health-doctor --version
repo-health-doctor . --fail-on block --public-safety
```

## Core Commands

```bash
repo-health-doctor .
repo-health-doctor . --public-safety
repo-health-doctor . --fail-on warn --public-safety
repo-health-doctor . --public-safety --format json --output /tmp/repo-health-doctor-public-safety.json
repo-health-doctor . --public-safety --format markdown --output /tmp/repo-health-doctor-public-safety.md
repo-health-doctor validate-policy .
repo-health-doctor list-allows .
repo-health-doctor list-allows . --fail-on expiring-soon
repo-health-doctor diff-reports before.json after.json
repo-health-doctor release-check .
repo-health-doctor sandbox .
repo-health-doctor sandbox-run . --approval approval.json --image python:3.12-slim --profile no-network-default --runner fake -- python3 -c "print('hello')"
```

Command details are intentionally kept in docs:

- [docs/quickstart.md](docs/quickstart.md): 5-minute demo and gate decisions
- [docs/demo-runbook.md](docs/demo-runbook.md): safe synthetic demo repos
- [docs/policy.md](docs/policy.md): policy and `validate-policy`
- [docs/ci-integration.md](docs/ci-integration.md): CI and GitHub Step Summary
- [docs/maintainer-guide.md](docs/maintainer-guide.md): maintainer workflow
- [docs/agent-guide.md](docs/agent-guide.md): agent workflow
- [docs/sandbox-run.md](docs/sandbox-run.md): experimental Docker sandbox-run add-on

## Output And Redaction

Current stable scan output uses `schema_version: 1.1` and reports:

- `PASS`: no blocking finding in the current check scope
- `WARN`: review required before relying on the result
- `BLOCK`: do not proceed until the finding or missing evidence is handled

Reports must not print raw secrets, raw scanner output, raw stdout or stderr,
host private paths, credentials, or raw policy values. Public-safety findings
are reported as neutral categories instead of raw detected values.

This compact policy JSON sample is kept in sync with the golden fixture:

```json
{
  "tool": "repo-health-doctor",
  "version": "0.1.0",
  "schema_version": "1.1",
  "repo_path": "<demo-repo>",
  "overall_status": "pass",
  "summary": {
    "pass": 1,
    "warn": 0,
    "block": 0
  },
  "checks": [
    {
      "name": "policy",
      "status": "pass",
      "summary": "Policy configuration loaded.",
      "details": {
        "findings": [],
        "policy_sources": [
          "repo"
        ],
        "ignore_path_count": 1,
        "allow_finding_count": 0
      }
    }
  ]
}
```

This text sample shows the redacted public-safety report shape:

```text
Repo Health Doctor: PASS
Target: <demo-repo>
Schema: 1.1
Summary: 12 pass, 0 warn, 0 block
Status: PASS ok, WARN review, BLOCK release blocker

Checks:
- [PASS] readme: README found.
    found: README.md

- [PASS] license: License file found.
    found: LICENSE

- [PASS] gitignore: .gitignore found.
    found: .gitignore, .git/info/exclude

- [PASS] ci: Workflow file found.
    found: .github/workflows/ci.yml

- [PASS] tests: Test directory found.
    found: tests

- [PASS] docs: Docs directory found.
    found: docs

- [PASS] scripts: Scripts directory found.
    found: scripts

- [PASS] secrets_scan: No obvious unallowed secrets detected.
    scanned_files: 6

- [PASS] large_files: No unallowed large files detected.
    threshold_bytes: 10485760

- [PASS] public_text_safety: No obvious public-facing text issues detected.
    scanned_files: 6
    scan_scope: tracked

- [PASS] tracked_artifacts: Tracked generated or environment files were not detected.
    scan_scope: tracked

- [PASS] policy: Policy configuration loaded.
    policy_sources: repo
    ignore_path_count: 1
    allow_finding_count: 0
```

Machine-readable schemas and golden samples are covered by tests.

## Relationship To Existing Tools

repo-health-doctor is an evidence normalizer and pre-execution gate. It can
consume or correlate evidence from specialized tools when policy allows it, but
it does not replace them.

## Limitations

- It cannot prove a repository is safe.
- It cannot replace dedicated secret, vulnerability, SBOM, CI/CD, EDR, or
  runtime detection tools.
- It cannot eliminate Docker, scanner-binary, observer, fixture, or version
  blind spots.
- Current stable JSON output is a check-oriented report, not the future
  evidence/gate model.
- Real-output-compatible coverage is limited to documented fixture, version,
  and adapter scope.
- Third-party security review is not done and remains external required work.

## Detailed Docs

- [docs/README.md](docs/README.md): full documentation index
- [docs/security-model.md](docs/security-model.md): redaction and safety boundary
- [docs/evaluation-model.md](docs/evaluation-model.md): tests, fixtures, and golden outputs
- [docs/public-contracts.md](docs/public-contracts.md): stable / experimental / non-contract surfaces
- [docs/security-review-needed.md](docs/security-review-needed.md): third-party review status
- [docs/compatibility-regeneration.md](docs/compatibility-regeneration.md): safe compatibility fixture regeneration
- [docs/release-notes/v0.1.0.md](docs/release-notes/v0.1.0.md): release notes
- [CHANGELOG.md](CHANGELOG.md): changelog
