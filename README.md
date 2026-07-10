# repo-health-doctor

[![CI](https://github.com/sudoworks-lab/repo-health-doctor/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/sudoworks-lab/repo-health-doctor/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-blue)
![Version](https://img.shields.io/badge/version-0.1.0-blue)

repo-health-doctor is a local-first pre-execution safety gate and evidence
normalizer for AI agents and developers reviewing unfamiliar repositories.

Run it before an AI agent, generated script, or developer runs commands from a
repository you do not trust yet.

It does not prove safety. It prevents false confidence.

Before `npm install`, `pip install`, `pytest`, `make`, or a generated command,
repo-health-doctor collects bounded evidence, normalizes native and imported
signals, surfaces limitations, and keeps gate decisions separate from execution
authorization.

## AI Agent Preflight

repo-health-doctor is built for the moment before Claude Code, Codex, Cursor,
or another AI coding agent runs a command from an unfamiliar repository. The
agent can preflight the checkout, read the gate decision, and stop before the
target command when the verdict is `BLOCK`, `QUARANTINE`, or `UNKNOWN`.

The safe demo is plan-only: it runs repo-health-doctor, displays the intended
target command, and never executes that target command.

```bash
env PYTHONPATH=src python3 scripts/demo_agent_preflight.py examples/demo-synthetic-supply-chain -- npm install
```

Expected result: the synthetic fixture reaches `QUARANTINE`, prints
`Action: DO NOT EXECUTE target command.`, and keeps
`Target command executed: false`. No global Claude Code, Codex, Cursor, MCP, or
hook configuration is changed.

See [docs/ai-agent-preflight.md](docs/ai-agent-preflight.md) for the full
safe demo and [docs/integration-claude-code.md](docs/integration-claude-code.md)
for future project-local hook integration notes.

## Why This Exists

Unfamiliar repositories often reach execution too quickly: a scanner reports no
findings, an observer is missing, evidence is not bound to the reviewed commit,
or an AI agent treats a review note as permission to continue.

repo-health-doctor exists to stop those shortcuts. Its job is to make the
review state explicit before host commands run:

- no finding is not proof that the repository is safe
- missing, degraded, or unbound evidence is not `PASS`
- a gate decision is not execution authorization
- `execution_authorized=false` is the default gate posture

## When To Use It

Use repo-health-doctor when you want a small, reviewable gate before touching a
repository you do not fully trust:

- maintainers reviewing AI-generated or external repository changes
- developers doing a first pass over an unfamiliar local checkout
- coding agents that need a fail-closed pre-execution check
- CI workflows that need redacted PASS / WARN / BLOCK reports

## What It Does

- Runs local-first checks and emits redacted text, Markdown, or JSON reports.
- Normalizes bounded evidence from native checks and imported scanner outputs.
- Provides real scanner adapters for local Gitleaks, OSV-Scanner, and Trivy
  binaries when explicitly invoked through the adapter layer.
- Records limitations as gate inputs instead of burying them as notes.
- Treats scanner failure, parse failure, unsupported versions, missing evidence,
  degraded observers, and commit mismatches as review-relevant conditions.
- Keeps gate decisions and execution authorization as separate artifacts.

Gitleaks, OSV-Scanner, Trivy, zizmor-style, and similar integrations are
external evidence paths. repo-health-doctor does not replace those tools and
does not claim their silence means a repository is safe.

## Real Scanner Suite

repo-health-doctor now has real scanner adapters for Gitleaks, OSV-Scanner,
and Trivy. The adapters do not reimplement mature scanners. They invoke a
locally available scanner binary only when the adapter layer is explicitly
called, parse its JSON report from a temporary file, normalize a minimal
redacted evidence summary, and pass that evidence into the same fail-closed
external scanner contract.

Scanner unavailable is fail-closed, not PASS. Unsupported versions, timeouts,
missing reports, invalid JSON, schema mismatches, and exit-code/report
contradictions become unknown or quarantine-oriented evidence instead of risk
lowering. No findings is not proof of safety; it means only that the scanner
did not report findings in the scope, version, configuration, database, and
coverage reached by that run.

Raw scanner report JSON, raw stdout, raw stderr, raw secret matches, code
snippets, advisory raw objects, and host absolute paths are not persisted in
normalized evidence. Gitleaks runs as a local static no-network adapter.
OSV-Scanner can query OSV.dev, and Trivy can download or update database/cache
state, so their network, cache, and privacy limitations are surfaced instead
of hidden as local-only behavior.

The default `repo-health-doctor .` CLI path still does not install scanners,
download scanners, run live scanners, contact scanner APIs, or authorize
execution. Real scanner execution is an explicit adapter/API surface in this
version; a dedicated CLI suite command is future product scope.

See [docs/real-scanner-suite.md](docs/real-scanner-suite.md),
[docs/real-gitleaks-compatibility.md](docs/real-gitleaks-compatibility.md),
[docs/real-osv-compatibility.md](docs/real-osv-compatibility.md), and
[docs/real-trivy-compatibility.md](docs/real-trivy-compatibility.md).

## Field Research Safety Protocol

Before using repo-health-doctor evidence in any write-up about a real
suspicious tool or repository, follow
[docs/field-research-safety-protocol.md](docs/field-research-safety-protocol.md).
The protocol keeps C-phase research non-executing, redacted, human-reviewed,
and non-accusatory. It treats repo-health-doctor output as observed evidence,
not proof of safety and not a maliciousness verdict.

The C-phase reporting workflow is docs-only in this release:
[field report template](docs/field-report-template.md),
[synthetic example report](docs/examples/synthetic-field-report.md),
[private candidate workflow](docs/private-candidate-review-workflow.md), and
[publication review checklist](docs/publication-review-checklist.md). These
documents do not collect targets, name real subjects, publish findings, or run
commands.

## Install

After the package is published, the intended user install path is:

```bash
pipx install repo-health-doctor
repo-health-doctor --help
```

For one-off runs after publication:

```bash
uvx repo-health-doctor --help
```

The project currently has no runtime package dependencies (`dependencies = []`
in `pyproject.toml`). Packaging/build tools are still needed to build or install
from source.

## What It Does Not Do

repo-health-doctor is not:

- a safety proof
- a replacement for security review or dedicated scanners
- a complete malware sandbox
- a claim of Docker-enforced safety for repository-derived code
- permission to run repository-derived commands

Third-party security review has not been performed.

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

The synthetic supply-chain demo is a fixture, not malware and not proof of a
real-world scanner finding. The current experimental static shape detector now
looks for the same general family in arbitrary repo names: package lifecycle
hooks, Python build-hook candidates, environment enumeration, credential-path
references, outbound network target shape, workflow write-risk, and obfuscated
eval candidates. A single axis starts as review evidence; multiple axes can
recommend quarantine. These signals are still gate inputs, not a safety proof.

`--gate-summary` is opt-in and intended as a human-readable demo / review aid.
It does not change the default v3 report contract. The gate decision sidecar,
human-readable explanation, and contextual wording are experimental. Even
`allow_limited` is not a safety proof or unrestricted execution permission.

More detail is in [docs/quickstart.md](docs/quickstart.md) and
[docs/demo-runbook.md](docs/demo-runbook.md).

## Sandbox-Run V1 Core Runtime

`sandbox-run` is repo-health-doctor's core execution backend for
AI-agent-oriented unknown-repository work. It runs one explicit argv in a
locked-down Docker profile, using a disposable workspace copy, and emits
bounded redacted execution evidence. It is not a complete malware sandbox, not
a safety proof, and not unrestricted execution authorization.

```bash
env PYTHONPATH=src python3 -m repo_health_doctor sandbox-run examples/demo-synthetic-supply-chain \
  --dry-run \
  --profile locked-down \
  --format json \
  --evidence-output /tmp/rhd-sandbox-run.json \
  -- python3 -c "print('hello from sandbox')"
```

For `sandbox-run`, `--output` writes the machine-readable JSON report. Stdout
uses `--format`, so you can keep the terminal summary human-readable while
writing JSON to the report path.

Real Docker mode omits `--dry-run`. It never pulls images automatically; the
image must already exist locally and Docker uses `--pull=never`. A successful
sandbox-run is bounded execution evidence only:

- successful execution does not mean safe
- successful execution does not mean authorization to continue
- Docker does not provide complete malware containment
- host HOME, credentials, SSH agent, and Docker socket are not mounted by the
  locked-down profile

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

## Stability And Public Contracts

The default v3 report remains the compatibility-stable output. The default CLI
behavior, redaction principle, no-finding limitation, decision versus
authorization separation, gate decision `execution_authorized=false`, and
surfaced limitations are stable public contract.

The evidence schema, gate decision sidecar, `--gate-summary`, human-readable
gate explanation, imported evidence adapters, real scanner adapters, sample
outputs, and execution authorization artifact are experimental in this version.
`sandbox-run` is the v1 core execution runtime, while its JSON schema and
wording remain draft contract surfaces in the v0.x series. `--fail-on-gate`,
`gate-check`, and the static supply-chain shape detector are also experimental.
Real-output-compatible fixture coverage and the Docker integration CI path are
also experimental and limited to documented fixture, version, and CI scope.

See [docs/public-contracts.md](docs/public-contracts.md) and
[docs/versioning.md](docs/versioning.md).

## Security Review Status

Third-party security review is not done. Internal tests, public-safety checks,
policy validation, schema checks, and compatibility fixtures are not a
substitute for external review. Security model review is welcome; use the
public template for non-sensitive review and avoid raw sensitive data.

See [docs/security-review-needed.md](docs/security-review-needed.md),
[docs/threat-model.md](docs/threat-model.md), and the
[security model review issue template](.github/ISSUE_TEMPLATE/security-model-review.yml).

## Dogfooding

CI includes a self-scan job that runs repo-health-doctor against this repository
with `--public-safety` and `--fail-on-gate quarantine`. This is trust evidence,
not proof of safety: it checks that the repo can pass its own quarantine/block
gate while keeping warnings visible for review.

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
repo-health-doctor . --public-safety --fail-on-gate quarantine
repo-health-doctor gate-check . --authorization authorization.json --argv-json argv.json
repo-health-doctor . --public-safety --format json --output /tmp/repo-health-doctor-public-safety.json
repo-health-doctor . --public-safety --format markdown --output /tmp/repo-health-doctor-public-safety.md
repo-health-doctor validate-policy .
repo-health-doctor list-allows .
repo-health-doctor list-allows . --fail-on expiring-soon
repo-health-doctor diff-reports before.json after.json
repo-health-doctor release-check .
repo-health-doctor sandbox .
repo-health-doctor sandbox-run . --profile locked-down --dry-run -- python3 -c "print('hello')"
```

Command details are intentionally kept in docs:

- [docs/quickstart.md](docs/quickstart.md): 5-minute demo and gate decisions
- [docs/demo-runbook.md](docs/demo-runbook.md): safe synthetic demo repos
- [docs/policy.md](docs/policy.md): policy and `validate-policy`
- [docs/ci-integration.md](docs/ci-integration.md): CI and GitHub Step Summary
- [docs/maintainer-guide.md](docs/maintainer-guide.md): maintainer workflow
- [docs/agent-development-guide.md](docs/agent-development-guide.md): agent workflow for this repo
- [docs/integration-claude-code.md](docs/integration-claude-code.md): Claude Code pre-execution gate integration
- [docs/sandbox-run.md](docs/sandbox-run.md): Docker sandbox-run v1 core runtime

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
- [docs/ai-agent-preflight.md](docs/ai-agent-preflight.md): plan-only AI agent preflight demo
- [docs/field-research-safety-protocol.md](docs/field-research-safety-protocol.md): C-0 safety protocol for future field research and publication review
- [docs/field-report-template.md](docs/field-report-template.md): C-1 synthetic field report template
- [docs/examples/synthetic-field-report.md](docs/examples/synthetic-field-report.md): C-2 internal-only synthetic field report example
- [docs/private-candidate-review-workflow.md](docs/private-candidate-review-workflow.md): C-3 private candidate review workflow
- [docs/publication-review-checklist.md](docs/publication-review-checklist.md): C-4 publication gate and public write-up checklist
- [docs/security-model.md](docs/security-model.md): redaction and safety boundary
- [docs/evaluation-model.md](docs/evaluation-model.md): tests, fixtures, and golden outputs
- [docs/public-contracts.md](docs/public-contracts.md): stable / experimental / non-contract surfaces
- [docs/real-scanner-suite.md](docs/real-scanner-suite.md): real Gitleaks / OSV-Scanner / Trivy adapter suite
- [docs/real-gitleaks-compatibility.md](docs/real-gitleaks-compatibility.md): real Gitleaks adapter boundary
- [docs/real-osv-compatibility.md](docs/real-osv-compatibility.md): real OSV-Scanner adapter boundary
- [docs/real-trivy-compatibility.md](docs/real-trivy-compatibility.md): real Trivy adapter boundary
- [docs/integration-claude-code.md](docs/integration-claude-code.md): Claude Code hook integration
- [docs/agent-development-guide.md](docs/agent-development-guide.md): agent workflow for this repo
- [docs/security-review-needed.md](docs/security-review-needed.md): third-party review status
- [docs/compatibility-regeneration.md](docs/compatibility-regeneration.md): safe compatibility fixture regeneration
- [docs/release-notes/v0.1.0.md](docs/release-notes/v0.1.0.md): release notes
- [CHANGELOG.md](CHANGELOG.md): changelog
