# Quickstart

This quickstart is for a local checkout. It uses `PYTHONPATH=src` and does not
install host scanners, run host scanners, contact remote APIs, or authorize
execution.

Use it before an AI agent or developer runs commands from an unfamiliar
repository. The quickstart demonstrates the core gate / evidence normalizer,
not a scanner replacement and not a safety proof.

## Install Assumption

For local development, run commands from the repository root:

```bash
env PYTHONPATH=src python3 -m repo_health_doctor --help
env PYTHONPATH=src python3 -m repo_health_doctor --version
```

Editable install is optional and depends on the local packaging environment.

## 5-Minute Demo

Run the no-finding-but-degraded demo. The v3 report can be `pass`, but that
does not prove runtime safety. The opt-in `--gate-summary` terminal output is
the human readout; it explains that no finding plus missing or degraded
observer evidence is not an execution green light. The JSON sidecar is
available when you want details.

```bash
env PYTHONPATH=src python3 -m repo_health_doctor examples/demo-no-finding-but-degraded \
  --public-safety \
  --gate-summary \
  --format json \
  --output /tmp/rhd-demo-no-finding.v3.json \
  --gate-decision-output /tmp/rhd-demo-no-finding.gate.json
python3 -m json.tool /tmp/rhd-demo-no-finding.gate.json
```

Then inspect the curated sample that records the intended degraded-observer
lesson:

```bash
python3 -m json.tool docs/sample-outputs/demo-no-finding-but-degraded.gate-decision.json
```

Run the synthetic supply-chain repository:

```bash
env PYTHONPATH=src python3 -m repo_health_doctor examples/demo-synthetic-supply-chain \
  --public-safety \
  --gate-summary \
  --format json \
  --output /tmp/rhd-demo-supply-chain.v3.json \
  --gate-decision-output /tmp/rhd-demo-supply-chain.gate.json
python3 -m json.tool /tmp/rhd-demo-supply-chain.gate.json
```

The terminal summary separates `Static health: PASS` from the gate decision and
prints `Execution authorized: false`. The no-finding demo remains a warning
because observer evidence is missing or degraded. The synthetic supply-chain
demo is expected to reach `quarantine` and name concrete safe fixture signals
such as the postinstall hook, credential/environment pattern, outbound target
string, workflow write-risk, and eval-like candidate. Both keep
`execution_authorized=false`.

To make a hook or CI job block on gate decisions, use the experimental
`--fail-on-gate` contract. This exits `2` when the selected gate threshold is
met:

```bash
env PYTHONPATH=src python3 -m repo_health_doctor examples/demo-synthetic-supply-chain \
  --public-safety \
  --fail-on-gate quarantine
```

## Reading Gate Decisions

- `verdict` is the review outcome: `allow_limited`, `warn`, `quarantine`,
  `block`, or `unknown`.
- `execution_authorized=false` means the decision is not permission to run
  repository-derived commands.
- `explanation` is the human-readable demo / review text.
- `required_actions` are the next review steps.
- `limitations` are inputs to the gate. They are not decorative notes.
- `residual_risks` record what remains uncertain.

`allow_limited` is not a safety proof and is not unrestricted execution
authorization. No scanner finding is not proof of safety. `PASS` in the current
v3 report means no blocking finding in the current check scope only. Gate
decisions keep `execution_authorized=false` by design.

The default v3 report remains the compatibility-stable output. The evidence
schema, gate decision sidecar, `--gate-summary`, human-readable gate
explanation, contextual wording, `--fail-on-gate`, `gate-check`, imported
evidence adapters, sample outputs, and execution authorization artifact are
experimental in this version. `sandbox-run` is the v1 core execution runtime,
while its schema and wording remain draft contract surfaces in the v0.x series.
Real-output-compatible fixture coverage and the Docker integration CI path are
also experimental and limited to documented scope. Stability details are in
[public-contracts.md](public-contracts.md).

## Sandbox-Run Smoke

After reviewing the gate output, you can inspect sandbox-run evidence without
invoking Docker by using `--dry-run`. This is a documentation and test smoke
path, not real Docker execution evidence:

```bash
env PYTHONPATH=src python3 -m repo_health_doctor sandbox-run examples/demo-synthetic-supply-chain \
  --dry-run \
  --profile locked-down \
  --evidence-output /tmp/rhd-sandbox-run.json \
  -- python3 -c "print('hello from sandbox')"
python3 -m json.tool /tmp/rhd-sandbox-run.json
```

`--evidence-output` writes the machine-readable JSON report while stdout stays
human-readable by default. Real Docker mode omits `--dry-run`, uses
`--pull=never`, does not pull images, requires the image to exist locally, and
still does not prove safety or grant unrestricted execution authorization.
Successful sandbox execution does not mean safe, and does not mean
authorization to continue. See [sandbox-run.md](sandbox-run.md).

## Sample Outputs

Sample outputs live in [sample-outputs](sample-outputs/):

- `demo-no-finding-but-degraded.v3.json`
- `demo-no-finding-but-degraded.gate-decision.json`
- `demo-synthetic-supply-chain.v3.json`
- `demo-synthetic-supply-chain.gate-decision.json`
- `gate-check-blocked.txt`
- `gitleaks-imported-evidence.gate-decision.json`
- `osv-imported-evidence.gate-decision.json`

## External Tool Adapters

The Gitleaks, OSV-Scanner, and Trivy real adapters normalize scanner JSON into
repo-health-doctor external scanner evidence when explicitly invoked through
the adapter/API surface. They are evidence paths, not scanner replacements, and
they never authorize execution. The default quickstart commands still do not
execute host scanners, manage vulnerability databases, or contact scanner APIs.

Scanner unavailable is fail-closed, not PASS. No findings is not proof of
safety. OSV-Scanner and Trivy live scans can use network, database, and cache
state, so their privacy and freshness limitations are surfaced in evidence
instead of hidden as local-only behavior.

Real-output-compatible redacted fixtures and adapter limits are documented in
[real-scanner-suite.md](real-scanner-suite.md),
[real-gitleaks-compatibility.md](real-gitleaks-compatibility.md),
[real-osv-compatibility.md](real-osv-compatibility.md), and
[real-trivy-compatibility.md](real-trivy-compatibility.md).
