# Demo Runbook

The demos are safe synthetic repositories under `examples/`. They are designed
to show gate behavior without real credentials, personal information, host
paths, malware, raw scanner output, scanner installation, or network access.

## Demo A: No Finding But Degraded

Purpose:

```text
Multiple clean checks can still be insufficient when runtime visibility is
missing or degraded.
```

Run:

```bash
env PYTHONPATH=src python3 -m repo_health_doctor examples/demo-no-finding-but-degraded \
  --public-safety \
  --gate-summary \
  --format json \
  --output /tmp/rhd-demo-no-finding.v3.json \
  --gate-decision-output /tmp/rhd-demo-no-finding.gate.json
python3 -m json.tool /tmp/rhd-demo-no-finding.v3.json
python3 -m json.tool /tmp/rhd-demo-no-finding.gate.json
python3 -m json.tool docs/sample-outputs/demo-no-finding-but-degraded.gate-decision.json
```

Expected lesson:

- v3 native checks can be clean in the current scope.
- the opt-in terminal summary separates static health from the gate decision.
- no finding is not proof of safety.
- missing or degraded observer evidence prevents an execution green light.
- the gate decision is not `allow_limited`.
- `execution_authorized=false`.

## Demo B: Synthetic Supply-Chain Chain

Purpose:

```text
A postinstall script, environment enumeration shape, redacted credential path
reference, workflow write-risk shape, example.invalid outbound target, and
obfuscated eval candidate can combine into quarantine evidence.
```

Run:

```bash
env PYTHONPATH=src python3 -m repo_health_doctor examples/demo-synthetic-supply-chain \
  --public-safety \
  --gate-summary \
  --format json \
  --output /tmp/rhd-demo-supply-chain.v3.json \
  --gate-decision-output /tmp/rhd-demo-supply-chain.gate.json
python3 -m json.tool /tmp/rhd-demo-supply-chain.v3.json
python3 -m json.tool /tmp/rhd-demo-supply-chain.gate.json
python3 -m json.tool docs/sample-outputs/demo-synthetic-supply-chain.gate-decision.json
```

Expected lesson:

- the synthetic repository contains no real malware.
- static health can show `PASS` while the gate summary still withholds an
  execution green light.
- the gate summary names concrete safe fixture signals: postinstall,
  credential/environment access shape, outbound target string, workflow
  write-risk, and eval-like candidate.
- static shape can still justify `quarantine`.
- missing, degraded, or unbound evidence prevents execution authorization.
- local execution should remain blocked unless a human chooses stronger
  isolation.
- `execution_authorized=false`.

`--gate-summary` is opt-in and prints a human-readable demo / review aid. It
does not change the default v3 report. The gate decision sidecar, its
human-readable `explanation`, contextual wording, and the curated sample
outputs remain experimental.

## Optional Demo C: Sandbox-Run Smoke

Purpose:

```text
Show the experimental approval-bound sandbox-run report shape without treating
the result as a safety proof.
```

Fake-runner smoke, no Docker daemon required:

```bash
env PYTHONPATH=src python3 -m repo_health_doctor sandbox-run examples/demo-synthetic-supply-chain \
  --approval examples/approvals/demo-sandbox-run-approval.json \
  --image python:3.12-slim \
  --profile no-network-default \
  --runner fake \
  --output /tmp/rhd-sandbox-run.json \
  -- python3 -c "print('hello from sandbox')"
python3 -m json.tool /tmp/rhd-sandbox-run.json
```

Expected lesson:

- the approval binds exact argv, target fingerprint, image, profile, network
  mode, timeout, and resource limits.
- `--output` writes machine-readable JSON; stdout remains human-readable unless
  `--format json` or `--format markdown` is selected.
- fake runner mode is for tests and docs only and does not invoke Docker.
- real Docker mode omits `--runner fake`, uses `--pull=never`, and blocks when
  the approved image is not already available locally.
- a completed sandbox-run is bounded execution evidence only.
- a completed sandbox-run is not proof of safety and not unrestricted execution
  authorization.

## Safety Checks

The demo examples and sample outputs are covered by tests:

```bash
env PYTHONPATH=src python3 -m unittest tests.test_demo_examples -v
env PYTHONPATH=src python3 -m unittest tests.test_quickstart_sample_outputs -v
```

These tests parse sample JSON, validate gate decision samples, and check for
forbidden leak patterns in the new demo and sample output files.
