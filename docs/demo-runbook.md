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

## Demo B: Synthetic Supply-Chain Shape

Purpose:

```text
A postinstall script, environment enumeration shape, redacted credential path
reference, workflow write-risk shape, outbound target shape, and obfuscated
eval candidate can combine into quarantine evidence.
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
- the demo is a fixture; the current detector looks for the general static
  shape family in arbitrary repo names and does not depend on the demo repo
  name.
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

## Demo C: Sandbox-Run Smoke

Purpose:

```text
Show the sandbox-run v1 evidence shape without treating the result as a safety proof.
```

Dry-run smoke, no Docker invocation:

```bash
env PYTHONPATH=src python3 -m repo_health_doctor sandbox-run examples/demo-synthetic-supply-chain \
  --dry-run \
  --profile locked-down \
  --evidence-output /tmp/rhd-sandbox-run.json \
  -- python3 -c "print('hello from sandbox')"
python3 -m json.tool /tmp/rhd-sandbox-run.json
```

Expected lesson:

- `--evidence-output` writes machine-readable JSON; stdout remains
  human-readable unless `--format json` or `--format markdown` is selected.
- dry-run and fake runner modes are for tests and docs only and do not replace
  real Docker verification.
- real Docker mode omits `--dry-run`, uses `--pull=never`, and blocks when the
  image is not already available locally.
- a successful sandbox-run is bounded execution evidence only.
- successful execution does not mean safe.
- successful execution does not mean authorization to continue.

## Safety Checks

The demo examples and sample outputs are covered by tests:

```bash
env PYTHONPATH=src python3 -m unittest tests.test_demo_examples -v
env PYTHONPATH=src python3 -m unittest tests.test_quickstart_sample_outputs -v
```

These tests parse sample JSON, validate gate decision samples, and check for
forbidden leak patterns in the new demo and sample output files.

## Demo D: AI Agent Preflight

Purpose:

```text
Show the moment before an AI agent runs an unknown-repository command, while
keeping the target command display-only and unexecuted.
```

Plan-only preflight:

```bash
env PYTHONPATH=src python3 scripts/demo_agent_preflight.py examples/demo-synthetic-supply-chain -- npm install
```

Expected lesson:

- the intended target command is printed as display-only.
- the target command is not executed.
- global Claude Code, Codex, Cursor, MCP, and hook configuration are not
  changed.
- `QUARANTINE`, `BLOCK`, or `UNKNOWN` means do not execute.
- no findings is not proof of safety.
- scanner unavailable or no evidence is not PASS.
- a gate decision is not execution authorization.

See [ai-agent-preflight.md](ai-agent-preflight.md) for the full guide.
