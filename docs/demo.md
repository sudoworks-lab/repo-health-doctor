# Demo

This page shows the smallest offline demo flow for `repo-health-doctor`.

Run commands from the repository root:

```bash
env PYTHONPATH=src python3 -m repo_health_doctor examples/demo-no-finding-but-degraded --public-safety
env PYTHONPATH=src python3 -m repo_health_doctor validate-policy examples/demo-no-finding-but-degraded
```

The demo fixture includes a README, LICENSE, workflow, tests, docs, scripts,
and a public policy file. The first command runs the bounded public-safety
check. The second validates policy structure without scanning repository
content.

You can also save normalized output for review:

```bash
demo_out="$(mktemp -d)"
env PYTHONPATH=src python3 -m repo_health_doctor examples/demo-no-finding-but-degraded \
  --public-safety \
  --gate-summary \
  --format json \
  --output "$demo_out/rhd-demo-report.json" \
  --gate-decision-output "$demo_out/rhd-demo-gate.json"
python3 -m json.tool "$demo_out/rhd-demo-gate.json"
```

Status meanings stay simple:

- `PASS`: no blocking finding in the current scope
- `WARN`: review before relying on the result
- `BLOCK`: do not proceed until the finding or missing evidence is handled

Reports expose `schema_version`, `overall_status`, `summary`, and `checks`
without printing raw secret-like values.

For an AI-agent-shaped preflight that never executes the displayed target
command:

```bash
env PYTHONPATH=src python3 scripts/demo_agent_preflight.py examples/demo-synthetic-supply-chain -- npm install
```

The expected action is `DO NOT EXECUTE`. See
[ai-agent-preflight.md](ai-agent-preflight.md).
