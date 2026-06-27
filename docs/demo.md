# Demo

This page shows the smallest offline demo flow for `repo-health-doctor`.

Run commands from the repository root:

```bash
PYTHONPATH=src python3 -m repo_health_doctor /tmp/repo-health-doctor-demo --public-safety
PYTHONPATH=src python3 -m repo_health_doctor validate-policy /tmp/repo-health-doctor-demo
```

The demo fixture includes a README, LICENSE, workflow, tests, docs, scripts,
and a public policy file. The first command runs the bounded public-safety
check. The second validates policy structure without scanning repository
content.

You can also save normalized output for review:

```bash
PYTHONPATH=src python3 -m repo_health_doctor /tmp/repo-health-doctor-demo --public-safety --format json --output /tmp/repo-health-doctor-demo.json
python3 -m json.tool /tmp/repo-health-doctor-demo.json
```

Status meanings stay simple:

- `PASS`: no blocking finding in the current scope
- `WARN`: review before relying on the result
- `BLOCK`: do not proceed until the finding or missing evidence is handled

Reports expose `schema_version`, `overall_status`, `summary`, and `checks`
without printing raw secret-like values.
