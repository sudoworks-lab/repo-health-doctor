# AI Agent Preflight

repo-health-doctor can sit in front of Claude Code, Codex, Cursor, or another
AI coding agent as a pre-execution safety gate. The operating rule is simple:
before the agent runs a repository-derived command in an unfamiliar checkout,
run repo-health-doctor first. If the gate decision is `BLOCK`, `QUARANTINE`, or
`UNKNOWN`, do not run the target command.

This guide starts with a plan-only demo. It does not edit Claude Code, Codex,
Cursor, MCP, or global hook configuration. It does not run the target command.
It only shows the command the agent wanted to run, runs repo-health-doctor
against the repository, and prints the decision.

## Safe Demo

From a repo-health-doctor checkout:

```bash
env PYTHONPATH=src python3 scripts/demo_agent_preflight.py examples/demo-synthetic-supply-chain -- npm install
```

The `npm install` argv is display-only. The demo script never executes it. The
expected lesson is:

```text
Gate decision: QUARANTINE
Execution authorized: false
Action: DO NOT EXECUTE target command.
Target command executed: false
```

You can also run the degraded no-finding fixture:

```bash
env PYTHONPATH=src python3 scripts/demo_agent_preflight.py examples/demo-no-finding-but-degraded -- npm test
```

That fixture shows that clean static checks and no scanner finding are still
not proof of safety when runtime or observer evidence is missing or degraded.

## Decision Policy

- `BLOCK`: do not run the target command.
- `QUARANTINE`: do not run the target command on the host.
- `UNKNOWN`: do not treat missing evidence as confidence.
- `WARN`: do not auto-run. Review limitations and require explicit human
  authorization before any execution path.
- `ALLOW_LIMITED`: still not a safety proof and still not unrestricted
  execution authorization.

The demo script uses repo-health-doctor's existing gate decision path:

```bash
repo-health-doctor <repo> --public-safety --gate-summary --gate-decision-output <temp-gate-json>
```

It stores sidecars in a temporary directory and discards them when the process
exits. It does not persist raw scanner reports, raw stdout, or raw stderr.

## What This Does Not Do

- It does not change global agent configuration.
- It does not install, download, or upgrade Gitleaks, OSV-Scanner, Trivy, or
  any package manager dependency.
- It does not run the target command.
- It does not modify Claude Code, Codex, Cursor, MCP, or hook settings.
- It does not create execution authorization.
- It does not prove the repository is safe.

Real hook integration is future scope. A project may later wire this decision
into Claude Code `PreToolUse`, a Codex wrapper, Cursor automation, or another
agent-specific control point, but that should be a separate reviewed change.

## Evidence Limits

No findings is not proof of safety. Scanner unavailable is not PASS. No
evidence is not PASS. A gate decision is a review result, not permission to run
repository-derived commands.

The real scanner suite can explicitly invoke mature tools and normalize their
JSON into redacted external scanner evidence:

- Gitleaks for secret detection evidence.
- OSV-Scanner for dependency vulnerability evidence.
- Trivy for filesystem vulnerability and misconfiguration evidence.

Those adapters are explicit adapter/API surfaces. The default preflight demo
does not run them. OSV-Scanner live scans can query OSV.dev. Trivy live scans
can use database and cache state. These network, cache, and privacy limitations
remain gate inputs rather than hidden assumptions.

## Relationship To Other Commands

- `repo-health-doctor . --public-safety --gate-summary` is the minimal manual
  preflight view.
- `repo-health-doctor . --public-safety --fail-on-gate quarantine` is useful
  for a wrapper that should exit `2` on `QUARANTINE` or `BLOCK`.
- `gate-check` adds explicit authorization validation for an exact argv, but
  it needs local authorization and argv JSON files.
- `sandbox-run --dry-run` shows sandbox-run evidence shape without invoking
  Docker.
- real `sandbox-run` is for the later point where reviewed, exact, authorized
  execution evidence is needed under a locked-down disposable workspace.

Start with the plan-only demo before changing hooks or wrappers.
