# Claude Code Integration

This guide is for using repo-health-doctor as a pre-execution gate in an
external project. It is not the development workflow for this repository; see
[agent-development-guide.md](agent-development-guide.md) for that.

repo-health-doctor does not authorize execution by itself. A gate decision says
what the current evidence supports. A separate execution authorization artifact
is required before running repository-derived commands.

## Claude Code Hook Contract

Claude Code hook behavior is documented in Anthropic's
[hooks reference](https://docs.anthropic.com/en/docs/claude-code/hooks) and
[hooks guide](https://docs.anthropic.com/en/docs/claude-code/hooks-guide).
For `PreToolUse`, exit `2` blocks the tool call and stderr is fed back to
Claude. Exit `1` is not a reliable block for most hook events; treat it as a
foot-gun for policy enforcement.

## Minimal PreToolUse Gate

Example `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "bash .claude/hooks/repo-health-gate.sh"
          }
        ]
      }
    ]
  }
}
```

Example `.claude/hooks/repo-health-gate.sh`:

```bash
#!/usr/bin/env bash
set -u

tmp_stderr="$(mktemp)"
repo-health-doctor "$PWD" --public-safety --fail-on-gate quarantine \
  >/dev/null 2>"$tmp_stderr"
status=$?

if [ "$status" -eq 0 ]; then
  rm -f "$tmp_stderr"
  exit 0
fi

if [ "$status" -eq 2 ]; then
  cat "$tmp_stderr" >&2
else
  echo "repo-health-doctor pre-execution gate did not pass; review locally before running repository commands." >&2
fi

rm -f "$tmp_stderr"
exit 2
```

The wrapper intentionally does not print the Claude Code tool input, command
body, environment values, or local file paths. It maps any non-zero
repo-health-doctor result to exit `2` so the hook blocks instead of becoming a
non-blocking exit `1` error.

## Gate-Check With Authorization

`gate-check` combines gate generation and authorization validation. It exits
`2` unless a valid authorization artifact is supplied and the selected gate
threshold allows the verdict.

```bash
repo-health-doctor gate-check "$PWD" \
  --fail-on-gate quarantine \
  --authorization .repo-health-doctor.local/authorization.json \
  --argv-json .repo-health-doctor.local/argv.json
```

Current limitation: `gate-check` does not auto-discover authorization artifacts.
Pass explicit local-only paths and do not commit those files.

## Flow

```text
repository checkout
  -> repo-health-doctor gate decision
  -> human reviews evidence and writes authorization artifact
  -> repo-health-doctor authorization validate or gate-check
  -> sandbox-run executes the exact argv in a locked-down disposable workspace
     when policy allows it
```

## Handling Decisions

- `BLOCK`: do not run the command. Fix the blocking evidence or redaction issue
  first.
- `QUARANTINE`: do not run locally. Use a dedicated VM or stronger isolation if
  execution is still necessary.
- `UNKNOWN`: do not treat missing evidence as confidence. Collect or review the
  missing evidence.
- `WARN`: review limitations and require explicit authorization before
  execution.
- `ALLOW_LIMITED`: still not a safety proof. Run only the exact reviewed command
  and scope after authorization validation succeeds.

## CLAUDE.md Or AGENTS.md Rule Example

```markdown
Before running repository-derived Bash commands, run:

repo-health-doctor . --public-safety --fail-on-gate quarantine

If it exits 2, stop and follow the redacted stderr next actions. Do not paste
secrets, command bodies, local paths, or environment values into logs or chat.
A gate decision is not execution authorization; validate an explicit
authorization artifact for the exact argv before running commands.
```

## Sandbox-Run Execution

When an agent needs execution evidence after the gate step, use `sandbox-run`
instead of running the repository-derived command on the host:

```bash
repo-health-doctor sandbox-run "$PWD" \
  --profile locked-down \
  --fail-on-gate quarantine \
  --authorization .repo-health-doctor.local/authorization.json \
  --evidence-output /tmp/repo-health-doctor-sandbox-run.json \
  -- python -m pytest
```

The sandbox-run policy block exit is `2` and uses stderr prefix
`SANDBOX-RUN POLICY BLOCK`. If the command itself exits `2`, stderr uses
`SANDBOX-RUN COMMAND EXIT` and the evidence has `command_started=true`.

See [sample-outputs/gate-check-blocked.txt](sample-outputs/gate-check-blocked.txt)
for a redacted blocked-hook style message.
