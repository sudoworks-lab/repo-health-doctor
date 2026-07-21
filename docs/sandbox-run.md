# Sandbox-Run V1 Core Runtime

`sandbox-run` is repo-health-doctor's core execution backend for
AI-agent-oriented unknown-repository work. It exists for the point after review
has decided that one bounded command should run, but should not run directly on
the host.

It provides practical strong isolation, disposable execution, default-deny
networking, redacted evidence capture, and gate / authorization binding. It is
not a proof of safety, not complete malware containment, and not unrestricted
execution authorization.

## Purpose

The v1 flow is:

1. Run the pre-execution gate.
2. Review the gate decision, limitations, and required actions.
3. If bounded execution evidence is still needed, run exactly one command with
   `sandbox-run`.
4. Keep the original repository unchanged.
5. Use the JSON evidence to decide the next review step.

The command is passed as argv. sandbox-run does not silently convert it to a
shell string. If a shell is required, the caller must explicitly pass it as the
command, for example `sh -c "..."`.

## CLI Usage

Dry-run evidence without invoking Docker:

```bash
env PYTHONPATH=src python3 -m repo_health_doctor sandbox-run tests/fixtures/demo-repo \
  --dry-run \
  --profile locked-down \
  --evidence-output /tmp/rhd-sandbox-run-dry.json \
  -- python -c "print('hello')"
python3 -m json.tool /tmp/rhd-sandbox-run-dry.json
```

Real Docker execution:

```bash
env PYTHONPATH=src python3 -m repo_health_doctor sandbox-run tests/fixtures/demo-repo \
  --profile locked-down \
  --fail-on-gate unknown \
  --image python@sha256:<64-lowercase-hex> \
  --authorization /tmp/rhd-human-authorization.json \
  --evidence-output /tmp/rhd-sandbox-run.json \
  -- python -c "print('authorized bounded probe')"
python3 -m json.tool /tmp/rhd-sandbox-run.json
```

Non-dry-run Docker execution requires a valid Human-controlled authorization.
The authorization binds the gate decision, threshold, exact argv, digest image
reference and local image ID, policy, expiry, repository commit and tree hash,
dirty state, worktree, and single-use reservation. Missing or invalid
authorization, including a legacy `--approval` artifact by itself, blocks
before Docker is invoked. `--dry-run` does not invoke Docker and may be used
without authorization.

Gate-bound execution:

```bash
env PYTHONPATH=src python3 -m repo_health_doctor sandbox-run examples/demo-synthetic-supply-chain \
  --profile locked-down \
  --fail-on-gate quarantine \
  --evidence-output /tmp/rhd-sandbox-run-block.json \
  -- python -c "print('will not start when gate blocks')"
```

`--output` and `--evidence-output` both write the machine-readable JSON report.
Use one of them. Stdout still follows `--format`.

## Locked-Down Profile

`locked-down` is the v1 default profile.

It generates Docker argv with:

- `--pull=never`
- `--network none`
- a local digest-pinned image in the form `name@sha256:<64 lowercase hex>`
- `/workspace` as the working directory
- a disposable repository copy mounted read-only at `/workspace`
- `/out` as a kernel-bounded 64 MiB, 4096-inode tmpfs; it is not a host bind
- read-only container root filesystem
- `/tmp` tmpfs
- `--cap-drop ALL`
- `--security-opt no-new-privileges`
- non-root numeric `uid:gid`
- memory, CPU, and PID limits
- fake `HOME=/tmp/home`
- minimal injected env keys only

It does not mount the original repository, host HOME, host credentials, SSH
agent, or Docker socket. It does not use privileged mode, host network, host
PID, host IPC, or capability additions.

## Image Policy

sandbox-run never pulls images automatically. Docker is invoked with
`--pull=never`, so the image must already exist locally. The default
`python:3.12-slim` reference is retained for dry-run and fake-runner
documentation compatibility only. Real Docker execution accepts only a strict
digest-pinned reference and binds it to the local image ID; mutable tags,
missing or malformed digests, option-like values, whitespace, and control
characters are rejected.

## Workspace Copy Policy

sandbox-run never runs inside the real repository. It creates a disposable run
root, copies allowed repository files into `/workspace`, runs the command
there, captures a diff summary, and then removes the run root unless
`--preserve-workspace` is explicitly set.

The copy policy excludes `.git`, `.env`, `.env.*`, credential directories,
shell history, common caches, dependency trees, virtual environments, build
outputs, coverage artifacts, OS metadata, and local IDE metadata. Symlinks are
not followed. Unsafe symlinks, path traversal attempts, and unsupported
filesystem entries such as FIFOs, sockets, and device files are not copied and
are recorded in evidence.

The copy has a budget:

- maximum file count
- maximum total copied bytes
- maximum single-file bytes

If the budget is exceeded, sandbox-run does not start the command. It records
`copy_budget_exceeded`, sets `policy_blocked=true`, keeps
`command_started=false`, and exits `2`.

The real runtime does not provide a host-backed writable path to the command:
`/workspace` is read-only and `/out` is a 64 MiB, 4096-inode tmpfs. This is the
runtime write budget; it is enforced by the mount boundary rather than by a
post-run size check or a polling watchdog. The report records the limits and
whether a path is host-backed.

Docker client output is streamed in fixed 8192-byte reads. stdout and stderr
are each limited to 64 KiB, total output is limited to 128 KiB, and previews
are separately character-bounded and redacted. Full raw stdout/stderr is not
retained in memory or written to disk. Output-budget exceedance is distinct
from timeout and is fail-closed with exit `2`.

## Network Policy

The default network policy is deny. The Docker backend uses `--network none`.
Network failure inside the command is recorded as command failure evidence, not
as policy failure. Host allowlists are not implemented in v1 and are not
claimed.

## Gate And Authorization Binding

`--fail-on-gate` generates a gate decision before Docker is invoked and blocks
with exit `2` when the verdict meets the selected threshold:

- `block`: `BLOCK`
- `quarantine`: `QUARANTINE` or `BLOCK`
- `warn`: `WARN`, `QUARANTINE`, or `BLOCK`
- `unknown`: `UNKNOWN`, `WARN`, `QUARANTINE`, or `BLOCK`

For non-dry-run Docker execution, `--authorization PATH` is mandatory.
sandbox-run validates the human-controlled execution authorization artifact
against the generated gate decision and exact argv, then performs the
worktree binding and single-use reservation immediately before Docker. A gate
decision is still not execution authorization, and product code does not
generate or approve the artifact automatically.

The legacy `--approval` artifact is still supported for exact sandbox-run
approval compatibility for non-real paths and dry-run planning. It never
authorizes a real Docker execution by itself. If supplied, mismatches block
before Docker.

## Exit Code Contract

- Policy, gate, authorization, legacy approval, or copy-budget block: exit `2`
  with stderr prefix `SANDBOX-RUN POLICY BLOCK`.
- Output byte budget exceeded: exit `2`, with the Docker client and the
  tracked container stopped and cleanup confirmed before the result is usable.
- Timeout: exit `1`; `command_start_state` is `unknown` unless command start is
  independently confirmed, and the tracked container is cleaned up.
- sandbox-run infrastructure or configuration error: exit `1` with stderr
  prefix `SANDBOX-RUN ERROR`.
- Cleanup failure or an unconfirmed tracked-container removal: exit `1` and
  report `cleanup_uncertain`.
- Command started: return the command exit code with stderr prefix
  `SANDBOX-RUN COMMAND EXIT` when nonzero.

This means a command that exits `2` is distinguishable from a policy block:
`command_started=true`, `command_exit_code=2`, and stderr uses the command-exit
prefix.

## Evidence Report

The JSON report is `schemas/sandbox-run.schema.json` with
`report_kind: sandbox_run`. It includes:

- run id, timestamps, dry-run and preserve flags
- target identity and fingerprint
- redacted argv and command cwd
- profile, backend, Docker argv, image, and network policy
- copy policy, exclusions, symlink policy, special-file policy, and copy budget
- env policy with keys only
- gate and authorization summaries
- canonical report fingerprintとrun ID、およびgate-bound reportでは元gate decisionの
  fingerprint、subject、policy version
- `policy_blocked`, `command_started`, `command_exit_code`,
  `sandbox_exit_code`, and `block_reason`
- bounded redacted stdout/stderr previews
- stdout/stderr/total observed byte counts, byte budgets, truncation flags, and
  output-budget status
- `command_start_state` (`not_started`, `confirmed`, or `unknown`)
- created / modified / deleted file summary
- container tracking, cleanup attempt/status/failure class, runtime write
  budget, and limitations

Reports must not contain raw secrets, raw host private paths, raw local
environment values, or unbounded stdout/stderr.

JSON reportは次のgateへ明示的に還流できる。

```bash
env PYTHONPATH=src python3 -m repo_health_doctor gate-check . \
  --sandbox-evidence /tmp/rhd-sandbox-run.json \
  -- <next-command>
```

`--sandbox-evidence`は最大16件、各256 KiB、合計1 MiB、生成から24時間以内に
boundedされる。gate decisionはraw reportを保持せず、sandbox report fingerprint、
run ID、元gate decision fingerprint、validation status、machine-readable reasonだけを
`evidence_refs`へ残す。duplicate fingerprintはinvalid evidenceとして扱う。
successful executionは`successful_execution_is_not_safety`というinformational noteであり、
安全証明でも次のcommandのauthorizationでもなく、gate verdictを改善しない。

## Fake Runner And Dry-Run

The fake runner and `--dry-run` are test and documentation helpers. They are
useful for argv validation, policy validation, schema checks, and CI without a
local daemon. They are not substitutes for real Docker verification of the
product path.

## Non-Goals

sandbox-run v1 is not:

- a safety proof
- complete malware containment
- VM-grade isolation
- an exploit detector
- an EDR replacement
- a scanner replacement
- a remote execution service
- authorization for arbitrary unknown-repository commands

Docker daemon, kernel, image, platform, and local configuration risks remain
review boundaries.
