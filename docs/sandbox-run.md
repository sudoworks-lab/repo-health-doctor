# Experimental Sandbox-Run Add-on

`sandbox-run` is an optional experimental Docker add-on for users who already
have a reviewed command and want to avoid running that repository-derived
command directly on the host.

It does not prove safety. It does not provide complete malware containment. It
does not grant unrestricted execution authorization.

## Purpose

The add-on runs one explicitly approved argv inside a constrained Docker
container, using a disposable copy of the target repository, and emits a
redacted sandbox execution report.

The default workflow remains:

1. Run the pre-execution gate first.
2. Review the gate decision, limitations, and human-readable summary.
3. If a human still wants bounded execution evidence, create a scoped
   sandbox-run approval for exactly one command.
4. Run `sandbox-run`.
5. Treat the result as bounded evidence, not as a safety proof.

## CLI Usage

Safe synthetic fake-runner smoke, requiring no Docker daemon:

```bash
env PYTHONPATH=src python3 -m repo_health_doctor sandbox-run examples/demo-synthetic-supply-chain \
  --approval examples/approvals/demo-sandbox-run-approval.json \
  --image python:3.12-slim \
  --profile no-network-default \
  --runner fake \
  --format json \
  --output /tmp/rhd-sandbox-run.json \
  -- python3 -c "print('hello from sandbox')"
python3 -m json.tool /tmp/rhd-sandbox-run.json
```

Real Docker mode uses the same approval and command shape, but omits
`--runner fake`:

```bash
env PYTHONPATH=src python3 -m repo_health_doctor sandbox-run examples/demo-synthetic-supply-chain \
  --approval examples/approvals/demo-sandbox-run-approval.json \
  --image python:3.12-slim \
  --profile no-network-default \
  --format json \
  --output /tmp/rhd-sandbox-run.json \
  -- python3 -c "print('hello from sandbox')"
```

Real Docker mode never pulls images. The image must already be available
locally, and the requested image must match the approval.

## Approval Requirements

The approval artifact must bind:

- `action: sandbox_run`
- exact command argv
- target identity and fingerprint
- Docker image reference
- sandbox profile
- network mode
- timeout
- resource limits
- root user allowance
- expiry, when present

Any mismatch blocks execution before Docker is invoked.

## Sandbox Profiles

`no-network-default` is the default practical host-execution-avoidance profile:

- Docker network mode is `none`.
- Docker socket, host HOME, credentials, and SSH agent are not mounted.
- The original repository path is not mounted directly as writable.
- A disposable copy is mounted at `/workspace`.
- The container is not privileged.
- Capabilities are dropped with `--cap-drop ALL`.
- `no-new-privileges` is set.
- memory, CPU, and PID limits are set.
- stdin is closed and TTY is disabled.
- timeout is enforced by Python.
- stdout and stderr are bounded and redacted in the report.

`no-network-readonly` adds a read-only root filesystem plus a small `/tmp`
tmpfs. It remains experimental and image-dependent.

`network-explicit` is reserved for future work and fails closed in S-001.

## Docker Boundary

The generated Docker argv is deterministic and tested. It includes
`docker run`, `--rm`, `--pull=never`, `--network none`, `/workspace` workdir,
capability drop, no-new-privileges, resource limits, a disposable workspace
mount, the approved image, and the approved argv.

It does not include privileged mode, host networking, host PID/IPC/UTS modes,
capability additions, Docker socket mounts, host HOME mounts, credential
mounts, arbitrary user volumes, or shell wrapping by default.

Docker is still not a complete malware sandbox. Kernel, daemon, image, and
platform risks remain outside the guarantee.

## Image Policy

- Images are not pulled automatically.
- The pull policy is `never`.
- Missing local images block execution.
- Digest-pinned images are preferred.
- Tag-based images are supported for usability, but the report records
  `image_digest_pinned=false`.
- `latest` tags are reported as a limitation.

## Workspace Copy Policy

The source repository is copied to a disposable workspace. The original path is
not mounted directly as writable.

The copy policy excludes `.git`, `.env`, common caches, virtual environments,
build outputs, and credential-like files. Symlinks and unsupported filesystem
entries are skipped and recorded. Unsafe or uncertain workspace copy evidence
blocks execution.

Post-run diff evidence records bounded counts and redacted interesting paths:
created, modified, deleted, before fingerprint, after fingerprint, and
`raw_contents_persisted=false`.

## Output Redaction

stdout and stderr are captured as bounded previews only. Reports include:

- `stdout_preview_redacted`
- `stderr_preview_redacted`
- truncation flags
- `redaction_applied`
- `raw_stdout_stderr_persisted=false`

Raw unbounded stdout/stderr is not persisted by default.

## Report Fields

The experimental report is `schemas/sandbox-run.schema.json` with
`report_kind: sandbox_run`. It includes target fingerprint, approval match,
profile, Docker boundary, disposable workspace status, workspace diff, result,
output summary, boundary statement, limitations, next actions, and safety
statement.

The report schema is experimental and may change in the v0.x series.

## Agent Usage Guidance

Agents should not run repository-derived commands on the host by default. Use:

1. gate first
2. human approval for the exact sandbox-run command
3. sandbox-run second
4. fail closed on missing approval, mismatch, missing image, timeout, degraded
   evidence, redaction failure, or cleanup uncertainty

Do not treat a completed sandbox-run as permission to continue executing
commands outside the approved scope.

## Limitations And Non-Goals

`sandbox-run` is not:

- complete malware containment
- VM-grade isolation
- an exploit detector
- an EDR replacement
- a scanner replacement
- a remote execution service
- authorization for arbitrary unknown repository commands

S-001 is a personal-OSS-grade add-on that reduces direct host execution risk
and produces bounded evidence. Stronger claims require future hardening and
external security review.
