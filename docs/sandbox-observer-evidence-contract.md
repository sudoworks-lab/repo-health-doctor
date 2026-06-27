# Unknown Repository Observer Evidence Contract

## Boundary

This is a design for future runner-collected evidence. It does not add a
runner, Docker action, observer invocation, or live command execution. `strace`
and runtime hooks are evidence sources, not safety guarantees. Missing,
degraded, unavailable, or ambiguous evidence never produces PASS.

## Collection Requirements

Future required `strace` evidence must identify observer availability, log
presence, parse success, collection boundaries, event counts, and safe log
handles. Runtime-hook evidence must identify hook availability, event count,
event categories, and read/parse status. Neither source may place raw syscall
lines, raw stdout/stderr, host paths, credential values, or unredacted errors
in reports.

The runner stores raw observer data only in a disposable, access-controlled
evidence location. It passes a normalized summary to policy evaluation and
renders counts/categories/logical handles only. Retention, access, and secure
deletion policy require human operational ownership before any live phase.

## Normalized Evidence Input

`schemas/sandbox-normalized-observer-evidence.schema.json` is the canonical,
closed input to behavior policy evaluation. It uses
`schema_version: "0.1-draft"` and
`report_kind: "sandbox_normalized_observer_evidence"`. The validator accepts
only this exact object shape; all objects use `additionalProperties: false`.
The evaluator retains a narrow compatibility shim for the prior static test
shape, but new producer integrations must emit this normalized document.

```json
{
  "schema_version": "0.1-draft",
  "report_kind": "sandbox_normalized_observer_evidence",
  "evidence_id": "redacted-evidence-handle",
  "source": {"observer_mode": "strace_runtime_hook", "strace_available": true, "strace_log_present": true, "strace_parse_success": true, "runtime_hook_available": true, "runtime_hook_active": true, "runtime_hook_parse_success": true, "observer_degraded": false, "degraded_reasons": []},
  "command": {"phase": "phase2_install_probe", "kind": "install_probe", "cwd": "/workspace", "argv_fingerprint": "sha256:<redacted-fingerprint>", "shell": false, "network_policy": "none"},
  "execution": {"return_code": 0, "timeout": false, "duration_ms": 0, "completed": true},
  "counts": {"process_event_count": 1, "unexpected_exec_count": 0, "subprocess_event_count": 0, "network_event_count": 0, "file_write_event_count": 0, "outside_allowed_write_count": 0, "denied_read_count": 0, "docker_socket_access_count": 0, "host_home_access_count": 0, "secret_event_count": 0, "outside_writable_delete_count": 0, "strace_parse_error_count": 0, "runtime_hook_parse_error_count": 0},
  "flags": {"evidence_complete": true, "raw_logs_included": false, "stdout_included": false, "stderr_included": false, "host_paths_redacted": true, "secrets_redacted": true},
  "summaries": {"process_summary": ["clean"], "file_summary": ["clean"], "network_summary": ["none"], "secret_summary": ["none"], "limitations": ["future_runner_required"], "residual_risks": ["observed_scope_only"]},
  "redaction": {"status": "redacted", "raw_host_path_present": false, "raw_secret_like_value_present": false}
}
```

The report is normalized evidence, never a raw log. It cannot include raw
syscall text, stdout, stderr, host paths, or secret-like values. Event data is
represented only by fixed categories, counts, fingerprints, and safe labels.
Unknown safety-relevant fields, malformed counts, raw paths, secret-like
values, raw logs, stdout, or stderr are invalid and BLOCK at validation.

The validator emits
`sandbox_normalized_observer_evidence_validation`. `valid: true` confirms the
shape only. `pass_eligible` is separately false for missing/unavailable
strace, missing log, parse failure or parse errors, degraded observers,
incomplete evidence, timeout, and—when policy requires it—unavailable,
inactive, or unparsable runtime hooks. A validator PASS is not a command
safety guarantee; the behavior-policy verdict remains the final policy input.

The static behavior-policy binding verifier additionally compares this
canonical document with its approval artifact, behavior policy, and candidate
key material. A validation report cannot replace the normalized evidence
document for that comparison because the report intentionally omits the exact
command and evidence identity needed for a closed binding. It blocks incomplete,
degraded, missing, or parse-failed evidence even when the document shape is
otherwise valid.

The non-executing runner preflight reuses the normalized evidence validator and
the behavior-policy binding verifier as static gates. It does not capture
observer data or parse raw logs. Missing, degraded, incomplete, or parse-failed
evidence remains PASS-ineligible and blocks the preflight when required by the
policy/binding checks.

`docs/sandbox-single-command-live-gate-design.md` defines the future controlled
live capture boundary. A future live gate must start observer capture before
the command, keep raw syscall logs and stdout/stderr out of reports, produce
this normalized evidence shape, and block final PASS when evidence is missing,
degraded, incomplete, or parse-failed.

## Failure Semantics

Observer unavailable, missing `strace` log, `strace` parse failure, required
runtime hook unavailable, missing evidence, timeout, or absent return code are
BLOCK by default. A future policy can classify explicitly optional
non-security evidence as WARN/needs review, but cannot convert required
observer absence into PASS. Network, denied read, outside write, Docker socket,
host HOME, secret, and outside delete evidence retain their default-deny
behavior-policy semantics.

PASS therefore means only that complete normalized evidence was within the
policy's monitored scope. It is not a conclusion that the repository, image,
or host is safe. No runner connection, Docker action, live phase, strace
execution, runtime-hook execution, or observer capture is implemented here.
