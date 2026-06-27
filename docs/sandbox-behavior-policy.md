# Sandbox Command Behavior Policy (Design Draft)

## Purpose

`sandbox.behavior_policy` validates a closed behavior-policy document and
evaluates supplied, already-collected evidence for one exact human-reviewed
command candidate. Its canonical evidence input is
`sandbox_normalized_observer_evidence`; the prior compact test input remains a
compatibility shim only. It supplements command-level approval; it does not
replace it. It has no runner, Docker, approval-file, or live-phase integration.

`strace` and runtime hooks provide observed evidence, not a safety guarantee.
The policy therefore evaluates the evidence that is available, records its
limitations, and fails closed when the required observer evidence is missing,
unavailable, or unparsable. It never converts a lack of observations into a
safety claim.

## Default-Deny Contract

The initial policy defaults are intentionally narrow:

- `network.allowed` is `false`.
- Shell strings, `shell: true`, `sh -c`, `bash -c`, and PowerShell are denied.
- Writes are allowed only in declared disposable logical prefixes.
- Host HOME, credential paths, and the Docker socket are denied reads and
  denied mounts.
- `max_secret_events` and `outside_writable_delete_max` are `0`.
- Subprocesses are denied unless an exact, reviewed binary allowlist and event
  limit are present.
- The expected return code, timeout, environment keys, image lock, and
  observer requirements are command-specific.

No policy can request host networking, shell access, Docker socket access,
host HOME access, raw credential access, a tag-only image, or a T4/T5 live
exception. Such input is invalid rather than a configurable relaxation.

## Behavior Policy JSON Example

This policy is static input to the evaluator. It cannot be supplied to the
runner as an approval file and cannot promote a draft.

```json
{
  "schema_version": "0.1-draft",
  "report_kind": "sandbox_command_behavior_policy",
  "policy_id": "behavior-policy:sha256:<redacted-fingerprint>",
  "binding": {
    "candidate_key": "sha256:<normalized-command-fingerprint>",
    "repo_identity": "sha256:<redacted-repository-fingerprint>",
    "commit": "<exact-commit-hash>",
    "phase": "phase3_runtime_probe",
    "kind": "runtime_smoke",
    "cwd": "/workspace",
    "argv": ["python", "-m", "<reviewed-module>"],
    "env_allowlist": ["PYTHONPATH"],
    "shell": false,
    "image_policy_schema_version": "unconfigured",
    "network_policy": "none"
  },
  "expected_behavior": {
    "network": {"allowed": false},
    "allowed_write_prefixes": [
      "/workspace",
      "/tmp/home",
      "/tmp/npm-cache",
      "/tmp/pip-cache",
      "/tmp/xdg-cache",
      "/tmp/tmp"
    ],
    "denied_read_prefixes": ["<host-home>", "<credential-paths>"],
    "denied_socket_paths": ["/var/run/docker.sock"],
    "allowed_exec_binaries": ["python"],
    "allow_subprocess": false,
    "limited_subprocess_binaries": [],
    "max_process_events": 0,
    "max_secret_events": 0,
    "max_outside_writable_delete": 0,
    "allowed_env_keys": ["HOME", "PYTHONPATH", "TMPDIR"],
    "timeout_seconds": 60,
    "expected_return_codes": [0]
  },
  "severity_rules": {
    "network_event": "block",
    "write_outside_allowed_prefix": "block",
    "docker_socket_access": "block",
    "host_home_access": "block",
    "denied_read_access": "block",
    "secret_event": "block",
    "unexpected_execve": "block",
    "subprocess_spawn": "block",
    "observer_unavailable": "block",
    "strace_log_missing": "block",
    "strace_parse_failure": "block",
    "evidence_missing": "block",
    "timeout": "block",
    "return_code_mismatch": "block",
    "outside_writable_delete": "block"
  },
  "observer_requirements": {
    "strace_required": true,
    "runtime_hook_required": true,
    "evidence_required": true,
    "default_verdict_on_missing_evidence": "block"
  },
  "redaction": {
    "raw_host_paths_redacted": true,
    "secret_like_values_redacted": true
  }
}
```

## Verdict Rules

The policy engine must first validate the binding exactly, then evaluate
redacted evidence. The following initial rules are non-negotiable:

| Observation or validation result | Verdict | Notes |
| --- | --- | --- |
| Network syscall/event count is non-zero | BLOCK | `--network none` is a containment control, not a reason to ignore an attempt. |
| Write outside an allowed disposable prefix | BLOCK | A path that cannot be normalized safely is also BLOCK. |
| Docker socket or host HOME access/mount | BLOCK | Never configurable as an exception. |
| Secret or honeypot event | BLOCK | Static credential references can be WARN; observed access is BLOCK. |
| Unexpected `execve` or disallowed binary | BLOCK in the initial unknown-repo rollout | A later policy may only reduce this to WARN through a reviewed allowlist and schema change. |
| Subprocess spawn while `allow_subprocess` is false or over limit | BLOCK | A limited subprocess policy requires exact binary allowlist and event cap. |
| Observer unavailable, degraded, or required runtime hook absent | BLOCK | The command cannot receive PASS. |
| Missing strace log or syscall parse failure | BLOCK | A successful process return code does not override evidence failure. |
| Evidence missing for a required rule | WARN or BLOCK, never PASS | Use BLOCK for a required observer; use WARN only for explicitly optional, non-security evidence. |
| Return code outside the exact allowlist or timeout | BLOCK | The result is not silently retried with broader permissions. |

Every verdict contains safe counts, categories, and limitation messages only.
It does not render raw syscall logs, stdout/stderr, raw host paths, or
secret-like values. PASS means only that the supplied evidence was within the
policy's monitored scope; it does not mean that the unknown repository is
safe. Missing evidence, observer degradation, unavailable observers, missing
strace logs, and parse failures never produce PASS.

## Schema Contract

Required behavior-policy fields are `schema_version`, `report_kind`,
`policy_id`, `binding`, `expected_behavior`, `severity_rules`,
`observer_requirements`, and `redaction`.
The binding must include repository identity, exact commit, candidate key,
phase, kind, cwd, argv, environment allowlist, `shell: false`, image lock ID,
and `network_policy: none`.

Optional fields may add safe reviewer notes, severity rationale, or an explicit
allowed subprocess binary list. They cannot add a new permission category or
relax a denied boundary. Unknown fields, absent fields, unsupported schema
versions, malformed limits, empty binary allowlists, non-array argv, missing
redaction requirements, or ambiguous severity rules are fail-closed. The
default JSON schema should use `additionalProperties: false`.

Any change that alters a default, required field, verdict meaning, or allowed
behavior requires a schema-version bump and a new human review. Older runners
must reject newer unsupported policy versions rather than ignoring fields.

The implementation is [sandbox-behavior-policy.schema.json](../schemas/sandbox-behavior-policy.schema.json)
with `schema_version: "0.1-draft"` and
`report_kind: "sandbox_command_behavior_policy"`. The evaluator produces a
`sandbox_behavior_verdict` report with the evaluated policy version. It is a
static verdict engine only; runner/live integration remains a later phase.

The controlled static dry-run integration may validate this policy against a
draft candidate and clean synthetic normalized evidence. That validates schema and
binding consistency only; it does not establish observer coverage, Docker
readiness, or live-command readiness.

## Static Behavior-Policy Binding Gate

`sandbox_behavior_policy_binding_validation` is a closed, document-only gate
for a supplied approval artifact, behavior policy, normalized observer
evidence, and exact candidate-key material. It rechecks policy ID and binding
fingerprint plus phase, kind, cwd, argv fingerprint, shell, network policy,
and observer requirements. Missing or mismatched material fails closed.

The gate requires complete, non-degraded evidence with available, present, and
successfully parsed strace data; it also requires an available, active, and
successfully parsed runtime hook when the policy requires one. Parse-error
counts, raw paths, and secret-like inputs block. Its PASS is not runner
authorization and does not replace the behavior-policy verdict. It never
contacts Docker, starts a runner, executes a command, or captures evidence.
