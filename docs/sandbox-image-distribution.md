# Sandbox Image Distribution Policy

## Boundary

`sandbox.image_lock` statically validates a closed image-lock document. It does
not query a Docker daemon, inspect an image, pull an image, start a container,
or connect a lock to a runner. An image lock is reproducibility evidence, not
an approval file or execution permit.

Registry digest-pinned images are the primary future distribution input. A
local sanctioned image is development-only and requires explicit opt-in plus
an exact full image ID. A tag-only image, including `latest`, is never valid.
Human-operated setup may pull a reviewed digest outside this tool; future
runtime execution must use `--pull=never` and verify the already-resolved
digest. Runner integration remains a later phase.

## Lock Contract

The implementation schema is
`schemas/sandbox-image-lock.schema.json`. It uses
`schema_version: "0.1-draft"` and `report_kind: "sandbox_image_lock"`.

Each lock includes a lock ID, one or more images, version metadata, required
runtime flags, a binding contract, and residual risks. Every image records:

- logical name, purpose, supported phases/runtimes, expected Linux platform;
- registry reference and exact digest for `registry_primary` images;
- optional image ID only for `local_dev_only` images;
- Python, Node, strace, pip, npm, and other tool-version slots;
- source/build metadata; and
- local-sanctioning state and portability limitations.

Required runtime flags are fixed to `pull_policy: never`, `network: none`,
`shell: false`, `host_home: false`, and `docker_socket: false`. A missing,
ambiguous, unsupported, or relaxed value is invalid and reports BLOCK.

```json
{
  "schema_version": "0.1-draft",
  "report_kind": "sandbox_image_lock",
  "lock_id": "python312-runtime-v1",
  "images": [
    {
      "logical_name": "python312-runtime",
      "distribution": "registry_primary",
      "registry_reference": "registry.example.invalid/rhd/python312@sha256:<64-hex>",
      "registry_digest": "sha256:<64-hex>",
      "expected_image_id": null,
      "purpose": "unknown_repo_runtime_observation",
      "supported_phases": ["phase2_install_probe", "phase3_runtime_probe"],
      "supported_runtimes": ["python"],
      "tool_versions": {"python": "3.12.x", "node": "not_included", "strace": "6.x", "pip": "24.x", "npm": "not_included", "other": "none"},
      "expected_platform": {"os": "linux", "architecture": "amd64"},
      "source_build_metadata": {"source": "human_reviewed_registry_setup", "build_reference": "release_v1"},
      "local_sanctioned_allowed": false,
      "local_sanctioned_limitations": []
    }
  ],
  "version_metadata": {"created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z", "source": "human_reviewed_registry_setup"},
  "required_runtime_flags": {"pull_policy": "never", "network": "none", "shell": false, "host_home": false, "docker_socket": false},
  "binding_contract": {"approval_draft_report_kind": "sandbox_approval_draft", "behavior_policy_report_kind": "sandbox_command_behavior_policy", "behavior_policy_schema_version": "0.1-draft", "image_lock_schema_version": "0.1-draft", "candidate_key_includes": ["image_lock_schema_version", "image_lock_id", "registry_digest", "expected_image_id", "required_runtime_flags", "behavior_policy_schema_version"]},
  "residual_risks": ["digest_pinning_does_not_remove_container_runtime_or_kernel_risk"]
}
```

For `local_dev_only`, `local_sanctioned_allowed` must be true,
`expected_image_id` must be a full `sha256:` ID, and a non-empty portability
limitation is required. The validator reports the limitation but does not
inspect the local image.

## Binding And Failure Rules

The lock binding contract reserves `image_lock_id`, registry digest, expected
image ID, required runtime flags, and behavior-policy schema version for the
future exact candidate key. It names `sandbox_approval_draft` and
`sandbox_command_behavior_policy` without changing either document. The
approval draft remains `approved: false` and `execution_permitted: false`.

Unknown fields, missing required fields, unsupported schema versions, missing
digest, tag-only registry references, short local IDs, unsafe runtime flags,
secret-like values, and malformed host-path-like values fail closed. Validation
reports safe categories and booleans only; it does not echo raw lock input.

Digest pinning and `--pull=never` reduce drift but do not remove container
runtime, kernel, or mount-breakout risks. T4/T5 repositories still require a
dedicated VM or stronger isolation before any separate investigation.

The controlled static dry-run integration can validate this lock alongside a
profile, draft, and behavior policy. This confirms static contract readiness
only; it does not inspect a local image or make a runner/live invocation ready.

## Static Approval Lock-Binding Gate

`sandbox.lock_binding` now compares a supplied command-approval artifact,
image lock, behavior policy, and closed candidate-key material. Its report
uses `schema_version: "0.1-draft"` and
`report_kind: "sandbox_image_lock_binding_validation"`; its schema is
`schemas/sandbox-image-lock-binding-validation.schema.json`.

The gate rechecks, rather than trusting a prior approval validation result,
the lock ID, digest or full local image ID, platform, complete tool-version
inventory, behavior-policy ID/fingerprint, candidate command binding, and the
fixed runtime boundaries: `pull_policy: never`, `network: none`, `shell:
false`, `host_home: false`, and `docker_socket: false`. Any missing,
ambiguous, unsupported, or mismatched value BLOCKs. The report is always
`execution_permitted: false`, `runner_connected: false`, and
`docker_contacted: false`.

For a local sanctioned image the gate requires explicit opt-in, a full image
ID, a development-only purpose, and portability limitations. A matching local
image therefore produces WARN with those limitations; it is never promoted to
the primary registry distribution path. The gate does not inspect the local
image or query Docker. A matching static report is not runner authorization;
runner connection remains a later phase.

`docs/sandbox-single-command-live-gate-design.md` defines the later controlled
single-command live gate image-attestation boundary. Runtime must use
`--pull=never`; a future Docker inspect step must fail closed on missing,
ambiguous, or mismatched digest, full image ID, platform, tool inventory, or
operator runtime attestation. This design document does not add Docker
inspection or execution.

## Static Image Attestation Skeleton

`sandbox.image_attestation` validates a supplied static image-attestation
report for future live gates. Its input schema is
`schemas/sandbox-image-attestation.schema.json` with `schema_version:
"0.1-draft"` and `report_kind: "sandbox_image_attestation"`. Its validation
report uses `report_kind: "sandbox_image_attestation_validation"`.

This static report is not a replacement for Docker inspect. It records the
shape future Docker inspect output must be normalized into: image reference
kind, registry digest or full local image ID, platform, tool inventory,
runtime flag attestations, operator runtime-version attestation, local-image
limitations, residual risks, and redaction status. The validator does not
query Docker, pull, inspect, run, connect a runner, or authorize execution.

When an image lock is supplied, the validator rechecks lock schema/report kind,
lock ID, registry digest or full local image ID, platform, tool versions, and
runtime flags. When an image-lock validation result is supplied, a BLOCK result
causes attestation validation to BLOCK. Digest, full image ID, platform, tool
inventory, or runtime flag mismatch fails closed.

Registry attestations must use a digest-pinned reference and runtime
`pull_policy: never`. Local sanctioned images require a matching full image
ID, explicit `allowed: true`, `dev_only: true`, and portability limitations;
they can validate only with WARN and remain development-only. Image rotation
requires invalidating approvals bound to the previous digest, full image ID,
or lock.
