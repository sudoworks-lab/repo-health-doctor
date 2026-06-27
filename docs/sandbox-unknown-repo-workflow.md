# Sandbox Unknown Repository Workflow (Design Draft)

## Status And Boundary

`repo-health-doctor sandbox-profile <path>` implements the read-only profile
and risk-tier steps in this document. It is not an execution feature, an
approval file, or permission to run any repository command. The existing
`sandbox` runner remains limited to its controlled-fixture gates.

The future workflow is deliberately ordered as follows:

1. Read the repository in plan-only mode.
2. Emit a redacted unknown-repository profile and assign the highest matching
   risk tier.
3. Generate zero or more approval *drafts* with
   `draft_requires_human_review` status.
4. Require a human to review the profile, exact command, behavior policy, and
   image lock in a separate promotion process.
5. Permit a future live runner only when every independent fail-closed gate is
   satisfied. Step 3 is implemented only as a non-executable report generator;
   step 4 has static validators and binding checks, and step 5 has only a
   non-executing preflight skeleton.

Plan-only discovery never fetches dependencies, starts Docker, pulls an image,
or executes a repository-derived command. A draft is evidence for review, not
an authorization artifact. In particular, no unknown-repository workflow may
set `approved: true` automatically.

The non-executing runner preflight is still a static-artifact consistency
check. A PASS means the supplied approval, image lock, behavior policy,
normalized observer evidence, binding reports, and static transition report
matched the current closed contracts. It does not contact Docker, start
observer capture, run a live phase, or permit execution; the report keeps
`execution_permitted: false`.

## Unknown Repository Profile

The profile is a static, read-only inventory. It must report categories,
repo-relative paths, counts, safe script names, and fingerprints instead of
raw source text, host paths, command strings, credential values, or URLs.

| Profile area | Required plan-only signals |
| --- | --- |
| Repository shape | Package managers, manifest files, package scripts, lifecycle scripts, npm scripts, Python build backend, and `pyproject.toml` `build-system.requires` classification. |
| Dependency sources | Direct URL, VCS, editable, and local-path dependency counts and redacted/repo-relative finding locations. |
| Executable surface | Native binaries, executable files, archives, script interpreter references, subprocess/toolchain references, and shell command references. |
| Network and shell indicators | Network-related references, `curl`, `wget`, `powershell`, `bash`, `sh`, and other shell/reference categories. |
| Host-boundary indicators | Credential-path references, Docker socket references, host HOME references, unsafe symlinks, and symlink escape risks. |
| Evasion and size indicators | Obfuscation indicators, suspicious files, large binaries, and archive indicators. |

`package_scripts` and `npm_scripts` record a safe name and a normalized
classification or fingerprint. They do not expose a raw script body. Findings
that might contain an access token, URL query string, local absolute path, or
credential value are redacted before the profile object is assembled and again
over the final report object.

### Profile JSON Example

This is the `sandbox-profile --format json` structure. Placeholder values are
schematic; runtime output uses redacted handles and fingerprints.

```json
{
  "schema_version": "0.1-draft",
  "report_kind": "sandbox_unknown_repo_profile",
  "mode": "plan_only",
  "execution_permitted": false,
  "repo_scope": {
    "repository_identity": "sha256:<redacted-repository-fingerprint>",
    "commit": "<commit-hash-or-unavailable>",
    "path": "<repo>"
  },
  "profile": {
    "package_managers": ["npm", "pip"],
    "manifest_files": [
      {"path": "package.json", "kind": "npm_manifest"},
      {"path": "pyproject.toml", "kind": "python_project"}
    ],
    "package_scripts": [
      {"ecosystem": "npm", "name": "test", "classification": "argv_candidate"}
    ],
    "lifecycle_scripts": [
      {"ecosystem": "npm", "name": "postinstall", "classification": "lifecycle_script"}
    ],
    "python_build": {
      "backend": "build_backend_reference",
      "build_system_requires": "external_dependencies_present"
    },
    "dependency_sources": {
      "direct_url_count": 1,
      "vcs_count": 0,
      "editable_count": 0,
      "local_path_count": 0
    },
    "indicators": {
      "native_binary_count": 0,
      "suspicious_file_count": 1,
      "unsafe_symlink_count": 0,
      "credential_path_reference_count": 0,
      "network_reference_count": 2,
      "shell_reference_count": 1,
      "command_reference_categories": ["curl_reference", "bash_reference"],
      "docker_socket_reference_count": 0,
      "host_home_reference_count": 0,
      "obfuscation_indicator_count": 0,
      "large_binary_or_archive_count": 0
    }
  },
  "risk": {
    "tier": "T4",
    "report_status": "block",
    "disposition": "dedicated_vm_required",
    "reasons": ["direct_url_dependency", "network_reference"]
  },
  "redaction": {
    "raw_host_paths_redacted": true,
    "secret_like_values_redacted": true
  },
  "limitations": [
    "Static profiling cannot establish runtime behavior or safety."
  ]
}
```

## Risk Tiers

The highest matching tier wins. A missing, unreadable, ambiguous, or
unsupported input never lowers the tier; it produces at least `needs_review`.
`needs_review` is a workflow disposition, while `warn` and `block` remain
report severities.

| Tier | Detection conditions | Report disposition | Future Phase 2 / 3 eligibility | Human review / draft | Dedicated VM guidance |
| --- | --- | --- | --- | --- | --- |
| T0 | No manifest, no scripts, no dependencies, no executable indicators. | `warn` + `needs_review`; no runtime candidate exists. | No. | No draft unless a later explicit candidate is supplied; human review is needed to change scope. | Not required by tier alone. |
| T1 | Manifest exists, no external fetch source, no lifecycle/build/shell/network/credential indicators. | `warn` + `needs_review`; static result is not safety proof. | Never automatic. A future low-risk rollout could consider only a human-promoted exact Phase 3 candidate. | Human review required; draft may be emitted with `approved: false`. | Not required by tier alone. |
| T2 | Dependencies require Phase 1 fetch and Phase 1.5 rescan, but no T3/T4 indicator. | `warn` + `needs_review`. | Never automatic. Only after successful future Phase 1/1.5 gates, human promotion, image lock, and behavior policy validation. | Human review required; draft may be emitted. | Recommended when provenance is weak. |
| T3 | Lifecycle script, build backend, subprocess/toolchain discovery, or executable build surface. | `WARN-high` + `needs_review`. | Not in the initial unknown-repository live rollout. Any later exception requires explicit human review and stronger isolation. | Draft may be emitted, never auto-promoted. | Recommended. |
| T4 | Obfuscation, credential access, network download/reference, native binary, direct URL, VCS dependency, Docker socket, host HOME, or equivalent high-risk indicator. | `block` + `dedicated_vm_required`. | No. It is not a Docker live candidate. | A draft may document the candidate, but must remain non-executable. | Required before any separate investigation. |
| T5 | Malware suspicion, active evasion, credential theft pattern, destructive behavior, persistence, or multiple T4 indicators with ambiguity. | `block` + `quarantine_or_specialist_review`. | No. | No approval draft for execution; only an incident/review record. | Required, preferably isolated from developer credentials and ordinary Docker access. |

The following are always default-deny and never auto-approved for an unknown
repository: shell execution, network access, direct URL or VCS dependencies,
credential or host HOME access, Docker socket access, native binaries,
obfuscation, and all T4/T5 candidates. Phase 2 authorization cannot satisfy a
Phase 3 request, and vice versa.

## Approval Drafts

`sandbox-approval-draft` calculates a stable `candidate_key` for exact-match
comparison from the source profile, static Git metadata when available, and an
explicit candidate. It does not write an approval file. A draft must retain `approved: false` and
`status: draft_requires_human_review` regardless of risk tier. A controlled
fixture approval file is a separate artifact type and cannot be copied,
renamed, or reused as an unknown-repository draft.

### Approval Draft JSON Example

```json
{
  "schema_version": "0.1-draft",
  "report_kind": "sandbox_approval_draft",
  "status": "draft_requires_human_review",
  "approved": false,
  "candidate_key": "sha256:<normalized-command-fingerprint>",
  "exact_match_key": "sha256:<normalized-command-fingerprint>",
  "repo_scope": {
    "repository_identity": "sha256:<redacted-repository-fingerprint>",
    "commit": "<exact-commit-hash>",
    "repo_relative_path": "."
  },
  "candidate": {
    "phase": "phase3_runtime_probe",
    "kind": "runtime_smoke",
    "cwd": "/workspace",
    "argv": ["python", "-m", "<reviewed-module>"],
    "env_allowlist": ["PYTHONPATH"],
    "shell": false
  },
  "execution_constraints": {
    "network_policy": "none",
    "image_lock_id": "python312-runtime-v1",
    "image_reference": "registry.example.invalid/rhd/python312@sha256:<digest>",
    "expected_image_id": "sha256:<full-local-image-id>"
  },
  "behavior_policy": {
    "schema_version": "unconfigured",
    "report_kind": "sandbox_command_behavior_policy",
    "status": "placeholder_not_validated"
  },
  "promotion_requirements": [
    "human_review_of_profile_and_exact_argv",
    "repo_identity_and_commit_still_match",
    "risk_tier_is_not_T4_or_T5",
    "approved_digest_pinned_image_lock_matches",
    "behavior_policy_is_valid_and_default_deny",
    "separate_human_created_approval_file"
  ],
  "limitations": [
    "This draft is not executable and does not authorize Docker or repository code."
  ]
}
```

### Human Promotion Requirements

Promotion is a manual, separately auditable action that is outside this design
phase. A human must verify all of the following before creating a new approved
approval file:

1. The repository identity, commit, repo-relative scope, phase, kind, cwd,
   argv, environment allowlist, shell setting, image identity, and network
   policy exactly match the reviewed draft.
2. The profile and risk tier still apply to the exact commit. Any repository
   change invalidates the draft.
3. The candidate is not T4 or T5, does not require a shell, network, direct
   URL/VCS source, credential access, host HOME, Docker socket, or an
   unreviewed binary.
4. A command-level behavior policy is valid, default-deny, and compatible with
   the exact command and digest-pinned image lock.
5. The reviewer creates a distinct approval file with a different status and
   records their external review evidence. No programmatic draft-to-approved
   conversion is permitted.

An incomplete scope, stale commit, missing policy, schema mismatch, or any
attempt to reuse Phase 2 approval for Phase 3 is fail-closed.

## Schema Versioning And Validation

The examples in this document introduce design-only report kinds. They do
not alter the existing `sandbox-report` schema or its `schema_version`.

`schema_version` identifies the versioned field contract for a report family.
`report_kind` identifies which report shape within that contract is being
carried, for example `sandbox_unknown_repo_profile` or a future
`sandbox_approval_draft`.

| Report kind | Required fields | Optional fields |
| --- | --- | --- |
| `sandbox_unknown_repo_profile` | `schema_version`, `report_kind`, `mode`, `execution_permitted`, `repo_scope`, `profile`, `risk`, `redaction`, `limitations` | Safe counts, categories, repo-relative finding handles, non-authoritative notes. |
| `sandbox_approval_draft` | `schema_version`, `report_kind`, `status`, `approved`, `execution_permitted`, `candidate_key`, `exact_match_key`, `repo_scope`, `source_profile_report`, `source_risk_tier`, `candidate`, `execution_constraints`, `behavior_policy`, `promotion_requirements` | Reviewer-facing safe notes and non-secret evidence handles. |

All required fields must be complete, typed, and normalized. `phase`, `kind`,
`cwd`, `argv`, `env_allowlist`, `shell`, image identity, and network policy are
security-decision fields; omission or ambiguity is a validation BLOCK.

Consumers reject absent or unsupported `schema_version`, unknown `report_kind`,
missing required field, unknown security-relevant field, and any unknown
field that could affect a safety decision. The default schema rule is
`additionalProperties: false`. A future extension needs a version bump and a
consumer update before it can influence execution. Breaking field, default,
or safety-semantics changes require a new major schema version; additive
informational fields require a new compatible version and remain rejected by
older consumers until explicitly supported. There is no best-effort parsing of
approval or behavior documents.

## Controlled Static Dry-Run Integration

`sandbox.dry_run` composes profile/risk tier, approval draft, behavior-policy
validation, and image-lock validation against controlled local fixtures. It
does not execute the repository or connect any component to Docker or a
runner. Its `static_controlled_dry_run` result is static gate readiness only,
not live readiness or a safety conclusion.

T0 remains candidate-free; T1-T3 retain
`draft_requires_human_review`, `approved: false`, and
`execution_permitted: false`; T4/T5 retain no live candidate. The dry-run
checks exact candidate binding fields and the future image-lock contract,
including profile tier, identity, phase, argv, environment, shell/network
denial, policy schema version, image-lock schema version, and image identity
fields. Runner integration remains a later phase.

The implemented draft schema is
`schemas/sandbox-approval-draft.schema.json`; it uses
`schema_version: "0.1-draft"` and `report_kind: "sandbox_approval_draft"`.
Its candidate key includes repository identity, commit, phase, kind, cwd,
argv, environment allowlist, shell, network policy, image-policy placeholder,
and behavior-policy schema/version. Therefore a Phase 2 draft cannot match a
Phase 3 candidate, and a change to any of those fields requires a different
draft. T4/T5 reports deliberately set `live_candidate_generated: false` and
do not carry a candidate key.

See [sandbox-behavior-policy.md](sandbox-behavior-policy.md) for the behavior
contract and [sandbox-image-distribution.md](sandbox-image-distribution.md) for
the image-lock contract.

## Controlled Static Transition Validation

The test-only static transition helper accepts only the repository's controlled
unknown-profile fixtures. It checks profile, draft, in-memory approval shape,
image lock, normalized evidence, behavior policy, and their static bindings,
then emits `sandbox_static_transition_validation`. It does not create an
approval file or connect a runner. Its result always retains
`approved: false`, `execution_permitted: false`, and disabled Docker/observer
flags. A PASS is static agreement only; live execution remains out of scope.
