# Unknown Repository Runner Preflight Design

## Status

The current implementation includes a non-executing runner preflight skeleton.
It authorizes no runner, Docker, pull, inspect, Phase 2/3 live execution,
approval promotion, observer capture, or unknown repository command.

`sandbox_runner_preflight` uses `schema_version: "0.1-draft"` and
`mode: non_executing_preflight`. It consumes supplied static mappings only and
checks approval validation, image lock validation, image lock-binding
validation, behavior policy validation, normalized observer evidence
validation, behavior-policy binding validation, and static transition
validation in that order. Missing, mismatched, expired, degraded, or
unsupported inputs fail closed.

All preflight reports keep `execution_permitted: false`, `runner_connected:
false`, `docker_contacted: false`, `docker_pull_performed: false`,
`docker_inspect_performed: false`, `docker_run_performed: false`,
`network_contacted: false`, `observer_capture_performed: false`, and
`phase_live_performed: false`. A preflight PASS means only that the supplied
static artifacts agree; it is not live execution authorization and does not
prove an unknown repository is safe.

## Image Preparation And Distribution

Registry digest-pinned images are primary. A human-operated setup workflow,
outside repository analysis, may acquire a reviewed digest and record the
digest, full local image ID, tool versions, platform, source/build evidence,
and timestamp in an image lock. The lock validator validates document
structure only; it is not proof that a local image currently matches.

Future execution preparation must verify the approved lock's digest, full
image ID when applicable, tool inventory, platform, and current container
runtime update attestations. Runtime must use `--pull=never`; a mismatch,
absence, ambiguous tool version, unsupported platform, or unavailable
verification blocks before command construction.

The implemented static lock-binding verifier is an earlier document-only gate:
it compares supplied approval, image-lock, behavior-policy, and candidate-key
material, then emits a non-executable PASS/WARN/BLOCK report. It does not
contact Docker, inspect an image, pull, run, build a runner command, or grant
runner authorization. Its PASS therefore means only that static bindings
match; runtime image verification remains a future operator/runner gate.

The static image-attestation skeleton records the future runtime image
verification shape and can compare supplied attestation data with an image
lock. It still does not perform Docker inspect and is not part of runner
preflight execution yet. A matching attestation validation report is not live
authorization.

Digest rotation is a new reviewed lock, not an in-place permission change. It
invalidates approvals bound to the prior digest/ID. Local sanctioned images
remain dev-only, explicit opt-in, full-ID-bound, portability-limited, and
never the primary production distribution path. Docker Desktop/Engine, runc,
and containerd currency is an operator attestation precondition, not a fact
the current tool obtains.

## Incremental Implementation Plan

| Commit | Purpose / candidate files | Tests and done condition | Dependencies | Live connection / prohibitions |
| --- | --- | --- | --- | --- |
| 1 | Approval promotion schema and static validator; `schemas/`, `sandbox/approval_*`, tests/docs. | Closed artifact validates only with all human/review/revocation fields; drafts cannot become approved automatically. | Existing draft/profile contracts. | No live; no artifact creation command. |
| 2 | Image preparation preflight contract and lock-binding verifier; image-lock module/tests/docs. **Implemented as static verification only.** | Digest/ID/tool/platform/runtime-flag equality is checked against supplied static evidence. | Image lock schema, approval schema design. | No Docker inspect/pull/run. |
| 3 | Normalized observer evidence schema and static validator; `schemas/`, behavior policy, tests/docs. **Implemented as static validation only.** | Missing/unknown/degraded evidence fails closed before evaluator PASS; schema validation is not a safety verdict. | Behavior policy evaluator. | No observer process, runner connection, Docker, or live capture. |
| 4 | Behavior-policy binding verifier; approval/policy/normalized-evidence/candidate-key cross-check module and tests. **Implemented as static verification only.** | Exact policy ID/fingerprint and phase/kind/cwd/argv fingerprint/shell/network/observer requirement mismatch blocks; missing, degraded, or parse-failed evidence blocks. | Commits 1-3. | No runner, Docker, observer capture, or live command. |
| 5 | Dry-run-to-approval transition tests using controlled fixtures only. **Implemented as static verification only.** | Profile, draft, in-memory approval shape, image/policy/evidence bindings, and final transition report are checked; T1/T2 remain human-gated and T3 exception/T4/T5 cases fail closed. | Commits 1-4. | No approval writing, runner, Docker, observer capture, or live commands. |
| 6 | Runner preflight skeleton with no target command construction. **Implemented as non-executing static preflight only.** | It accepts supplied static inputs and emits a non-executable PASS/WARN/BLOCK preflight report while keeping execution disabled. | Commits 1-5; operational image-preparation procedure. | No Docker action, observer capture, runner connection, network, or live phase. |
| 6a | Image attestation static report skeleton. **Implemented as static validation only.** | Supplied attestation shape and image-lock digest/ID/platform/tool/runtime bindings validate without contacting Docker. | Commit 7 design and image lock schema. | No Docker inspect/pull/run, runner connection, or live execution. |
| 7 | Controlled single-command live gate, separately authorized. **Designed in `docs/sandbox-single-command-live-gate-design.md`; not implemented.** | All independent gates, observer capture, image verification, and disposal cleanup are demonstrated against a new controlled fixture. | Commits 1-6 plus explicit maintainer approval. | This is the first possible live milestone; no unknown repository rollout. |

Before commit 7, maintainers must decide approval artifact ownership and
revocation workflow, reviewed image preparation/rotation ownership, observer
raw-evidence retention, T3 exception authority, and the isolation platform.
