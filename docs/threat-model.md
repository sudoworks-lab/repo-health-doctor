# Threat Model

This document positions repo-health-doctor as a pre-execution safety gate for
AI agents and developers touching unknown repositories.

It does not prove safety. It prevents false confidence.

## Scope

repo-health-doctor focuses on evidence collection, limitation recording, and
fail-closed gate decisions before an agent or developer runs repository-derived
commands.

Handles? values:

- `yes`: currently handled in a bounded, tested way
- `partial`: some evidence or gate exists, but coverage is incomplete
- `no`: not handled by repo-health-doctor
- `future`: designed or planned, but not implemented as a stable capability

| Threat | Handles? | How | Limitations |
| --- | --- | --- | --- |
| hardcoded secrets | partial | Native secret-like pattern checks and external scanner evidence can block or raise risk. | Native detection is heuristic. Dedicated secret scanners remain important. No finding is not proof that no secret exists. |
| raw secret leakage in reports | yes | Reports use redacted finding categories and tests cover raw-value avoidance. External scanner redaction flags block unsafe imported results. | Full raw scanner output redaction pipeline is not complete. |
| malicious postinstall | partial | Sandbox planning and unknown-repo profiling identify install/runtime candidates and require gated approval. | Static indicators and controlled probes are not complete malware analysis. |
| dependency confusion / malicious package behavior | partial | Unknown repo profile, Phase 1/1.5 planning, and external risk rules can surface dependency and install-chain signals. | Package ecosystem resolution and malicious package behavior coverage are incomplete. |
| outbound exfiltration attempt | partial | Sandbox behavior policy and observer evidence can treat network evidence as a blocker when observed. External evidence chains credential/network signals. | Observer degradation or absence prevents confidence. Network behavior not observed is not safe evidence. |
| GitHub Actions token abuse | partial | `zizmor-style` adapter foundation and risk rules cover broad permissions, unpinned actions, and CI token risk signals. | Real zizmor output compatibility is version-dependent. actionlint/zizmor are not replaced. |
| pull_request_target + untrusted checkout | partial | External risk rules map this chain to elevated risk and human review. | Requires suitable scanner or synthetic evidence; not a complete CI policy engine. |
| known vulnerable dependency | partial | External scanner result schema, risk rules, and the OSV imported evidence adapter can represent supplied vulnerability evidence, including redacted real-output-compatible fixtures. | Compatibility is version scoped. repo-health-doctor does not run OSV-Scanner or manage vulnerability databases. |
| SBOM transparency | future | External scanner mapping reserves Syft/SBOM evidence as dependency inventory input. | SBOM generation and validation are not implemented as a stable adapter. |
| Docker escape | partial | Sandbox and Docker scanner plans avoid Docker socket, host HOME, credentials, and direct repo writable mounts. The experimental `sandbox-run` add-on adds approval-bound Docker argv, `--network none`, `--pull=never`, disposable workspace copy, and bounded redacted output evidence. | Docker is not a complete malware sandbox; kernel, daemon, platform, and image trust risks remain. A completed sandbox-run is not a safety proof or unrestricted execution authorization. |
| host credential access | partial | Disposable workspace, redaction contracts, sandbox constraints, and readiness gates prohibit credential mounts and host HOME access. | Static checks cannot prove code will not attempt host credential access unless execution is observed under policy. |
| AI agent prompt/workflow injection | partial | Pre-execution gate encourages plan-only review before generated commands and workflow changes. | Prompt injection semantics are not fully modeled. Human review remains required for ambiguous instructions. |
| unknown behavior due to degraded observer | partial | Degraded observer state is not PASS and remains a limitation or blocker. | Absence of observation cannot prove absence of behavior. |
| scanner unavailable | partial | External scanner validators and risk mapper treat scanner failure, parse failure, unsupported version, or timeout as unknown/block rather than PASS. | Coverage depends on supplied scanner result fields and adapter maturity. |
| raw scanner output leakage | partial | External scanner schemas track raw-output flags; Docker path discards bounded raw output after normalization. | Full redaction pipeline and report UX hardening remain future work. |
| commit mismatch / unbound evidence | partial | Imported report validator can fail closed on expected commit mismatch and tracks binding/trust fields. | Future evidence model needs stronger subject identity, tree hash, and signature fields. |

## Non-Goals

repo-health-doctor is not a replacement for dedicated scanners, endpoint
detection, or complete malware sandboxing. It is the gate that keeps scanner
silence, missing evidence, and degraded observation from becoming false
confidence.
