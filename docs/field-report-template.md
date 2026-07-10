# Field Report Template

This template records repo-health-doctor observations for future field
research review. It separates observed evidence, limitations, human review
status, and publication status. It does not turn repo-health-doctor output into
a safety proof or a maliciousness determination.

Use this template only after the
[field research safety protocol](field-research-safety-protocol.md) has been
accepted for the review. Keep subject identifiers redacted or synthetic until
publication review explicitly approves naming.

## Purpose

- Record repo-health-doctor observations in a consistent private draft.
- Keep observed evidence separate from interpretation and publication status.
- Preserve limitations, scanner availability, and untested areas.
- Require human review before publication or subject naming.
- State that repo-health-doctor is not a safety proof and not a maliciousness
  determination.

## Required Sections

Every field report must include:

- Report status
- Subject handling
- Reviewed material
- Bound commit / artifact
- Commands not executed
- Scanner availability
- Observed indicators
- Gate decision
- Confidence
- Limitations
- What was not tested
- Redaction checklist
- Human review status
- Publication status
- Responsible disclosure / maintainer contact status
- Final wording approval

## Template

```text
report_status:
  report_id: <synthetic-or-redacted-id>
  report_version: 1
  report_status: draft | review_requested | reviewed | closed
  publication_status: internal_only | private_report | disclosure_pending | publish_blocked | publish_allowed_after_review

subject_handling:
  subject_identifier: <redacted-or-synthetic>
  subject_type: repository | package | tool | agent-plugin | unknown
  subject_named_publicly: false
  naming_review_status: not_requested | requested | approved | rejected

reviewed_material:
  material_type: local_checkout | supplied_archive | supplied_report | synthetic_fixture
  source_reference_redacted: <redacted-or-synthetic>
  review_scope: <bounded scope>
  collection_mode: non_executing | imported_evidence | mocked_fixture

bound_commit_or_artifact:
  commit: <commit-or-unbound>
  artifact_digest: <digest-or-not-recorded>
  worktree_state: unchanged | modified | unknown | not_applicable
  binding_limitations:
    - <limitation>

commands_not_executed:
  target_command_executed: false
  install_or_package_manager_executed: false
  clone_or_download_automated: false
  live_scanner_executed: false
  notes:
    - <non-executing review note>

scanner_availability:
  gitleaks: unavailable | not_run | completed | limited
  osv_scanner: unavailable | not_run | completed | limited
  trivy: unavailable | not_run | completed | limited
  scanner_unavailable_is_not_pass: true

observed_indicators:
  - indicator_id: <synthetic-id>
    source: repo-health-doctor | imported_evidence | human_note
    summary: <redacted observation>
    evidence_boundary: <scope>

gate_decision:
  verdict: allow_limited | warn | quarantine | block | unknown
  execution_authorized: false
  reason_summary:
    - <redacted reason>

confidence:
  level: low | medium | high
  rationale:
    - <why this confidence level is bounded>

limitations:
  - <scanner coverage / evidence / binding / review limitation>

what_was_not_tested:
  - <not tested>

redaction_checklist:
  raw_secret_present: false
  personal_information_present: false
  private_path_present: false
  local_address_present: false
  raw_stdout_or_stderr_present: false
  raw_scanner_report_present: false
  token_like_string_present: false

human_review_status:
  reviewed: false
  reviewer: <redacted-or-role>
  review_notes:
    - <redacted note>

responsible_disclosure_or_maintainer_contact_status:
  considered: false
  status: not_applicable | pending | completed | deferred
  notes:
    - <redacted note>

final_wording_approval:
  approved: false
  approver: <redacted-or-role>
  allowed_summary: <redacted summary or empty>
```

## Allowed Wording

Use evidence-first wording:

- "repo-health-doctor reported ..."
- "observed indicators"
- "review recommended"
- "quarantine recommended"
- "not enough evidence to lower risk"
- "not a safety proof"
- "not a maliciousness determination"
- "needs human review"
- "scanner unavailable is not PASS"
- "no findings is not proof of safety"

## Disallowed Wording

Do not use these as conclusions or public labels:

- "malicious confirmed"
- "scam"
- "criminal"
- "definitely malicious"
- "steals tokens"
- "safe"
- "clean"
- "proven safe"
- "no risk"
- "guaranteed"

The word "malicious" may appear only when describing disallowed wording or
when saying that repo-health-doctor does not make a maliciousness
determination.

## Publication Gate

Set `publication_status: publish_blocked` when any of these are true:

- redaction is incomplete.
- human review before publication is missing.
- a real subject is named without review.
- a raw secret, personal information, private path, local address, raw output,
  raw scanner report, or token-like string exists.
- exploit instructions, target command execution steps, install steps, clone
  automation, download automation, or package-manager steps exist.
- limitations are missing.
- scanner unavailable, no evidence, no packages, no results, or no findings is
  presented as PASS or as a safety proof.
- repo-health-doctor output is presented as a maliciousness determination.

Set `publication_status: publish_allowed_after_review` only when all of these
are true:

- evidence and subject identifiers are redacted or naming was explicitly
  approved.
- the report is evidence-based and non-accusatory.
- limitations and what was not tested are included.
- scanner availability is included.
- human review before publication is complete.
- final wording approval is recorded.

Publication approval is a human decision. This template records the decision;
it does not grant permission by itself.
