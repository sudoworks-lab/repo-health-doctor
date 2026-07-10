# Publication Review Checklist

Use this checklist before any public write-up, advisory, blog post, issue, or
social post based on repo-health-doctor field research material. It is a human
review checklist, not publication automation.

repo-health-doctor output is observed evidence. It is not a safety proof, not a
maliciousness determination, and not permission to name a real subject.

## Purpose

- Prevent unreviewed publication of a real subject.
- Keep write-ups evidence-based, redacted, and non-accusatory.
- Confirm limitations, disclosure consideration, and final wording approval.
- Block public posts that include raw output, personal data, exploit
  instructions, or target command execution steps.

## Required Checks

Mark each item before publication:

```text
evidence_bound_to_commit_or_artifact: yes | no | not_applicable
non_accusatory_language_used: yes | no
limitations_included: yes | no
raw_secret_present: no
personal_information_present: no
private_path_present: no
local_address_present: no
raw_scanner_output_present: no
raw_stdout_or_stderr_present: no
token_like_string_present: no
exploit_instructions_present: no
target_command_execution_steps_present: no
install_or_package_manager_steps_present: no
scanner_unavailable_treated_as_pass: no
no_findings_treated_as_safety_proof: no
human_review_completed: yes | no
disclosure_or_maintainer_contact_considered: yes | no | not_applicable
final_wording_approved: yes | no
```

Required statements in the draft:

- Scanner unavailable is not PASS.
- No findings is not proof of safety.
- repo-health-doctor is not a maliciousness determination.
- A gate decision is not execution authorization.
- Human review before publication is required.

## Publication Statuses

Use one of these statuses:

- `internal_only`: private review material only.
- `private_report`: share only through an approved private reporting path.
- `disclosure_pending`: wait for disclosure, maintainer contact, or reviewer
  decision.
- `publish_blocked`: do not publish.
- `publish_allowed_after_review`: publication may proceed only after recorded
  redaction, limitations, disclosure consideration, and final wording approval.

Set `publish_blocked` when:

- human review is missing.
- redaction is incomplete.
- limitations are missing.
- a real subject is named without review.
- scanner unavailable, no evidence, no packages, no results, or no findings is
  treated as PASS or safety proof.
- raw secrets, personal information, private paths, local addresses, raw
  scanner output, raw stdout, raw stderr, or token-like strings remain.
- exploit instructions, bypass guidance, payload details, target command
  execution steps, install steps, download steps, clone automation, or
  package-manager steps appear.
- repo-health-doctor output is used as a maliciousness determination.

Set publish_allowed_after_review only when:

- evidence is commit-bound or artifact-bound, or the binding limitation is
  clearly stated.
- the report is redacted.
- the wording is non-accusatory.
- limitations and what was not tested are included.
- disclosure or maintainer contact was considered.
- a human reviewer approved the final wording and publication status.

## SNS-Specific Guardrails

For social posts:

- no quote-post dogpiling.
- no naming without review.
- no screenshots containing secrets, personal data, private paths, local
  addresses, raw scanner output, raw stdout, or raw stderr.
- no "confirmed malicious" style claims.
- no sensational wording or public pile-on prompts.
- summarize observed evidence and limitations, not accusations.
- link only to reviewed material that has passed the publication gate.

If the evidence is incomplete or ambiguous, do not post.

## Reviewer Sign-Off

Record reviewer sign-off before any publication:

```text
reviewer: <role-or-redacted-name>
date: <date-or-not-recorded>
decision: internal_only | private_report | disclosure_pending | publish_blocked | publish_allowed_after_review
required_redactions:
  - <redaction item or none>
final_allowed_summary:
  - <non-accusatory evidence summary or empty>
```

Reviewer sign-off must confirm:

- no raw secret, personal information, private path, local address, raw output,
  or token-like string remains.
- no exploit instructions, bypass guidance, payload details, target command
  execution steps, install steps, download steps, clone automation, or
  package-manager steps remain.
- scanner unavailable is not PASS.
- no findings is not proof of safety.
- repo-health-doctor output is not presented as a maliciousness determination.
