# Private Candidate Review Workflow

This workflow defines how a future review team may organize a private
candidate before any external publication, naming, or execution decision. It is
not a target collection workflow and does not automate clone, download,
install, live scanning, or target command execution.

repo-health-doctor output remains observed evidence. It is not a safety proof,
not a maliciousness determination, and not permission to publish a claim about
a real subject.

## Purpose

- Create a private intake record before handling a real candidate.
- Define what is in scope and what is explicitly prohibited.
- Keep candidate review stopped until redaction, evidence limits, and human
  review are complete.
- Produce a private candidate review packet, not a public accusation.

## Intake Fields

Every candidate review starts with these fields:

```text
candidate_id: <redacted-or-synthetic-id>
source_type: repository | package | tool | agent-plugin | report | unknown
source_reference_redacted: <redacted-or-synthetic-reference>
why_reviewed:
  - <non-accusatory reason>
who_requested_review: <role-or-redacted-requester>
review_scope: metadata_only | supplied_report | local_non_executing_checkout | synthetic_fixture
allowed_actions:
  - create private review packet
  - record redacted observations
  - run docs-only or imported-evidence checks when separately approved
prohibited_actions:
  - no clone automation
  - no install
  - no download automation
  - no target command execution
  - no package-manager execution
  - no exploit reproduction
  - no raw secret or personal information collection
publication_status: internal_only | private_report | disclosure_pending | publish_blocked | publish_allowed_after_review
```

The candidate record must use redacted or synthetic identifiers until human
review explicitly approves real subject naming.

## Workflow Stages

1. `intake_created`
   - Create the redacted private intake record.
   - Record why the candidate was reviewed without accusation.
   - Set `publication_status: internal_only`.

2. `scope_reviewed`
   - Confirm allowed and prohibited actions.
   - Confirm whether any evidence can be collected without execution.
   - Stop if the requested action would require clone automation, install,
     download automation, package-manager execution, target command execution,
     or exploit reproduction.

3. `evidence_collected`
   - Record only redacted observations and bounded evidence.
   - Preserve scanner unavailable, no evidence, and no findings as limitations.
   - Do not save raw scanner reports, raw stdout, raw stderr, raw match text,
     private paths, local addresses, credentials, or personal information.

4. `report_drafted`
   - Draft the report with
     [field-report-template.md](field-report-template.md).
   - Separate observed indicators from confidence, limitations, and what was
     not tested.
   - Keep `execution_authorized=false` when a gate decision is present.

5. `redaction_reviewed`
   - Confirm no secret, personal information, private path, local address,
     raw output, raw scanner report, or token-like string remains.
   - Confirm no real subject is named unless naming review is complete.

6. `human_reviewed`
   - A human reviewer checks evidence, wording, limitations, and scope.
   - If review is incomplete, set `publication_status: publish_blocked`.

7. `disclosure_decision`
   - Consider private report, maintainer contact, responsible disclosure, or no
     external contact.
   - Record the decision without public naming unless approved.

8. `publication_decision`
   - Use
     [publication-review-checklist.md](publication-review-checklist.md).
   - Publish nothing unless the checklist records review, redaction,
     limitations, disclosure consideration, and final wording approval.

## Hard Stops

Stop the workflow and set `publication_status: publish_blocked` when any of
these appear:

- clone automation, install, download automation, package-manager execution, or
  target command execution is requested without explicit separate approval.
- publication is requested before human review.
- a real subject is named without naming review.
- raw secrets, personal information, private paths, local addresses, raw
  scanner output, raw stdout, raw stderr, or token-like strings are present.
- exploit reproduction, bypass guidance, payload details, or secret collection
  steps are requested.
- scanner unavailable, no evidence, no packages, no results, or no findings is
  being treated as PASS.
- repo-health-doctor output is being used as a maliciousness determination.

## Output

The private workflow produces:

- private candidate review packet.
- synthetic or redacted field report.
- publication gate decision.
- next human action.

Recommended packet shape:

```text
candidate_id: <redacted-or-synthetic-id>
current_stage: intake_created | scope_reviewed | evidence_collected | report_drafted | redaction_reviewed | human_reviewed | disclosure_decision | publication_decision
field_report: <path-or-redacted-reference>
publication_gate_decision: internal_only | private_report | disclosure_pending | publish_blocked | publish_allowed_after_review
next_human_action:
  - <review action>
automation_boundary:
  auto_publish: false
  auto_accuse: false
  auto_execute: false
```

## Future Automation Note

Automation may help organize private packets, route review tasks, or check that
required fields exist. It must not auto-publish, auto-accuse, auto-name a real
subject, auto-clone, auto-install, auto-download, run target commands, or turn
repo-health-doctor output into a maliciousness determination.
