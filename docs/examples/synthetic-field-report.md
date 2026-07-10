# Synthetic Field Report Example

This example is fully synthetic. It does not identify a real repository,
author, company, account, package, organization, or URL. It is not for external
publication.

## Report Status

```text
report_id: synthetic-field-report-a
subject_identifier: Synthetic Candidate A
subject_type: agent-plugin
report_status: reviewed
publication_status: internal_only
publication_note: internal example only / not for external publication
subject_named_publicly: false
```

## Reviewed Material

```text
material_type: synthetic fixture summary
source_reference_redacted: synthetic-only
review_scope: redacted static summary and synthetic gate sidecar
collection_mode: non_executing
target_command_executed: false
install_or_package_manager_executed: false
clone_or_download_automated: false
live_scanner_executed: false
```

No target command was executed. No install, download, package manager, clone
automation, live scanner, remediation, or hook change occurred.

## Bound Commit / Artifact

```text
commit: unbound synthetic example
artifact_digest: not recorded
worktree_state: not_applicable
binding_limitations:
  - synthetic example only
  - not evidence about a real subject
```

## Scanner Availability

```text
gitleaks: not_run
osv_scanner: not_run
trivy: not_run
scanner_unavailable_is_not_pass: true
```

Scanner unavailable is not PASS. No findings is not proof of safety. This
example does not claim scanner coverage.

## Observed Indicators

```text
observed_indicators:
  - indicator_id: synthetic-indicator-1
    source: repo-health-doctor
    summary: repo-health-doctor reported a synthetic package lifecycle hook shape.
    evidence_boundary: synthetic static summary only
  - indicator_id: synthetic-indicator-2
    source: repo-health-doctor
    summary: repo-health-doctor reported a synthetic environment-access shape.
    evidence_boundary: synthetic static summary only
```

The indicators are observations. They are not a maliciousness determination.
They are not a safety proof. They need human review before any use outside a
private review packet.

## Gate Decision

```text
verdict: quarantine
execution_authorized: false
reason_summary:
  - quarantine recommended for the synthetic example because multiple bounded
    indicators require review.
```

The gate decision is a review result, not execution authorization.

## Confidence

```text
level: low
rationale:
  - the example is synthetic
  - no real subject was reviewed
  - no live scanners were run
  - evidence is not commit-bound to a real target
```

## Limitations

- Synthetic example only.
- No real repository, package, account, company, maintainer, or author was
  reviewed.
- No live scanner result is represented.
- No runtime behavior was observed.
- No dependency resolution was performed.
- No findings is not proof of safety.
- repo-health-doctor is not a maliciousness determination.

## What Was Not Tested

- target command execution.
- install or package-manager behavior.
- clone or download automation.
- live scanner behavior.
- runtime network behavior.
- maintainer response or disclosure handling.

## Redaction Checklist

```text
raw_secret_present: false
personal_information_present: false
private_path_present: false
local_address_present: false
raw_stdout_or_stderr_present: false
raw_scanner_report_present: false
token_like_string_present: false
```

## Human Review Status

```text
reviewed: true
reviewer: documentation-role
review_result: example wording only
```

The review confirms only that this example is synthetic, redacted, and
non-accusatory.

## Publication Status

```text
publication_status: internal_only
publication_note: internal example only / not for external publication
publication_gate_decision: publish_blocked
block_reasons:
  - synthetic example is not evidence about a real subject
  - no disclosure path applies
  - no public naming approval exists
```

This report must remain internal example material. It must not be reused as a
public claim about a real subject.
