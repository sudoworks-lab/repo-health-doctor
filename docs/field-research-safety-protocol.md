# Field Research Safety Protocol

This protocol defines how repo-health-doctor evidence may be used before any
researcher writes about a real suspicious OSS project, standalone tool, or
AI-agent-oriented tool. It is a safety, evidence, wording, and publication
gate. It is not a workflow for collecting targets.

repo-health-doctor is not a safety proof and not a maliciousness classifier. It
reports observed evidence, missing evidence, scanner limitations, and gate
recommendations that require human review.

## C-Phase Artifacts

Use these documents together:

- C-1: [field-report-template.md](field-report-template.md) records observed
  evidence, limitations, review status, and publication status.
- C-2: [examples/synthetic-field-report.md](examples/synthetic-field-report.md)
  shows an internal-only synthetic report with no real subject.
- C-3:
  [private-candidate-review-workflow.md](private-candidate-review-workflow.md)
  defines private intake, hard stops, and review stages.
- C-4: [publication-review-checklist.md](publication-review-checklist.md)
  defines the public write-up gate and final wording sign-off.

## Purpose

- Keep field research evidence-based, redacted, and reviewable.
- Prevent scanner silence from becoming a safety claim.
- Prevent a repo-health-doctor result from becoming a public accusation.
- Preserve a path for private reporting, maintainer contact, or responsible
  disclosure when a real subject may be affected.

## Non-Goals

This protocol must not be used for:

- public shaming or pile-ons.
- naming a real repository, author, company, account, or maintainer before
  human review.
- declaring that a subject is malicious, fraudulent, criminal, or confirmed
  harmful based only on repo-health-doctor output.
- publishing attack instructions, exploit reproduction steps, payloads,
  bypass guidance, or secret collection methods.
- collecting secrets or personal information.
- automating clone, download, install, package-manager, or execution steps.
- live execution of unknown repository code.

## Evidence Language

Use non-accusatory language:

- "observed indicators"
- "repo-health-doctor reported"
- "the evidence is consistent with"
- "needs review"
- "quarantine recommended"
- "scanner unavailable"
- "scope limited"
- "not tested"

Avoid accusatory conclusions:

- do not write "malicious" as a conclusion.
- do not write "confirmed scam" or "fraud confirmed".
- do not write "criminal" or imply criminal intent.
- do not describe a person, company, account, or repository as an attacker.

No findings is not proof of safety. A report without findings means only that
no finding was reported in the reached scope, tool configuration, scanner version,
database freshness, and evidence boundary. Scanner unavailable is not PASS. No
evidence is not PASS. A gate decision is not execution authorization.

## Handling External Subjects

Before any real repository, package, tool, author, company, account, or
maintainer is identified outside the private review context:

- require human review before publication.
- verify that evidence is redacted and bounded.
- consider private reporting, maintainer contact, or responsible disclosure.
- avoid spreading unverified claims on social media or chat channels.
- keep subject identifiers redacted or synthetic until publication review
  explicitly approves naming.
- record who reviewed the wording, evidence, limitations, and disclosure path.

If the evidence is incomplete, unbound, or ambiguous, publish nothing that lets
readers identify the real subject.

## Safe Collection

The safe collection posture is non-executing by default:

- do not automate clone, install, download, package-manager, or execution
  steps.
- do not run an unknown repository target command.
- do not run package lifecycle hooks or remediation commands.
- do not run live scanners unless a separate reviewed plan explicitly allows
  the network, cache, privacy, and binary provenance implications.
- do not persist raw scanner reports, raw stdout, or raw stderr.
- do not save raw secret values, raw match text, source snippets, local host
  details, private paths, local addresses, personal data, emails, credentials,
  or token-like strings.
- do not include exploit payloads, bypass details, or secret exfiltration
  steps in notes, fixtures, docs, or public write-ups.

When evidence is collected from an already available local checkout, bind the
review to the target commit when possible. If commit binding is unavailable,
dirty, ambiguous, or not human-reviewed, treat the evidence as limited and do
not use it for public naming.

## Report Template

Use this private draft shape before any public write-up:

```text
subject_identifier: <redacted-or-synthetic>
subject_type: repository | package | tool | agent-plugin | unknown
review_scope: local checkout | supplied archive | supplied report | unknown
target_commit: <commit-or-unbound>
worktree_state: unchanged | modified | unknown
collection_mode: non-executing | imported evidence | mocked fixture
observed_evidence:
  - <redacted indicator summary>
repo_health_doctor_result:
  status: pass | warn | block | unknown
  gate_decision: allow_limited | warn | quarantine | block | unknown
scanner_limitations:
  - <scanner unavailable / coverage / freshness / scope limitation>
confidence: low | medium | high
what_was_not_tested:
  - <not tested>
human_review_status: not reviewed | reviewed privately | approved for naming
publication_status: do not publish | private report | public draft | published
disclosure_path: none | maintainer contact | private advisory | public note
```

The draft must use redacted or synthetic identifiers until human review
approves a real subject name. It must not include raw logs, raw scanner output,
raw paths, secrets, personal information, source snippets, payloads, or
step-by-step reproduction of harmful behavior.

## Publication Gate

Do not publish when any of these are true:

- a secret, credential, personal detail, email address, private host detail,
  local address, raw path, raw output, or token-like string remains.
- evidence is not bound to a reviewed commit or the binding limitation is not
  clearly stated.
- scanner unavailable, no evidence, no results, no packages, or no findings is
  presented as PASS or safety proof.
- reproduction requires running unknown code, installing dependencies, running
  package managers, or showing exploit steps.
- the draft contains accusatory wording, names a real subject without approval,
  or invites public pile-on behavior.
- limitations, confidence, and what was not tested are missing.
- human review before publication has not happened.
- private report, maintainer contact, or responsible disclosure has not been
  considered for a real affected subject.

Publication may proceed only when all of these are true:

- identifiers and evidence are redacted unless naming was explicitly approved.
- the write-up is evidence-based and non-accusatory.
- limitations, scanner availability, confidence, and untested areas are clear.
- no target command execution, install, clone automation, exploit
  reproduction, payload, or bypass guidance is included.
- the evidence path is reviewable and commit-bound when possible.
- human review before publication is complete and recorded.

## Public Write-Up Checklist

Before a blog post, advisory, issue, or social post leaves private review:

- Confirm the draft uses observed evidence language, not conclusions about
  intent.
- Confirm no real subject is named unless human review approved naming.
- Confirm no secret, personal information, private path, local address, email
  address, credential, token-like string, raw scanner output, raw stdout, or
  raw stderr remains.
- Confirm no exploit reproduction, payload, bypass, or secret collection
  instructions are present.
- Confirm scanner limitations and no-findings limitations are explicit.
- Confirm scanner unavailable, no evidence, no packages, no results, and no
  findings are not treated as PASS.
- Confirm what was not tested is present.
- Confirm the report says whether private reporting, maintainer contact, or
  responsible disclosure was considered.
- Confirm a human reviewer approved the wording and publication status.

## C-Phase Completion

- C-1: synthetic field report template:
  [field-report-template.md](field-report-template.md).
- C-2: synthetic field report example:
  [examples/synthetic-field-report.md](examples/synthetic-field-report.md).
- C-3: private candidate review workflow:
  [private-candidate-review-workflow.md](private-candidate-review-workflow.md).
- C-4: publication gate and public write-up checklist:
  [publication-review-checklist.md](publication-review-checklist.md).
