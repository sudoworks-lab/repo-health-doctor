# Unknown Repository Approval Transition Design

## Status And Boundary

This document now has a static schema/validator for a future human-created
approval artifact. It does not implement approval promotion, write an approval
file, set `approved: true`, or connect a runner. Existing `sandbox_approval_draft` reports remain
`draft_requires_human_review`, `approved: false`, and
`execution_permitted: false`.

An approval is command-scoped evidence of a human decision, not a repository
permission grant. It does not relax image, behavior, observer, redaction, or
prior-phase gates.

## Proposed Artifact Contract

The proposed artifact uses `schema_version: "0.1-draft"` and
`report_kind: "sandbox_unknown_repo_command_approval"`. `approved: true` is
permitted only in a separately created, human-authored artifact after all
required fields validate. It is never derived or written automatically from a
draft.

Required fields:

- artifact metadata: `schema_version`, `report_kind`, `approval_id`,
  `created_at`, `expires_at`, `created_by`, `reviewed_by`, `reviewed_at`, and
  a review-evidence handle;
- source draft: draft schema/version, report kind, candidate key, exact-match
  key, source profile reference, repository identity, commit, risk tier, and
  a `clean_verified` working-tree assertion;
- command scope: one phase, kind, cwd, argv, env allowlist, `shell: false`,
  `network_policy: none`, and an explicit single-command scope;
- behavior binding: behavior policy report kind, schema version, policy ID,
  and exact policy-binding fingerprint;
- image binding: image lock report kind/schema version, lock ID, registry
  digest or sanctioned full local image ID, platform, tool-version inventory,
  and `pull_policy: never` runtime constraint;
- lifecycle controls: revocation state, invalidation reasons, and expiry.

The artifact must use closed objects. Missing, unsupported, ambiguous, or
unknown security-relevant fields invalidate it. Raw paths, secret-like values,
raw observer logs, and reviewer credentials are never rendered.

`schemas/sandbox-unknown-repo-command-approval.schema.json` and the static
validator can read and reject/accept a supplied artifact shape. A validation
PASS is not runner authorization and does not create, promote, or use the
artifact. T4/T5 are rejected; T3 requires complete exception metadata; commit,
candidate, behavior policy, image lock, expiry, and reviewer mismatches fail
closed.

The separate static lock-binding verifier additionally compares the supplied
artifact with an image-lock document and behavior-policy document. It must see
the exact lock ID and digest/full local image ID, platform/tool inventory,
policy ID/fingerprint, command binding, and fixed runtime constraints. This
duplication is intentional: an artifact-shape PASS does not override a later
binding mismatch. The verifier neither creates an artifact nor authorizes a
runner, and its report remains `execution_permitted: false`.

## Controlled Static Transition Tests

`sandbox_static_transition_validation` composes controlled local fixture
profile/draft data with an in-memory approval-shaped mapping, image lock,
normalized observer evidence, and both static binding verifiers. It neither
generates nor saves an approval artifact: the in-memory `approved: true` shape
exists only to exercise its validator, while the final transition report always
has `approved: false` and `execution_permitted: false`.

The final PASS means only that the supplied static bindings agree. It is not
runner authorization, Docker readiness, observer coverage, or permission for a
live command. The transition helper rejects non-controlled fixture paths and
does not contact Docker, a runner, strace, runtime hooks, or the network.

The non-executing runner preflight consumes an already supplied approval
artifact and static transition report as inputs. It does not generate an
approval artifact, promote a draft, write `approved: true`, or make an approval
executable. Even when the preflight verdict is PASS, its report remains
`execution_permitted: false`; runner execution gates are a later phase.

`docs/sandbox-single-command-live-gate-design.md` defines the later controlled
single-command live gate boundary. That gate must revalidate the approval
artifact before any controlled live attempt, but it still must not generate an
approval, promote a draft, or allow Phase 2 and Phase 3 approvals to authorize
each other.

## Transition Conditions

A reviewer may consider promotion only when all conditions hold:

1. The source draft has `draft_requires_human_review`, is not itself an
   approval file, and its candidate key equals the proposed exact-match key.
2. Repository identity and exact commit match the profile and draft. A dirty
   working tree is rejected by default; a later exception process must not
   silently substitute a changed worktree for the reviewed commit.
3. The risk tier is T1 or T2, or a separately documented T3 exception applies.
   T4 and T5 are never promotable.
4. The candidate has exactly one phase and command: phase, kind, cwd, argv,
   env allowlist, shell, network policy, image identity, and behavior policy
   binding all match.
5. The image lock and behavior policy have passed their static validators and
   their versions/binding fields match the artifact.
6. A human records why the command is needed, why the tier remains acceptable,
   expiry, and external review evidence.

T1/T2 are never auto-promoted. A new commit, dirty worktree, profile identity
change, risk-tier increase, candidate-key mismatch, image digest/ID change,
behavior-policy change, expiration, revocation, or any phase/kind/cwd/argv/env
/shell/network change invalidates the approval.

## Phase Separation And Fixture Boundary

Phase 2 and Phase 3 approvals are distinct artifacts. A Phase 2 approval
cannot authorize a Phase 3 candidate even if argv happens to match. The phase
is part of both candidate key and artifact scope.

Controlled-fixture approvals are test fixtures for the existing sandbox
runner. They are not unknown-repository artifacts, cannot be copied or renamed
into one, and must not carry unknown-repository profile/risk semantics. An
unknown-repository approval always binds the unknown profile, reviewed commit,
behavior policy, and image lock.

## Revocation

Revocation is immediate and fail-closed. The future validator must reject an
artifact when it is expired, revoked, superseded, malformed, or has any
invalidation reason. Revocation records require timestamp, actor, reason
category, and a safe evidence handle; they must not contain raw secret or host
data.
