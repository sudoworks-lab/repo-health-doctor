# Authorization Artifact Discovery

Authorization artifact discovery is an experimental `gate-check` convenience
for a narrow local workflow. It does not create execution authorization. A
successful discovery result must still pass the existing authorization
validator, exact-argv checks, and the other gate boundaries.

## Candidate and read contract

Discovery considers exactly one candidate at the Git top-level:
`.repo-health-doctor.authorization.json`.

- The supplied directory must resolve to the Git top-level exactly. A
  repository subdirectory is refused; discovery does not search parent,
  sibling, or nested directories.
- The candidate must be untracked, a regular file, and not a symlink.
- The default maximum size is 64 KiB. The bounded read also reads at most one
  byte beyond that limit so growth during the read is refused.
- The reader uses `O_NOFOLLOW` when the platform provides it, compares the
  `lstat` and descriptor `fstat` state before reading, and compares the state
  and byte count again after reading.
- The content must be a JSON object. Raw content, Git stderr, and local paths
  are not part of the refusal result or public report.

The artifact is ignored by default. The repository `.gitignore` contains this
example so an operator can create the local candidate without adding it to a
commit.

## Machine-readable refusal reasons

The implementation module
`repo_health_doctor.gate.authorization_discovery` is the source of truth for
these exact reason strings. The contract test checks that every code reason is
present in this table.

| Reason | Meaning |
| --- | --- |
| `tracked_refused` | Git reports the candidate as tracked. |
| `not_a_git_repo` | The supplied directory is not the exact Git top-level, or is not a Git repository. |
| `symlink_refused` | The candidate is a symlink, including a broken symlink or a replacement detected as a symlink at open time. |
| `not_found` | The single top-level candidate does not exist. |
| `parse_failed` | The bounded content is invalid JSON or is valid JSON but not an object. |
| `too_large` | The configured limit is invalid, the candidate is over 64 KiB by default, or the bounded read grows past the limit. |
| `git_error` | Git cannot be executed, times out, returns an unexpected failure, or returns an unusable top-level value. |
| `file_changed` | The candidate is not a regular file, cannot be opened or stat-ed safely, or changes during the lstat/open/read checks. |

Refusal is fail-closed. A caller must not reinterpret one reason as a
different reason, retry a different candidate, or treat a refusal as approval.

## `gate-check` integration

The CLI invokes discovery only when trailing argv (trailing command arguments)
are present after `--`, no explicit authorization artifact was supplied, and
`--no-discover` was not requested.

- Explicit `--authorization` input always has priority and prevents discovery.
- Without trailing arguments, the existing authorization-missing behavior is
  preserved; the candidate is not read.
- `--no-discover` prevents discovery and does not prevent explicit
  authorization validation.
- There is one candidate and there is no fallback. A nested candidate,
  alternate filename, parent directory, or other path cannot be selected.
- A discovered object is passed to the existing authorization validator. The
  discovery result alone never changes `execution_authorized` and never
  authorizes command execution.

## Residual risk

The lstat/open/fstat/bounded-read sequence reduces observable file replacement
and growth races but does not eliminate local-writer races. This is a
TOCTOU residual risk: another process may alter the filesystem around the
discovery boundary in ways that the checks cannot completely exclude.
Discovery is therefore only a bounded input lookup. Exact command, repository
subject, commit/tree, `snapshot_id`, manifest fingerprint, expiry, and execution
authorization must be checked again by the downstream authorization and
runtime boundaries.

The contract is intentionally single-file and no-fallback. A refusal or a
missing candidate must remain a fail-closed result rather than a reason to
search more broadly.
