# Security Model

## Mental Model

- repo-health-doctor is a local-first pre-execution safety gate and evidence
  normalizer for AI agents and developers reviewing unfamiliar repositories.
- Static health is scoped evidence only. `PASS` means no blocking finding in
  the current check scope; it is not proof of safety.
- A gate decision is a review outcome that surfaces limitations and required
  actions. It remains separate from execution authorization and keeps
  `execution_authorized=false`.
- Imported scanner results are evidence inputs. Scanner silence, scanner
  failure, missing binding, missing limitations, or degraded observation must
  not become authorization to run repository-derived commands.
- `sandbox-run` is the core v1 runtime for one bounded argv in a locked-down
  disposable Docker workspace. It produces bounded evidence, not complete
  containment or unrestricted permission to continue.

## What This Tool Protects

- Raw secret candidates are not printed in text, JSON, or Markdown output
- Private paths are reported as neutral categories
- Local IPs are reported as neutral categories
- Policy allow targets are not echoed back as raw values
- Tracked generated artifacts, cache candidates, and env file candidates can be blocked before publish
- The tool works local-first and does not depend on network transmission

## What This Tool Does Not Protect

- Complete secret scanning coverage
- Dependency vulnerability detection
- GitHub settings auditing
- Legal or license review
- Prevention of malicious contributors
- Enterprise DLP use cases
- Security proof for unknown repositories or unknown code
- Docker-based complete malware containment; syscall/process observation is
  still incomplete even when gated runtime-hook probes are enabled

## Redaction Contract

- Secret candidates, token candidates, private paths, local IPs, and policy allow target raw values must not appear in text, JSON, or Markdown output
- Reports should expose `rule_id`, `severity`, repo-relative path, line number, size, category, and safe policy metadata only
- `redacted: true` means the raw value was replaced by a category or fixed mask
- Debugging output must not print raw values to stdout, JSON, CI artifacts, or issue templates

## Change Management

- If redaction behavior changes, update tests and any affected golden outputs together
- Keep `schema_version` stable unless the maintainer explicitly approves a contract change
- Explain backward-compatibility impact in the change description when output behavior intentionally changes
- Update the public docs, tests, and golden outputs together when sandbox,
  schema, fail-closed, or redaction behavior changes.
- Static design notes or partial fixture coverage must not be treated as live
  proof. Docker runtime proof, observer capture, live execution, approval
  promotion, and `approved: true` artifacts remain explicit human-approval
  boundaries.

## Sandbox Boundary

- `sandbox` remains plan-first by default, and repo-derived Docker runtime commands require explicit opt-in plus exact-match approval before any gated execution path is considered
- approval files are validated against normalized `argv` candidates before any execution gate is considered
- disposable workspace materialization and cleanup now happen locally before report generation
- disposable HOME / cache / tmp now include honeypot file and environment placement for secret-access observation; report argv, output, and error summaries redact honeypot values and generic credential-like patterns, with a final report-wide redaction pass as defense in depth
- Docker argv, disposable workspace, and Phase 1 fetch plans are emitted as dry-run contracts
- fixed harmless Docker preflight is separately gated by `--run-preflight` plus either a digest-pinned registry image or an explicitly sanctioned local image with a matching full image ID
- registry digest image references remain the preferred execution input; tag-only images are not treated as safe by default, `latest` tags are not sanctioned, and sandbox execution never performs image pulls
- local sanctioned images require explicit opt-in plus exact full-image-ID match against `docker image inspect`, and reports must retain the tag / expected ID / actual ID evidence together with portability limitations
- Phase 1 dependency fetch can run only with `--run-phase1`, an accepted execution image reference, and a successful Docker preflight in the same invocation
- Python Phase 1 planning can derive tool-generated binary-only fetch candidates from `requirements*.txt`, safe subsets of `poetry.lock` / `uv.lock`, and safe subsets of `pyproject.toml` `build-system.requires`; ambiguous or unsupported sources remain skipped fail-closed
- A controlled fixture that uses only repo-local backend code and `build-system.requires = []` can treat Phase 1 as `not_required` only when no VCS, direct URL, editable, or local path dependency source is detected; report limitations must surface the `skipped-safe` rationale and the `no_external_fetch_required` decision
- Phase 1.5 fetched artifact static rescan separates install-time risk from ordinary packaged capability: lifecycle scripts, unsafe dependency sources, source-distribution build steps, and obfuscated dynamic execution remain BLOCK, while ordinary library network/env/cert/path references can be reported as WARN or INFO only
- Phase 1.5 also distinguishes install-time build/backend code from packaged test/support code inside wheels: backend-path dynamic execution combined with env/credential/path references remains BLOCK, while packaged `tests/` helpers with the same primitives stay review-worthy WARN and do not by themselves prove an install-time path
- Phase 1.5 also rescans controlled fetched archives for npm tarball lifecycle metadata, Python `setup.py` / build-backend traces, URL / IP, secret-path, environment sweep, and suspicious-exec markers; when a `no_external_fetch_required` Phase 1 decision yields zero fetched artifacts and zero dependency-source risks, Phase 1.5 may report `not_required` with a `no_artifacts_to_rescan` rationale, otherwise missing artifacts and unreadable artifacts never establish PASS
- WARN findings in Phase 1.5 are still review items rather than safety confirmation, and Phase 2 / Phase 3 require that Phase 1.5 report no BLOCK findings before any later execution path is considered
- The Phase 2 / Phase 3 prior-phase dependency gates may treat `Phase 1: not_required` plus `Phase 1.5: not_required` as cleared, but that exception does not relax exact-match approval, Docker preflight, image policy, or observer readiness
- Python build metadata can now yield tool-generated Phase 2 install probe candidates, but those candidates remain approval-gated before any execution path is considered
- Phase 2 install probes require an approval file; approval is exact-command scoped by normalized `phase` / `kind` / `cwd` / `argv` / `env_allowlist` / `shell`, not a repo-wide permission grant
- Phase 2 or Phase 3 approval files can also bind a sanctioned local image tag, expected full image ID, network policy, and controlled-fixture scope; mismatches keep execution fail-closed and do not authorize any other phase
- observer planning now reports runtime-hook readiness first, then uses Docker preflight to harmlessly probe whether the selected image exposes `strace`; runtime-hook-only coverage is never treated as PASS
- `strace -V` in preflight is only an availability check; the separate target-wrap smoke runs a fixed harmless process under `strace` to confirm log generation, collection, and parsing without touching repo-derived commands
- Phase 2 / Phase 3 runner paths are explicit-opt-in and approval-gated, and can run only after prior phase gates pass; `strace` + runtime-hook observation can improve confidence, but runtime-hook-only or missing syscall logs still degrades the result to WARN at best
- harmless preflight can confirm that `strace` is available inside the selected image, but full syscall tracing is still only exercised when a later dynamic probe wraps a target process
- successful target-wrap smoke only proves tracing for that harmless fixed target and does not establish safety for unknown repository commands; Phase 2 / Phase 3 still require separate approval coverage
- approval does not relax `strace`, fail-closed gating, redaction, or later phase prerequisites; it only authorizes the exact reviewed command when every other gate is already satisfied
- No approval means no repo-derived install or runtime command runs, including Python `setup.py` / build backend / editable candidates and `python -m pytest`; VCS and local-path Python dependency sources are excluded from Phase 1 fetch planning
- `shell: true`, shell strings, and `sh -c` / `bash -c` candidates are rejected or skipped rather than normalized into a shell command
- The canonical `sandbox.dynamic_evidence` object records phase status, result/event/syscall counts, observer mode, degradation reasons, confidence, and limitations without treating unsupported, skipped, or degraded observation as safety confirmation
- runtime-hook event emission is covered by controlled local tests, but that does not prove full live coverage for repo-derived dynamic probes
- host absolute paths are redacted into logical handles in report output
- dynamic observation limits are reported explicitly instead of being treated as PASS
- This is Docker-based host-execution risk reduction, not a complete malware
  sandbox; Docker daemon, mount, kernel, image, and platform-configuration
  risks remain outside its guarantee
- `sandbox-run` is the core unknown-repo execution runtime. It can bind to the
  gate and execution authorization artifacts, and it still supports a legacy
  exact approval artifact for compatibility.
- `sandbox-run` copies the repository into a disposable workspace and mounts
  that copy at `/workspace`; it does not mount the original repository path as
  writable and does not mount host HOME, credentials, SSH agent, or Docker
  socket. It also mounts a disposable `/out` directory for command artifacts.
- `sandbox-run` uses `--pull=never` and fails closed when the approved image is
  not available locally. Tag-based images remain less reproducible than
  digest-pinned images and are reported as a limitation.
- A successful `sandbox-run` report is bounded execution evidence only. It is
  not proof of safety, not complete containment, and not execution
  authorization beyond the exact command. Successful execution does not mean
  safe, and successful execution does not mean authorization to continue.

## Unknown Repository Design Boundary

- `sandbox-profile` implements only the plan-only unknown-repository profile
  and risk-tier assignment. `sandbox-approval-draft` consumes that static
  profile to emit a non-executable review report; neither command executes
  repository-derived commands, pulls images, or starts Docker
- An unknown-repository candidate remains
  `draft_requires_human_review` with `approved: false`; a draft is not an
  approval file and cannot be promoted automatically
- Unknown-repository behavior-policy validation and static evidence verdicts
  are available, but live execution remains unavailable until a separate
  implementation validates an exact human-created approval, digest-pinned
  image lock, observer evidence, and every existing sandbox gate
- T4/T5 indicators, shell/network requests, direct URL or VCS sources,
  credential access, host HOME, Docker socket access, native binaries, and
  obfuscation are default-deny; T4/T5 require dedicated-VM guidance rather
  than a Docker live candidate
- Future profile, draft, behavior-policy, and image-lock documents are closed
  schema contracts: missing or unsupported versions, incomplete safety fields,
  and unknown safety-relevant fields fail closed
- See [sandbox-unknown-repo-workflow.md](sandbox-unknown-repo-workflow.md),
  [sandbox-behavior-policy.md](sandbox-behavior-policy.md), and
  [sandbox-image-distribution.md](sandbox-image-distribution.md) for the
  design-only contracts
