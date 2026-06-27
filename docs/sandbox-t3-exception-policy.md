# Unknown Repository T3 Exception Policy

## Default Position

T3 is `needs_review`, never auto-approved. A future exception is one exact
command for one commit and must use the same command-scoped approval contract
as T1/T2 plus the additional controls in this document. This design does not
implement an exception or enable execution.

## Preconditions To Consider An Exception

All of the following are required before human review may consider promotion:

- Phase 1 and Phase 1.5 are completed under their future gates, or a documented
  `not_required` decision applies without unsafe dependency sources.
- The exact lifecycle/build/toolchain surface has a bounded purpose and an
  exact argv. Shell remains false and network remains none.
- No direct URL/VCS dependency, credential path, host HOME, Docker socket,
  native binary, obfuscation, persistence, or destructive indicator remains.
  Any such signal is T4/T5 territory, not a T3 exception.
- The behavior policy denies subprocesses by default. A limited subprocess
  exception names exact normalized binaries and a strict event cap.
- A dedicated image lock, exact digest, platform, tool inventory, and stronger
  isolation rationale are reviewed. Local dev-only images are insufficient for
  a T3 exception unless a separate human policy explicitly permits the
  development context.

Build backend or lifecycle candidates need a reviewable explanation of why the
specific backend/script is required, which files it can write, expected return
code, timeout, and why a non-executing alternative is unavailable. Generic
install commands, broad test commands, shell wrappers, or command discovery
are not sufficient.

## Required Exception Fields

The future T3 approval artifact adds `t3_exception` with a rationale,
reviewed surface categories, Phase 1/1.5 evidence handles, isolation level,
subprocess allowance/limit, expected write prefixes, named reviewers, and a
short expiry. It must also record why T4/T5 indicators are absent. Omission is
fail-closed.

Human review confirms the reviewed commit is clean, the profile tier remains
T3, the exact candidate key still matches, image/behavior bindings match, and
observer requirements cannot be downgraded. Any change invalidates the
exception. A dedicated VM or stronger isolation is required whenever the
surface cannot be bounded to the disposable workspace and exact allowlists.
