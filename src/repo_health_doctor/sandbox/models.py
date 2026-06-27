from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
import re
from typing import Any


STATUS_PASS = "pass"
STATUS_WARN = "warn"
STATUS_BLOCK = "block"
STATUS_VALUES = (STATUS_PASS, STATUS_WARN, STATUS_BLOCK)

SEVERITY_DETAIL_PASS = "PASS"
SEVERITY_DETAIL_WARN_LOW = "WARN-low"
SEVERITY_DETAIL_WARN_MED = "WARN-med"
SEVERITY_DETAIL_WARN_HIGH = "WARN-high"
SEVERITY_DETAIL_BLOCK = "BLOCK"
SEVERITY_DETAIL_VALUES = (
    SEVERITY_DETAIL_PASS,
    SEVERITY_DETAIL_WARN_LOW,
    SEVERITY_DETAIL_WARN_MED,
    SEVERITY_DETAIL_WARN_HIGH,
    SEVERITY_DETAIL_BLOCK,
)

PHASE_0_STATIC = "phase0_static"
PHASE_1_FETCH = "phase1_fetch"
PHASE_1B_STRACE_SMOKE = "phase1b_strace_smoke"
PHASE_1_5_RESCAN = "phase1_5_rescan"
PHASE_2_INSTALL_PROBE = "phase2_install_probe"
PHASE_3_RUNTIME_PROBE = "phase3_runtime_probe"

UNSAFE_SHELL_PREFIXES = (
    ("sh", "-c"),
    ("bash", "-c"),
    ("cmd", "/c"),
    ("powershell", "-command"),
    ("pwsh", "-command"),
)

# Match shell launch forms in repository script metadata, including whitespace
# variants and absolute shell paths. The sandbox does not execute these forms.
UNSAFE_SHELL_SCRIPT_PATTERN = re.compile(
    r"(?i)(?:^|[\s;|&()])(?:[A-Za-z0-9_./-]*/)?(?:sh|bash|cmd|powershell|pwsh)\s+(?:-c|/c|-command)(?:\s|$)"
)


def normalize_repo_cwd(value: str | None) -> str:
    if value is None:
        return "."
    normalized = value.replace("\\", "/").strip()
    if not normalized or normalized == ".":
        return "."
    if normalized.startswith("/"):
        raise ValueError("cwd must be repo-relative")
    pure_path = PurePosixPath(normalized)
    if any(part == ".." for part in pure_path.parts):
        raise ValueError("cwd must not escape the repository root")
    collapsed = pure_path.as_posix().lstrip("./")
    return collapsed or "."


def _normalize_argv(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ValueError("argv must be a non-empty string array")
    argv: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ValueError("argv entries must be non-empty strings")
        argv.append(item)
    return tuple(argv)


def _normalize_env_allowlist(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ValueError("env_allowlist must be a string array")
    allowlist: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ValueError("env_allowlist entries must be non-empty strings")
        allowlist.append(item)
    return tuple(allowlist)


def has_unsafe_shell_argv(argv: tuple[str, ...]) -> bool:
    lowered = tuple(token.lower() for token in argv)
    return any(lowered[: len(prefix)] == prefix for prefix in UNSAFE_SHELL_PREFIXES)


def script_uses_explicit_shell(value: str) -> bool:
    return UNSAFE_SHELL_SCRIPT_PATTERN.search(value) is not None


@dataclass(frozen=True)
class ExecutionCommand:
    phase: str
    kind: str
    cwd: str
    argv: tuple[str, ...]
    env_allowlist: tuple[str, ...]
    shell: bool = False
    evidence: tuple[tuple[str, str], ...] = ()
    approved: bool = False

    @classmethod
    def from_mapping(
        cls,
        payload: dict[str, Any],
        *,
        approved: bool = False,
    ) -> "ExecutionCommand":
        if not isinstance(payload, dict):
            raise ValueError("command payload must be an object")
        phase = payload.get("phase")
        kind = payload.get("kind")
        if not isinstance(phase, str) or not phase.strip():
            raise ValueError("command phase is required")
        if not isinstance(kind, str) or not kind.strip():
            raise ValueError("command kind is required")
        cwd = normalize_repo_cwd(payload.get("cwd", "."))
        argv = _normalize_argv(payload.get("argv"))
        env_allowlist = _normalize_env_allowlist(payload.get("env_allowlist", []))
        shell = bool(payload.get("shell", False))
        if shell:
            raise ValueError("shell execution is not supported in the current sandbox contract")
        if has_unsafe_shell_argv(argv):
            raise ValueError("explicit shell launch is not supported in the current sandbox contract")

        evidence_pairs: list[tuple[str, str]] = []
        raw_evidence = payload.get("evidence", {})
        if isinstance(raw_evidence, dict):
            for key, value in sorted(raw_evidence.items()):
                if isinstance(key, str) and isinstance(value, str):
                    evidence_pairs.append((key, value))

        return cls(
            phase=phase.strip(),
            kind=kind.strip(),
            cwd=cwd,
            argv=argv,
            env_allowlist=env_allowlist,
            shell=False,
            evidence=tuple(evidence_pairs),
            approved=approved,
        )

    def approval_key(self) -> tuple[str, str, str, tuple[str, ...], tuple[str, ...], bool]:
        return (self.phase, self.kind, self.cwd, self.argv, self.env_allowlist, self.shell)

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "phase": self.phase,
            "kind": self.kind,
            "cwd": self.cwd,
            "argv": list(self.argv),
            "env_allowlist": list(self.env_allowlist),
            "shell": self.shell,
            "approved": self.approved,
        }
        if self.evidence:
            payload["evidence"] = {key: value for key, value in self.evidence}
        return payload


@dataclass(frozen=True)
class SkippedCommand:
    reason: str
    phase: str | None = None
    kind: str | None = None
    cwd: str | None = None
    argv: tuple[str, ...] = ()
    shell: bool = False
    detail: str | None = None

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "reason": self.reason,
            "shell": self.shell,
        }
        if self.phase is not None:
            payload["phase"] = self.phase
        if self.kind is not None:
            payload["kind"] = self.kind
        if self.cwd is not None:
            payload["cwd"] = self.cwd
        if self.argv:
            payload["argv"] = list(self.argv)
        if self.detail is not None:
            payload["detail"] = self.detail
        return payload


@dataclass(frozen=True)
class SandboxCheck:
    id: str
    status: str
    severity_detail: str
    confidence: str
    phase: str
    summary: str
    evidence: dict[str, Any]
    limitations: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status,
            "severity_detail": self.severity_detail,
            "confidence": self.confidence,
            "phase": self.phase,
            "summary": self.summary,
            "evidence": self.evidence,
            "limitations": list(self.limitations),
        }
