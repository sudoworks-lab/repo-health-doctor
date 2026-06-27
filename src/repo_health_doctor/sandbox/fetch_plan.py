from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import subprocess
from typing import Any

from .docker import build_container_command_argv
from .models import ExecutionCommand, PHASE_1_FETCH, SkippedCommand
from .workspace import MaterializedWorkspace

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10+ should provide tomllib
    tomllib = None  # type: ignore[assignment]


PYTHON_REQUIREMENTS_GLOB = "requirements*.txt"
NODE_FETCH_ENV_ALLOWLIST = ("HOME", "NPM_CONFIG_CACHE", "TMPDIR", "XDG_CACHE_HOME")
PYTHON_FETCH_ENV_ALLOWLIST = ("HOME", "PIP_CACHE_DIR", "TMPDIR", "XDG_CACHE_HOME")
DEFAULT_PHASE1_TIMEOUT_SECONDS = 180
SAFE_PYTHON_PACKAGE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
SAFE_PYTHON_PACKAGE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._!+-]*$")
SAFE_PYTHON_REQUIREMENT_SPEC = re.compile(
    r"^\s*"
    r"([A-Za-z0-9][A-Za-z0-9._-]*)"
    r"("
    r"\s*(?:===|==|!=|<=|>=|<|>|~=)\s*[A-Za-z0-9*._+-]+"
    r"(?:\s*,\s*(?:===|==|!=|<=|>=|<|>|~=)\s*[A-Za-z0-9*._+-]+)*"
    r")?"
    r"\s*$"
)


@dataclass(frozen=True)
class Phase1CommandResult:
    kind: str
    argv: tuple[str, ...]
    return_code: int | None
    status: str
    timed_out: bool
    stdout_summary: str
    stderr_summary: str
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "kind": self.kind,
            "argv": list(self.argv),
            "return_code": self.return_code,
            "status": self.status,
            "timed_out": self.timed_out,
            "stdout_summary": self.stdout_summary,
            "stderr_summary": self.stderr_summary,
        }
        if self.error is not None:
            payload["error"] = self.error
        return payload


def _has_python_manifests(root: Path) -> bool:
    if (root / "pyproject.toml").is_file():
        return True
    for file_name in ("setup.py", "setup.cfg", "poetry.lock", "uv.lock"):
        if (root / file_name).is_file():
            return True
    return any(path.is_file() for path in root.glob(PYTHON_REQUIREMENTS_GLOB))


def _find_node_lockfile(root: Path) -> str | None:
    for lockfile in ("package-lock.json", "npm-shrinkwrap.json"):
        if (root / lockfile).is_file():
            return lockfile
    return None


def _load_toml(path: Path) -> dict[str, Any]:
    if tomllib is None:
        return {}
    try:
        payload = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _scan_requirement_line(line: str) -> str | None:
    stripped = line.strip()
    lowered = stripped.lower().split(";", 1)[0].strip()
    if not stripped or stripped.startswith("#"):
        return None
    if lowered.startswith(("-e ", "--editable ")):
        return "editable_dependency"
    if lowered.startswith(("git+", "hg+", "svn+", "bzr+")) or " @ git+" in lowered:
        return "vcs_dependency"
    if lowered.startswith(("http://", "https://")) or " @ http://" in lowered or " @ https://" in lowered:
        return "direct_url_dependency"
    if lowered.startswith(("./", "../", "/", "file:")):
        return "local_path_dependency"
    if " @ file:" in lowered or " @ ." in lowered or " @ /" in lowered:
        return "local_path_dependency"
    return None


def _unsupported_requirement_reasons(path: Path) -> list[str]:
    reasons: list[str] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ["requirements_read_failed"]
    for line in lines:
        reason = _scan_requirement_line(line)
        if reason and reason not in reasons:
            reasons.append(reason)
    return reasons


def _canonical_python_package_spec(name: Any, version: Any) -> str | None:
    if not isinstance(name, str) or not isinstance(version, str):
        return None
    normalized_name = name.strip()
    normalized_version = version.strip()
    if not normalized_name or not normalized_version:
        return None
    if not SAFE_PYTHON_PACKAGE_NAME.fullmatch(normalized_name):
        return None
    if not SAFE_PYTHON_PACKAGE_VERSION.fullmatch(normalized_version):
        return None
    return f"{normalized_name}=={normalized_version}"


def _canonical_build_requirement_spec(requirement: Any) -> str | None:
    if not isinstance(requirement, str):
        return None
    match = SAFE_PYTHON_REQUIREMENT_SPEC.fullmatch(requirement)
    if match is None:
        return None
    package_name = match.group(1)
    specifiers = re.sub(r"\s+", "", match.group(2) or "")
    return f"{package_name}{specifiers}"


def _poetry_package_source_reason(source: Any) -> str | None:
    if source in (None, {}):
        return None
    if not isinstance(source, dict):
        return "unsupported_source_metadata"
    source_type = source.get("type")
    if not isinstance(source_type, str) or not source_type.strip():
        return "unsupported_source_metadata"
    lowered = source_type.strip().lower()
    if lowered in {"git", "url", "file", "directory", "path"}:
        return f"{lowered}_dependency"
    return "unsupported_source_metadata"


def _uv_package_source_reason(source: Any) -> str | None:
    if source in (None, {}):
        return None
    if not isinstance(source, dict):
        return "unsupported_source_metadata"
    if "registry" in source:
        return None
    if isinstance(source.get("type"), str) and source["type"].strip().lower() == "registry":
        return None
    if "editable" in source:
        return "editable_dependency"
    if "git" in source:
        return "git_dependency"
    if "path" in source or "directory" in source:
        return "local_path_dependency"
    if "url" in source:
        return "local_or_remote_source"
    return "unsupported_source_metadata"


def _build_lockfile_download_commands(
    *,
    manifest_name: str,
    package_specs: list[str],
) -> list[ExecutionCommand]:
    if not package_specs:
        return []
    return [
        ExecutionCommand(
            phase=PHASE_1_FETCH,
            kind="dependency_fetch",
            cwd=".",
            argv=("python", "-m", "pip", "download", "--only-binary=:all:", *package_specs),
            env_allowlist=PYTHON_FETCH_ENV_ALLOWLIST,
            evidence=(("manifest", manifest_name), ("binary_only", "required")),
        )
    ]


def _build_poetry_lock_fetch_plan(root: Path) -> tuple[list[ExecutionCommand], list[SkippedCommand], list[str]]:
    lock_path = root / "poetry.lock"
    payload = _load_toml(lock_path)
    if not payload:
        return [], [], ["poetry.lock was detected but could not be parsed into a safe Phase 1 fetch plan."]

    packages = payload.get("package")
    if not isinstance(packages, list):
        return [], [], ["poetry.lock was detected but did not expose a supported package list for Phase 1 planning."]

    specs: list[str] = []
    skipped: list[SkippedCommand] = []
    limitations: list[str] = []
    for package in packages:
        if not isinstance(package, dict):
            skipped.append(
                SkippedCommand(
                    phase=PHASE_1_FETCH,
                    kind="dependency_fetch",
                    cwd=".",
                    argv=("python", "-m", "pip", "download", "--only-binary=:all:"),
                    reason="unsupported_python_dependency_source",
                    detail="poetry.lock:malformed_package_entry",
                )
            )
            continue
        reason = _poetry_package_source_reason(package.get("source"))
        name = package.get("name")
        version = package.get("version")
        spec = _canonical_python_package_spec(name, version)
        if reason is not None:
            skipped.append(
                SkippedCommand(
                    phase=PHASE_1_FETCH,
                    kind="dependency_fetch",
                    cwd=".",
                    argv=("python", "-m", "pip", "download", "--only-binary=:all:"),
                    reason="unsupported_python_dependency_source",
                    detail=f"poetry.lock:{name if isinstance(name, str) else 'unknown'}:{reason}",
                )
            )
            continue
        if spec is None:
            skipped.append(
                SkippedCommand(
                    phase=PHASE_1_FETCH,
                    kind="dependency_fetch",
                    cwd=".",
                    argv=("python", "-m", "pip", "download", "--only-binary=:all:"),
                    reason="unsupported_python_dependency_source",
                    detail=f"poetry.lock:{name if isinstance(name, str) else 'unknown'}:invalid_name_or_version",
                )
            )
            continue
        specs.append(spec)

    unique_specs = sorted(dict.fromkeys(specs))
    if skipped:
        limitations.append(
            "poetry.lock included entries that the current sandbox implementation will not fetch in Phase 1."
        )
    if not unique_specs:
        limitations.append("poetry.lock was detected, but no safe binary-only Phase 1 fetch candidates could be generated.")
    return _build_lockfile_download_commands(manifest_name="poetry.lock", package_specs=unique_specs), skipped, limitations


def _build_uv_lock_fetch_plan(root: Path) -> tuple[list[ExecutionCommand], list[SkippedCommand], list[str]]:
    lock_path = root / "uv.lock"
    payload = _load_toml(lock_path)
    if not payload:
        return [], [], ["uv.lock was detected but could not be parsed into a safe Phase 1 fetch plan."]

    packages = payload.get("package")
    if not isinstance(packages, list):
        return [], [], ["uv.lock was detected but did not expose a supported package list for Phase 1 planning."]

    specs: list[str] = []
    skipped: list[SkippedCommand] = []
    limitations: list[str] = []
    for package in packages:
        if not isinstance(package, dict):
            skipped.append(
                SkippedCommand(
                    phase=PHASE_1_FETCH,
                    kind="dependency_fetch",
                    cwd=".",
                    argv=("python", "-m", "pip", "download", "--only-binary=:all:"),
                    reason="unsupported_python_dependency_source",
                    detail="uv.lock:malformed_package_entry",
                )
            )
            continue
        reason = _uv_package_source_reason(package.get("source"))
        name = package.get("name")
        version = package.get("version")
        spec = _canonical_python_package_spec(name, version)
        if reason is not None:
            skipped.append(
                SkippedCommand(
                    phase=PHASE_1_FETCH,
                    kind="dependency_fetch",
                    cwd=".",
                    argv=("python", "-m", "pip", "download", "--only-binary=:all:"),
                    reason="unsupported_python_dependency_source",
                    detail=f"uv.lock:{name if isinstance(name, str) else 'unknown'}:{reason}",
                )
            )
            continue
        if spec is None:
            skipped.append(
                SkippedCommand(
                    phase=PHASE_1_FETCH,
                    kind="dependency_fetch",
                    cwd=".",
                    argv=("python", "-m", "pip", "download", "--only-binary=:all:"),
                    reason="unsupported_python_dependency_source",
                    detail=f"uv.lock:{name if isinstance(name, str) else 'unknown'}:invalid_name_or_version",
                )
            )
            continue
        specs.append(spec)

    unique_specs = sorted(dict.fromkeys(specs))
    if skipped:
        limitations.append("uv.lock included entries that the current sandbox implementation will not fetch in Phase 1.")
    if not unique_specs:
        limitations.append("uv.lock was detected, but no safe binary-only Phase 1 fetch candidates could be generated.")
    return _build_lockfile_download_commands(manifest_name="uv.lock", package_specs=unique_specs), skipped, limitations


def _iter_pyproject_dependency_entries(payload: dict[str, Any]) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    project = payload.get("project")
    if not isinstance(project, dict):
        return entries

    dependencies = project.get("dependencies")
    if isinstance(dependencies, list):
        for index, requirement in enumerate(dependencies):
            if isinstance(requirement, str):
                entries.append((f"project.dependencies[{index}]", requirement))

    optional_dependencies = project.get("optional-dependencies")
    if isinstance(optional_dependencies, dict):
        for group_name, group_requirements in sorted(optional_dependencies.items()):
            if not isinstance(group_name, str) or not isinstance(group_requirements, list):
                continue
            for index, requirement in enumerate(group_requirements):
                if isinstance(requirement, str):
                    entries.append((f"project.optional-dependencies.{group_name}[{index}]", requirement))
    return entries


def _build_pyproject_dependency_source_findings(payload: dict[str, Any]) -> tuple[list[SkippedCommand], list[str]]:
    skipped: list[SkippedCommand] = []
    for location, requirement in _iter_pyproject_dependency_entries(payload):
        reason = _scan_requirement_line(requirement)
        if reason is None:
            continue
        skipped.append(
            SkippedCommand(
                phase=PHASE_1_FETCH,
                kind="dependency_fetch",
                cwd=".",
                argv=("python", "-m", "pip", "download", "--only-binary=:all:"),
                reason="unsupported_python_dependency_source",
                detail=f"pyproject.toml:{location}:{reason}",
            )
        )
    limitations: list[str] = []
    if skipped:
        limitations.append(
            "pyproject.toml dependency metadata included VCS, direct URL, editable, or local path dependency sources; Phase 1 remains fail-closed."
        )
    return skipped, limitations


def _build_pyproject_build_fetch_plan(
    root: Path,
) -> tuple[list[ExecutionCommand], list[SkippedCommand], list[str], dict[str, Any]]:
    payload = _load_toml(root / "pyproject.toml")
    if not payload:
        return [], [], [], {}

    build_system = payload.get("build-system")
    if not isinstance(build_system, dict):
        return [], [], [], {}
    requires = build_system.get("requires")
    if not isinstance(requires, list):
        return [], [], [], {}

    dependency_skipped, dependency_limitations = _build_pyproject_dependency_source_findings(payload)
    if dependency_skipped:
        return [], dependency_skipped, dependency_limitations, {}
    if not requires:
        return (
            [],
            [],
            [
                "skipped-safe: Phase 1 external dependency fetch is not_required because pyproject.toml declares build-system.requires = [] and no external dependency source risk was detected."
            ],
            {
                "status": "not_required",
                "reason": "no_external_fetch_required",
            },
        )

    safe_specs: list[str] = []
    skipped: list[SkippedCommand] = []
    limitations: list[str] = list(dependency_limitations)
    for requirement in requires:
        safe_spec = _canonical_build_requirement_spec(requirement)
        if safe_spec is None:
            detail = requirement if isinstance(requirement, str) and requirement.strip() else "invalid_build_requirement"
            skipped.append(
                SkippedCommand(
                    phase=PHASE_1_FETCH,
                    kind="dependency_fetch",
                    cwd=".",
                    argv=("python", "-m", "pip", "download", "--only-binary=:all:"),
                    reason="unsupported_python_dependency_source",
                    detail=f"pyproject.toml:build-system.requires:{detail}",
                )
            )
            continue
        safe_specs.append(safe_spec)

    unique_specs = sorted(dict.fromkeys(safe_specs))
    if skipped:
        limitations.append(
            "pyproject.toml build-system.requires included entries that the current sandbox implementation will not fetch in Phase 1."
        )
    if not unique_specs:
        return [], skipped, limitations, {}
    return [
        ExecutionCommand(
            phase=PHASE_1_FETCH,
            kind="dependency_fetch",
            cwd=".",
            argv=("python", "-m", "pip", "download", "--only-binary=:all:", *unique_specs),
            env_allowlist=PYTHON_FETCH_ENV_ALLOWLIST,
                evidence=(("manifest", "pyproject.toml"), ("source", "build-system.requires"), ("binary_only", "required")),
        )
    ], skipped, limitations, {}


def _summarize_output(output: str, materialized: MaterializedWorkspace) -> str:
    sanitized = materialized.redact_text(output.strip())
    if not sanitized:
        return ""
    lines = sanitized.splitlines()[:3]
    clipped = " | ".join(lines)
    if len(clipped) > 200:
        return clipped[:197] + "..."
    return clipped


def build_fetch_plan(root: Path) -> dict[str, Any]:
    commands: list[ExecutionCommand] = []
    skipped_commands: list[SkippedCommand] = []
    limitations: list[str] = []
    not_required_status: str | None = None
    not_required_reason: str | None = None

    if (root / "package.json").is_file():
        lockfile = _find_node_lockfile(root)
        argv = (
            "npm",
            "ci",
            "--ignore-scripts",
            "--audit=false",
            "--fund=false",
        )
        if lockfile is None:
            argv = (
                "npm",
                "install",
                "--ignore-scripts",
                "--audit=false",
                "--fund=false",
            )
            limitations.append(
                "Node.js lockfile was not detected; Phase 1 falls back to npm install with scripts disabled."
            )
        commands.append(
            ExecutionCommand(
                phase=PHASE_1_FETCH,
                kind="dependency_fetch",
                cwd=".",
                argv=argv,
                env_allowlist=NODE_FETCH_ENV_ALLOWLIST,
                evidence=(
                    ("manifest", "package.json"),
                    ("lockfile", lockfile or "absent"),
                ),
            )
        )

    python_requirements = sorted(path for path in root.glob(PYTHON_REQUIREMENTS_GLOB) if path.is_file())
    for requirements_path in python_requirements:
        relative_path = requirements_path.relative_to(root).as_posix()
        unsupported = _unsupported_requirement_reasons(requirements_path)
        if unsupported:
            skipped_commands.append(
                SkippedCommand(
                    phase=PHASE_1_FETCH,
                    kind="dependency_fetch",
                    cwd=".",
                    argv=(
                        "python",
                        "-m",
                        "pip",
                        "download",
                        "--only-binary=:all:",
                        "-r",
                        relative_path,
                    ),
                    reason="unsupported_python_dependency_source",
                    detail=f"{relative_path}:{','.join(unsupported)}",
                )
            )
            limitations.append(
                f"Python requirements file {relative_path} includes entries that the current sandbox implementation will not fetch in Phase 1."
            )
            continue
        commands.append(
            ExecutionCommand(
                phase=PHASE_1_FETCH,
                kind="dependency_fetch",
                cwd=".",
                argv=(
                    "python",
                    "-m",
                    "pip",
                    "download",
                    "--only-binary=:all:",
                    "-r",
                    relative_path,
                ),
                env_allowlist=PYTHON_FETCH_ENV_ALLOWLIST,
                evidence=(("manifest", relative_path), ("binary_only", "required")),
            )
        )

    poetry_lock_exists = (root / "poetry.lock").is_file()
    uv_lock_exists = (root / "uv.lock").is_file()

    if _has_python_manifests(root) and not python_requirements:
        if poetry_lock_exists and uv_lock_exists:
            skipped_commands.append(
                SkippedCommand(
                    phase=PHASE_1_FETCH,
                    kind="dependency_fetch",
                    cwd=".",
                    argv=("python", "-m", "pip", "download", "--only-binary=:all:"),
                    reason="python_fetch_plan_not_generated",
                    detail="ambiguous_python_lockfiles:poetry.lock,uv.lock",
                )
            )
            limitations.append(
                "Python manifests were detected with both poetry.lock and uv.lock; Phase 1 planning remains fail-closed until one lockfile source is selected."
            )
        elif uv_lock_exists:
            uv_commands, uv_skipped, uv_limitations = _build_uv_lock_fetch_plan(root)
            commands.extend(uv_commands)
            skipped_commands.extend(uv_skipped)
            limitations.extend(uv_limitations)
        elif poetry_lock_exists:
            poetry_commands, poetry_skipped, poetry_limitations = _build_poetry_lock_fetch_plan(root)
            commands.extend(poetry_commands)
            skipped_commands.extend(poetry_skipped)
            limitations.extend(poetry_limitations)
        else:
            pyproject_commands, pyproject_skipped, pyproject_limitations, pyproject_metadata = _build_pyproject_build_fetch_plan(root)
            if pyproject_commands or pyproject_skipped or pyproject_limitations or pyproject_metadata:
                commands.extend(pyproject_commands)
                skipped_commands.extend(pyproject_skipped)
                limitations.extend(pyproject_limitations)
                if pyproject_metadata.get("status") == "not_required":
                    not_required_status = "not_required"
                    not_required_reason = str(pyproject_metadata.get("reason", "no_external_fetch_required"))
            else:
                skipped_commands.append(
                    SkippedCommand(
                        phase=PHASE_1_FETCH,
                        kind="dependency_fetch",
                        cwd=".",
                        argv=("python", "-m", "pip", "download", "--only-binary=:all:"),
                        reason="python_fetch_plan_not_generated",
                        detail="supported requirements file not found",
                    )
                )
                limitations.append(
                    "Python manifests were detected without a supported requirements file, supported lockfile, or safe build-system.requires subset."
                )

    commands = sorted(commands, key=lambda item: item.approval_key())
    skipped_commands = sorted(
        skipped_commands,
        key=lambda item: (
            item.phase or "",
            item.kind or "",
            item.cwd or "",
            item.argv,
            item.reason,
        ),
    )
    return {
        "commands": [command.as_dict() for command in commands],
        "skipped_commands": [command.as_dict() for command in skipped_commands],
        "limitations": limitations,
        "not_required_status": not_required_status,
        "not_required_reason": not_required_reason,
    }


def run_phase1_fetch(
    *,
    resolved_base_argv: list[str],
    fetch_commands: list[dict[str, Any]],
    materialized: MaterializedWorkspace,
    timeout_seconds: int = DEFAULT_PHASE1_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    results: list[Phase1CommandResult] = []
    for command in fetch_commands:
        argv = command.get("argv")
        kind = command.get("kind", "dependency_fetch")
        if not isinstance(argv, list) or not argv or any(not isinstance(item, str) for item in argv):
            results.append(
                Phase1CommandResult(
                    kind=str(kind),
                    argv=(),
                    return_code=None,
                    status="invalid_command",
                    timed_out=False,
                    stdout_summary="",
                    stderr_summary="",
                    error="phase1 command must use normalized argv form",
                )
            )
            return {
                "requested": True,
                "performed": False,
                "status": "failed",
                "network_mode": "bridge",
                "timeout_seconds": timeout_seconds,
                "results": [result.as_dict() for result in results],
                "limitations": ["Phase 1 fetch plan contained an invalid command payload."],
            }
        full_argv = build_container_command_argv(
            resolved_base_argv,
            container_argv=tuple(argv),
            network_mode="bridge",
        )
        try:
            completed = subprocess.run(
                full_argv,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                shell=False,
            )
        except FileNotFoundError as exc:
            results.append(
                Phase1CommandResult(
                    kind=str(kind),
                    argv=tuple(argv),
                    return_code=None,
                    status="docker_binary_missing",
                    timed_out=False,
                    stdout_summary="",
                    stderr_summary="",
                    error=materialized.redact_text(str(exc)),
                )
            )
            return {
                "requested": True,
                "performed": False,
                "status": "failed",
                "network_mode": "bridge",
                "timeout_seconds": timeout_seconds,
                "results": [result.as_dict() for result in results],
                "limitations": ["Docker binary is unavailable for Phase 1 fetch."],
            }
        except subprocess.TimeoutExpired as exc:
            results.append(
                Phase1CommandResult(
                    kind=str(kind),
                    argv=tuple(argv),
                    return_code=None,
                    status="timeout",
                    timed_out=True,
                    stdout_summary=_summarize_output(exc.stdout or "", materialized),
                    stderr_summary=_summarize_output(exc.stderr or "", materialized),
                    error="phase1_fetch_timeout",
                )
            )
            return {
                "requested": True,
                "performed": True,
                "status": "failed",
                "network_mode": "bridge",
                "timeout_seconds": timeout_seconds,
                "results": [result.as_dict() for result in results],
                "limitations": ["Phase 1 fetch timed out before dependency retrieval completed."],
            }
        except OSError as exc:
            results.append(
                Phase1CommandResult(
                    kind=str(kind),
                    argv=tuple(argv),
                    return_code=None,
                    status="host_error",
                    timed_out=False,
                    stdout_summary="",
                    stderr_summary="",
                    error=materialized.redact_text(str(exc)),
                )
            )
            return {
                "requested": True,
                "performed": False,
                "status": "failed",
                "network_mode": "bridge",
                "timeout_seconds": timeout_seconds,
                "results": [result.as_dict() for result in results],
                "limitations": ["Phase 1 fetch failed before the dependency command could complete."],
            }

        result = Phase1CommandResult(
            kind=str(kind),
            argv=tuple(argv),
            return_code=completed.returncode,
            status="passed" if completed.returncode == 0 else "non_zero_exit",
            timed_out=False,
            stdout_summary=_summarize_output(completed.stdout, materialized),
            stderr_summary=_summarize_output(completed.stderr, materialized),
        )
        results.append(result)
        if completed.returncode != 0:
            return {
                "requested": True,
                "performed": True,
                "status": "failed",
                "network_mode": "bridge",
                "timeout_seconds": timeout_seconds,
                "results": [item.as_dict() for item in results],
                "limitations": ["Phase 1 fetch returned a non-zero exit code and remains fail-closed."],
            }

    return {
        "requested": True,
        "performed": bool(fetch_commands),
        "status": "passed" if fetch_commands else "skipped",
        "network_mode": "bridge",
        "timeout_seconds": timeout_seconds,
        "results": [result.as_dict() for result in results],
        "limitations": ([] if fetch_commands else ["Phase 1 fetch had no runnable commands after planning."]),
    }
