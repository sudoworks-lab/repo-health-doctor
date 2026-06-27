from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

from .models import (
    ExecutionCommand,
    PHASE_2_INSTALL_PROBE,
    PHASE_3_RUNTIME_PROBE,
    SkippedCommand,
    script_uses_explicit_shell,
)

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10+ should provide tomllib
    tomllib = None  # type: ignore[assignment]


INSTALL_SCRIPT_NAMES = ("preinstall", "install", "postinstall", "prepare")
RUNTIME_SCRIPT_NAMES = ("test", "start")
PYTHON_REQUIREMENTS_GLOB = "requirements*.txt"
SAFE_PROJECT_SCRIPT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
SAFE_PROJECT_SCRIPT_TARGET = re.compile(r"^[A-Za-z_][A-Za-z0-9_\.]*:[A-Za-z_][A-Za-z0-9_\.]*$")
PYTHON_PHASE2_INSTALL_ARGV = ("python", "-m", "pip", "install", "--no-deps", "--no-build-isolation", ".")
PYTHON_PHASE2_EDITABLE_ARGV = ("python", "-m", "pip", "install", "--no-deps", "--no-build-isolation", "-e", ".")
CONTROLLED_PHASE3_RUNTIME_FIXTURE_NAME = "sandbox-phase3-python-runtime"


def _load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _load_toml(path: Path) -> dict[str, Any]:
    if tomllib is None:
        return {}
    try:
        payload = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _build_python_install_probe_commands(
    *,
    root: Path,
    pyproject_payload: dict[str, Any],
) -> tuple[list[ExecutionCommand], list[SkippedCommand], list[str]]:
    commands: list[ExecutionCommand] = []
    skipped: list[SkippedCommand] = []
    limitations: list[str] = []

    manifest_sources: list[str] = []
    if (root / "setup.py").is_file():
        manifest_sources.append("setup.py")
    if (root / "setup.cfg").is_file():
        manifest_sources.append("setup.cfg")

    build_backend = None
    build_system = pyproject_payload.get("build-system")
    if isinstance(build_system, dict):
        raw_build_backend = build_system.get("build-backend")
        if isinstance(raw_build_backend, str) and raw_build_backend.strip():
            build_backend = raw_build_backend.strip()
            manifest_sources.append("pyproject.toml")

    manifest_sources = list(dict.fromkeys(manifest_sources))
    if not manifest_sources:
        return commands, skipped, limitations

    evidence_pairs = [("manifest", ",".join(manifest_sources))]
    if build_backend is not None:
        evidence_pairs.append(("build_backend", build_backend))

    commands.append(
        ExecutionCommand(
            phase=PHASE_2_INSTALL_PROBE,
            kind="install_script_probe",
            cwd=".",
            argv=PYTHON_PHASE2_INSTALL_ARGV,
            env_allowlist=(),
            evidence=tuple(evidence_pairs),
        )
    )
    commands.append(
        ExecutionCommand(
            phase=PHASE_2_INSTALL_PROBE,
            kind="editable_install_probe",
            cwd=".",
            argv=PYTHON_PHASE2_EDITABLE_ARGV,
            env_allowlist=(),
            evidence=tuple(evidence_pairs),
        )
    )
    limitations.append(
        "Python Phase 2 install probes are tool-generated from build metadata and remain approval-gated before any execution."
    )
    return commands, skipped, limitations


def _build_python_project_script_commands(
    pyproject_payload: dict[str, Any],
) -> tuple[list[ExecutionCommand], list[SkippedCommand], list[str]]:
    commands: list[ExecutionCommand] = []
    skipped: list[SkippedCommand] = []
    limitations: list[str] = []

    project_payload = pyproject_payload.get("project")
    if not isinstance(project_payload, dict):
        return commands, skipped, limitations
    scripts = project_payload.get("scripts")
    if not isinstance(scripts, dict):
        return commands, skipped, limitations

    generated_count = 0
    for raw_name, raw_target in sorted(scripts.items()):
        if not isinstance(raw_name, str) or not isinstance(raw_target, str):
            skipped.append(
                SkippedCommand(
                    phase=PHASE_3_RUNTIME_PROBE,
                    kind="runtime_smoke",
                    cwd=".",
                    reason="unsafe_or_ambiguous",
                    detail="project.scripts entry must use string key and string target",
                )
            )
            continue
        script_name = raw_name.strip()
        target = raw_target.strip()
        if not script_name or not target:
            skipped.append(
                SkippedCommand(
                    phase=PHASE_3_RUNTIME_PROBE,
                    kind="runtime_smoke",
                    cwd=".",
                    reason="unsafe_or_ambiguous",
                    detail="project.scripts entry must not be empty",
                )
            )
            continue
        if not SAFE_PROJECT_SCRIPT_NAME.fullmatch(script_name) or not SAFE_PROJECT_SCRIPT_TARGET.fullmatch(target):
            skipped.append(
                SkippedCommand(
                    phase=PHASE_3_RUNTIME_PROBE,
                    kind="runtime_smoke",
                    cwd=".",
                    argv=(script_name,) if SAFE_PROJECT_SCRIPT_NAME.fullmatch(script_name) else (),
                    reason="unsafe_or_ambiguous",
                    detail=f"project.scripts:{script_name}",
                )
            )
            continue
        commands.append(
            ExecutionCommand(
                phase=PHASE_3_RUNTIME_PROBE,
                kind="test_probe" if script_name.lower() in {"test", "pytest"} else "runtime_smoke",
                cwd=".",
                argv=(script_name,),
                env_allowlist=(),
                evidence=(("source", "project.scripts"), ("script", script_name)),
            )
        )
        generated_count += 1

    if generated_count:
        limitations.append(
            "Python project.scripts console entrypoints are suggested as approval-gated runtime candidates and may require Phase 2 installation first."
        )
    else:
        limitations.append("Python project.scripts metadata was present, but no safe runtime candidates could be generated.")
    return commands, skipped, limitations


def _build_controlled_fixture_runtime_probe_commands(
    root: Path,
    pyproject_payload: dict[str, Any],
) -> tuple[list[ExecutionCommand], list[SkippedCommand], list[str]]:
    if root.name != CONTROLLED_PHASE3_RUNTIME_FIXTURE_NAME:
        return [], [], []

    tool_section = pyproject_payload.get("tool")
    if not isinstance(tool_section, dict):
        return [], [], []
    repo_health_doctor = tool_section.get("repo_health_doctor")
    if not isinstance(repo_health_doctor, dict):
        return [], [], []
    sandbox = repo_health_doctor.get("sandbox")
    if not isinstance(sandbox, dict):
        return [], [], []
    raw_argv = sandbox.get("controlled_runtime_probe_argv")
    if not isinstance(raw_argv, list) or not raw_argv or any(not isinstance(item, str) or not item.strip() for item in raw_argv):
        return (
            [],
            [
                SkippedCommand(
                    phase=PHASE_3_RUNTIME_PROBE,
                    kind="test_probe",
                    cwd=".",
                    reason="unsafe_or_ambiguous",
                    detail="tool.repo_health_doctor.sandbox.controlled_runtime_probe_argv must be a non-empty string array",
                )
            ],
            ["Controlled fixture runtime metadata was present, but no valid harmless runtime probe argv could be generated."],
        )

    return (
        [
            ExecutionCommand(
                phase=PHASE_3_RUNTIME_PROBE,
                kind="test_probe",
                cwd=".",
                argv=tuple(raw_argv),
                env_allowlist=(),
                evidence=(("source", "controlled_fixture_runtime_probe"), ("fixture", root.name)),
            )
        ],
        [],
        ["Controlled fixture runtime probe is tool-generated as a harmless Python argv for plan-only approval verification."],
    )


def detect_execution_plan(root: Path) -> tuple[dict[str, Any], list[str]]:
    detected_languages: list[str] = []
    manifests: list[str] = []
    commands: list[ExecutionCommand] = []
    skipped_commands: list[SkippedCommand] = []
    limitations: list[str] = []

    package_json_path = root / "package.json"
    if package_json_path.is_file():
        detected_languages.append("node")
        manifests.append("package.json")
        for lockfile in ("package-lock.json", "npm-shrinkwrap.json"):
            if (root / lockfile).is_file():
                manifests.append(lockfile)

        package_payload = _load_json(package_json_path)
        scripts = package_payload.get("scripts")
        if isinstance(scripts, dict):
            for script_name in INSTALL_SCRIPT_NAMES:
                script_value = scripts.get(script_name)
                if not isinstance(script_value, str) or not script_value.strip():
                    continue
                if script_uses_explicit_shell(script_value):
                    skipped_commands.append(
                        SkippedCommand(
                            phase=PHASE_2_INSTALL_PROBE,
                            kind="install_script_probe",
                            cwd=".",
                            argv=("npm", "run", script_name),
                            reason="unsafe_or_ambiguous",
                            detail=f"script:{script_name}",
                        )
                    )
                    continue
                commands.append(
                    ExecutionCommand(
                        phase=PHASE_2_INSTALL_PROBE,
                        kind="install_script_probe",
                        cwd=".",
                        argv=("npm", "run", script_name),
                        env_allowlist=(),
                        evidence=(("manifest", "package.json"), ("script", script_name)),
                    )
                )
            for script_name in RUNTIME_SCRIPT_NAMES:
                script_value = scripts.get(script_name)
                if not isinstance(script_value, str) or not script_value.strip():
                    continue
                if script_uses_explicit_shell(script_value):
                    skipped_commands.append(
                        SkippedCommand(
                            phase=PHASE_3_RUNTIME_PROBE,
                            kind="test_probe" if script_name == "test" else "runtime_smoke",
                            cwd=".",
                            argv=("npm", script_name) if script_name in {"test", "start"} else ("npm", "run", script_name),
                            reason="unsafe_or_ambiguous",
                            detail=f"script:{script_name}",
                        )
                    )
                    continue
                commands.append(
                    ExecutionCommand(
                        phase=PHASE_3_RUNTIME_PROBE,
                        kind="test_probe" if script_name == "test" else "runtime_smoke",
                        cwd=".",
                        argv=("npm", script_name),
                        env_allowlist=(),
                        evidence=(("manifest", "package.json"), ("script", script_name)),
                    )
                )
        else:
            limitations.append("Node.js scripts could not be parsed from package.json.")

    python_manifest_detected = False
    pyproject_path = root / "pyproject.toml"
    if pyproject_path.is_file():
        python_manifest_detected = True
        manifests.append("pyproject.toml")
    for python_file in ("setup.py", "setup.cfg", "poetry.lock", "uv.lock"):
        if (root / python_file).is_file():
            python_manifest_detected = True
            manifests.append(python_file)
    requirement_files = sorted(
        path.relative_to(root).as_posix()
        for path in root.glob(PYTHON_REQUIREMENTS_GLOB)
        if path.is_file()
    )
    if requirement_files:
        python_manifest_detected = True
        manifests.extend(requirement_files)
    if python_manifest_detected:
        detected_languages.append("python")
        pyproject_payload = _load_toml(pyproject_path) if pyproject_path.is_file() else {}

        python_phase2_commands, python_phase2_skipped, python_phase2_limitations = _build_python_install_probe_commands(
            root=root,
            pyproject_payload=pyproject_payload,
        )
        commands.extend(python_phase2_commands)
        skipped_commands.extend(python_phase2_skipped)
        limitations.extend(python_phase2_limitations)
        controlled_runtime_commands, controlled_runtime_skipped, controlled_runtime_limitations = (
            _build_controlled_fixture_runtime_probe_commands(root, pyproject_payload)
        )
        if controlled_runtime_commands or controlled_runtime_skipped or controlled_runtime_limitations:
            commands.extend(controlled_runtime_commands)
            skipped_commands.extend(controlled_runtime_skipped)
            limitations.extend(controlled_runtime_limitations)
        else:
            python_project_script_commands, python_project_script_skipped, python_project_script_limitations = (
                _build_python_project_script_commands(pyproject_payload)
            )
            commands.extend(python_project_script_commands)
            skipped_commands.extend(python_project_script_skipped)
            limitations.extend(python_project_script_limitations)
        if (root / "tests").is_dir():
            commands.append(
                ExecutionCommand(
                    phase=PHASE_3_RUNTIME_PROBE,
                    kind="test_probe",
                    cwd=".",
                    argv=("python", "-m", "pytest"),
                    env_allowlist=(),
                    evidence=(("source", "tests_directory"),),
                )
            )
        else:
            tool_section = pyproject_payload.get("tool", {})
            pytest_detected = False
            if isinstance(tool_section, dict):
                pytest_detected = bool(tool_section.get("pytest")) or bool(tool_section.get("pytest.ini_options"))
            if pytest_detected:
                commands.append(
                    ExecutionCommand(
                        phase=PHASE_3_RUNTIME_PROBE,
                        kind="test_probe",
                        cwd=".",
                        argv=("python", "-m", "pytest"),
                        env_allowlist=(),
                        evidence=(("source", "pyproject.toml"),),
                    )
                )

    if not manifests:
        limitations.append("No supported Node.js or Python manifests were detected.")

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

    execution_plan = {
        "mode": "plan_only",
        "detected_languages": list(dict.fromkeys(detected_languages)),
        "manifest_paths": manifests,
        "commands": [command.as_dict() for command in commands],
        "skipped_commands": [command.as_dict() for command in skipped_commands],
    }
    return execution_plan, limitations
