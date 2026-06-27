from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Iterator

from ..doctor import STATUS_BLOCK, STATUS_WARN, TOOL_VERSION
from .workspace import GENERIC_SECRET_PATTERNS, REDACTED_VALUE

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10+ should provide tomllib
    tomllib = None  # type: ignore[assignment]


UNKNOWN_PROFILE_SCHEMA_VERSION = "0.1-draft"
REPORT_KIND_UNKNOWN_REPO_PROFILE = "sandbox_unknown_repo_profile"
MAX_PROFILE_FILES = 2_000
MAX_TEXT_SCAN_BYTES = 256 * 1024
SAFE_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SKIPPED_DIRECTORIES = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__"}
NATIVE_SUFFIXES = {".dll", ".dylib", ".exe", ".so"}
ARCHIVE_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tgz", ".whl", ".egg", ".gz", ".bz2", ".xz", ".7z")
MANIFEST_KINDS = {
    "package.json": "npm_manifest",
    "package-lock.json": "npm_lockfile",
    "npm-shrinkwrap.json": "npm_lockfile",
    "pyproject.toml": "python_project",
    "setup.py": "python_setup",
    "setup.cfg": "python_setup_config",
    "poetry.lock": "poetry_lockfile",
    "uv.lock": "uv_lockfile",
    "Pipfile": "pipenv_manifest",
    "Pipfile.lock": "pipenv_lockfile",
}


def _redact_text(value: str, root: Path) -> str:
    redacted = value.replace(str(root), "<repo>")
    for pattern in GENERIC_SECRET_PATTERNS:
        redacted = pattern.sub(REDACTED_VALUE, redacted)
    return redacted


def _redact_value(value: Any, root: Path) -> Any:
    if isinstance(value, str):
        return _redact_text(value, root)
    if isinstance(value, list):
        return [_redact_value(item, root) for item in value]
    if isinstance(value, dict):
        return {
            _redact_text(key, root) if isinstance(key, str) else key: _redact_value(item, root)
            for key, item in value.items()
        }
    return value


def _fingerprint(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _safe_label(value: str, root: Path) -> str | None:
    normalized = value.strip()
    if not SAFE_LABEL.fullmatch(normalized):
        return None
    if _redact_text(normalized, root) != normalized:
        return None
    return normalized


def _safe_relative(root: Path, path: Path) -> str:
    try:
        return _redact_text(path.relative_to(root).as_posix(), root)
    except ValueError:
        return "<outside-repo>"


def _load_json_object(path: Path) -> tuple[dict[str, Any], str | None]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}, "parse_error"
    if not isinstance(payload, dict):
        return {}, "ambiguous_root_type"
    return payload, None


def _load_toml_object(path: Path) -> tuple[dict[str, Any], str | None]:
    if tomllib is None:
        return {}, "toml_parser_unavailable"
    try:
        payload = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return {}, "parse_error"
    if not isinstance(payload, dict):
        return {}, "ambiguous_root_type"
    return payload, None


def _dependency_class(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        return "ambiguous"
    lowered = value.strip().lower()
    if lowered.startswith(("-e ", "--editable ")):
        return "editable"
    if lowered.startswith(("git+", "git://", "git@", "github:")) or " @ git+" in lowered:
        return "vcs"
    if lowered.startswith(("http://", "https://")) or " @ http://" in lowered or " @ https://" in lowered:
        return "direct_url"
    if lowered.startswith(("file:", "./", "../", "/", "link:", "workspace:")):
        return "local_path"
    if " @ file:" in lowered or " @ ./" in lowered or " @ ../" in lowered or " @ /" in lowered:
        return "local_path"
    return "regular"


def _increment_dependency(counts: dict[str, int], value: Any) -> None:
    kind = _dependency_class(value)
    counts[f"{kind}_count"] += 1


def _classify_script(value: str) -> str:
    lowered = value.lower()
    if re.search(r"(?:^|[\s;|&])(?:sh|bash|cmd|powershell|pwsh)\s+(?:-c|/c|-command)", lowered):
        return "explicit_shell_reference"
    if any(token in lowered for token in ("curl", "wget", "powershell")):
        return "network_tool_reference"
    if any(token in lowered for token in ("subprocess", "child_process", "os.system", "exec(")):
        return "subprocess_reference"
    return "argv_candidate"


def _script_entry(name: str, value: str, root: Path) -> dict[str, str]:
    safe_name = _safe_label(name, root)
    entry = {
        "classification": _classify_script(value),
        "script_fingerprint": _fingerprint(value),
    }
    if safe_name is None:
        entry["name_fingerprint"] = _fingerprint(name)
    else:
        entry["name"] = safe_name
    return entry


def _iter_repo_files(root: Path, symlinks: dict[str, int], limitations: list[str]) -> Iterator[Path]:
    yielded = 0
    for directory, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        base = Path(directory)
        retained_dirs: list[str] = []
        for name in sorted(dirnames):
            child = base / name
            if child.is_symlink():
                _record_symlink(root, child, symlinks)
                continue
            if name in SKIPPED_DIRECTORIES:
                continue
            retained_dirs.append(name)
        dirnames[:] = retained_dirs
        for name in sorted(filenames):
            path = base / name
            if path.is_symlink():
                _record_symlink(root, path, symlinks)
                continue
            yielded += 1
            if yielded > MAX_PROFILE_FILES:
                limitations.append("profile_file_limit_reached")
                return
            yield path


def _record_symlink(root: Path, path: Path, counts: dict[str, int]) -> None:
    counts["count"] += 1
    try:
        resolved = path.resolve(strict=False)
    except OSError:
        counts["broken_count"] += 1
        return
    if not resolved.exists():
        counts["broken_count"] += 1
    elif not resolved.is_relative_to(root):
        counts["outside_repo_count"] += 1


def _scan_text_indicators(text: str, indicators: dict[str, int]) -> None:
    lowered = text.lower()
    if (
        "http://" in lowered
        or "https://" in lowered
        or re.search(r"\b(?:requests|urllib|socket)\s*(?:[.(])", lowered) is not None
        or re.search(r"\bimport\s+(?:requests|urllib|socket)\b", lowered) is not None
        or "fetch(" in lowered
        or "axios." in lowered
    ):
        indicators["network_related_reference_count"] += 1
    if any(token in lowered for token in (".aws/credentials", ".aws/config", ".ssh/", ".netrc", ".npmrc", ".pypirc", "aws_secret_access_key", "github_token", "npm_token")):
        indicators["credential_path_reference_count"] += 1
    if "/var/run/docker.sock" in lowered or "docker.sock" in lowered:
        indicators["docker_socket_reference_count"] += 1
    if any(token in lowered for token in ("path.home(", "expanduser(", "process.env.home", "os.environ['home']", "os.environ.get('home'", "$home", "~/.ssh")):
        indicators["host_home_reference_count"] += 1
    if any(token in lowered for token in ("sh -c", "bash -c", "powershell", "subprocess", "os.system", "child_process", "shell=True")):
        indicators["shell_command_reference_count"] += 1
    if "curl" in lowered:
        indicators["curl_reference_count"] += 1
    if "wget" in lowered:
        indicators["wget_reference_count"] += 1
    if "powershell" in lowered:
        indicators["powershell_reference_count"] += 1
    if re.search(r"(?:^|[\s;|&])bash(?:\s|$)", lowered):
        indicators["bash_reference_count"] += 1
    if any(token in lowered for token in ("base64.b64decode", "fromcharcode", "eval(", "exec(")):
        indicators["obfuscation_indicator_count"] += 1
    if any(token in lowered for token in ("rm -rf", "shutil.rmtree", "os.remove", "fs.rm", "unlink(")):
        indicators["destructive_reference_count"] += 1
    if any(token in lowered for token in ("crontab", "systemctl", "/etc/systemd", ".bashrc")):
        indicators["persistence_reference_count"] += 1


def _scan_file(path: Path, root: Path, indicators: dict[str, int], analysis: dict[str, int]) -> None:
    name = path.name.lower()
    if any(marker in name for marker in ("payload", "dropper", "keylogger", "credential")):
        indicators["suspicious_file_count"] += 1
    if path.suffix.lower() in NATIVE_SUFFIXES:
        indicators["native_binary_count"] += 1
    if name.endswith(ARCHIVE_SUFFIXES):
        indicators["large_binary_or_archive_count"] += 1
    try:
        size = path.stat().st_size
    except OSError:
        analysis["read_error_count"] += 1
        return
    if size >= MAX_TEXT_SCAN_BYTES:
        indicators["large_binary_or_archive_count"] += 1
        return
    try:
        data = path.read_bytes()
    except OSError:
        analysis["read_error_count"] += 1
        return
    if data.startswith((b"\x7fELF", b"MZ")):
        indicators["native_binary_count"] += 1
        return
    if b"\x00" in data:
        indicators["large_binary_or_archive_count"] += 1
        return
    try:
        _scan_text_indicators(data.decode("utf-8"), indicators)
    except UnicodeDecodeError:
        analysis["read_error_count"] += 1


def _profile_package_json(
    root: Path,
    package_json: Path,
    dependency_counts: dict[str, int],
    analysis: dict[str, int],
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    payload, issue = _load_json_object(package_json)
    if issue is not None:
        analysis["parse_error_count" if issue == "parse_error" else "ambiguous_field_count"] += 1
        return [], []
    scripts: list[dict[str, str]] = []
    lifecycle: list[dict[str, str]] = []
    raw_scripts = payload.get("scripts", {})
    if not isinstance(raw_scripts, dict):
        analysis["ambiguous_field_count"] += 1
    else:
        for raw_name, raw_value in sorted(raw_scripts.items(), key=lambda item: str(item[0])):
            if not isinstance(raw_name, str) or not isinstance(raw_value, str):
                analysis["ambiguous_field_count"] += 1
                continue
            entry = _script_entry(raw_name, raw_value, root)
            scripts.append(entry)
            if raw_name in {"preinstall", "install", "postinstall", "prepare"}:
                lifecycle.append(entry)
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        raw_dependencies = payload.get(section)
        if raw_dependencies is None:
            continue
        if not isinstance(raw_dependencies, dict):
            analysis["ambiguous_field_count"] += 1
            continue
        for value in raw_dependencies.values():
            _increment_dependency(dependency_counts, value)
    return scripts, lifecycle


def _profile_pyproject(
    pyproject: Path,
    dependency_counts: dict[str, int],
    analysis: dict[str, int],
) -> dict[str, Any]:
    profile = {
        "backend_status": "not_declared",
        "build_system_requires": {"status": "not_declared", "count": 0, "dependency_classes": []},
    }
    payload, issue = _load_toml_object(pyproject)
    if issue is not None:
        analysis["parse_error_count" if issue == "parse_error" else "ambiguous_field_count"] += 1
        profile["backend_status"] = "unavailable"
        profile["build_system_requires"]["status"] = "unavailable"
        return profile
    build_system = payload.get("build-system")
    if build_system is not None:
        if not isinstance(build_system, dict):
            analysis["ambiguous_field_count"] += 1
            profile["backend_status"] = "invalid"
            profile["build_system_requires"]["status"] = "invalid"
        else:
            backend = build_system.get("build-backend")
            if backend is not None:
                if isinstance(backend, str) and backend.strip():
                    profile["backend_status"] = "declared"
                else:
                    analysis["ambiguous_field_count"] += 1
                    profile["backend_status"] = "invalid"
            requires = build_system.get("requires")
            if requires is not None:
                if not isinstance(requires, list):
                    analysis["ambiguous_field_count"] += 1
                    profile["build_system_requires"]["status"] = "invalid"
                else:
                    classes: list[str] = []
                    for requirement in requires:
                        kind = _dependency_class(requirement)
                        _increment_dependency(dependency_counts, requirement)
                        classes.append(kind)
                    profile["build_system_requires"] = {
                        "status": "present",
                        "count": len(requires),
                        "dependency_classes": sorted(dict.fromkeys(classes)),
                    }
    project = payload.get("project")
    if project is not None:
        if not isinstance(project, dict):
            analysis["ambiguous_field_count"] += 1
        else:
            dependencies = project.get("dependencies")
            if dependencies is not None:
                if not isinstance(dependencies, list):
                    analysis["ambiguous_field_count"] += 1
                else:
                    for requirement in dependencies:
                        _increment_dependency(dependency_counts, requirement)
            optional = project.get("optional-dependencies")
            if optional is not None:
                if not isinstance(optional, dict):
                    analysis["ambiguous_field_count"] += 1
                else:
                    for values in optional.values():
                        if not isinstance(values, list):
                            analysis["ambiguous_field_count"] += 1
                            continue
                        for requirement in values:
                            _increment_dependency(dependency_counts, requirement)
    return profile


def _profile_requirements(path: Path, dependency_counts: dict[str, int], analysis: dict[str, int]) -> None:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        analysis["read_error_count"] += 1
        return
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            _increment_dependency(dependency_counts, stripped)


def _risk_for(profile: dict[str, Any]) -> dict[str, Any]:
    dependencies = profile["dependency_sources"]
    indicators = profile["indicators"]
    analysis = profile["analysis"]
    reasons: list[str] = []
    if (
        indicators["destructive_reference_count"]
        and indicators["credential_path_reference_count"]
        and indicators["obfuscation_indicator_count"]
    ) or (indicators["destructive_reference_count"] and indicators["persistence_reference_count"]):
        return {
            "tier": "T5",
            "report_status": STATUS_BLOCK,
            "disposition": "quarantine_or_specialist_review",
            "reasons": ["malware_suspicion_indicator_combination"],
            "live_eligibility": "not_a_candidate",
        }
    for key, reason in (
        (dependencies["direct_url_count"], "direct_url_dependency"),
        (dependencies["vcs_count"], "vcs_dependency"),
        (indicators["credential_path_reference_count"], "credential_path_reference"),
        (indicators["network_related_reference_count"], "network_reference"),
        (indicators["native_binary_count"], "native_binary"),
        (indicators["obfuscation_indicator_count"], "obfuscation_indicator"),
        (indicators["docker_socket_reference_count"], "docker_socket_reference"),
        (indicators["host_home_reference_count"], "host_home_reference"),
    ):
        if key:
            reasons.append(reason)
    if reasons:
        return {
            "tier": "T4",
            "report_status": STATUS_BLOCK,
            "disposition": "dedicated_vm_required",
            "reasons": reasons,
            "live_eligibility": "not_a_candidate",
        }
    if (
        profile["lifecycle_scripts"]
        or profile["python_build"]["backend_status"] == "declared"
        or indicators["shell_command_reference_count"]
        or analysis["parse_error_count"]
        or analysis["ambiguous_field_count"]
        or analysis["read_error_count"]
        or profile["symlink_risks"]["count"]
        or profile["large_binary_or_archive_indicators"]["count"]
    ):
        reasons = []
        if profile["lifecycle_scripts"]:
            reasons.append("lifecycle_script")
        if profile["python_build"]["backend_status"] == "declared":
            reasons.append("python_build_backend")
        if indicators["shell_command_reference_count"]:
            reasons.append("shell_or_subprocess_reference")
        if analysis["parse_error_count"] or analysis["ambiguous_field_count"] or analysis["read_error_count"]:
            reasons.append("parse_or_ambiguity")
        if profile["symlink_risks"]["count"]:
            reasons.append("symlink_risk")
        if profile["large_binary_or_archive_indicators"]["count"]:
            reasons.append("large_binary_or_archive_indicator")
        return {
            "tier": "T3",
            "report_status": STATUS_WARN,
            "disposition": "needs_review",
            "reasons": reasons,
            "live_eligibility": "not_implemented",
        }
    if sum(dependencies.values()):
        return {
            "tier": "T2",
            "report_status": STATUS_WARN,
            "disposition": "needs_review",
            "reasons": ["dependencies_present"],
            "live_eligibility": "not_implemented",
        }
    if profile["manifest_files"]:
        return {
            "tier": "T1",
            "report_status": STATUS_WARN,
            "disposition": "needs_review",
            "reasons": ["manifest_present"],
            "live_eligibility": "not_implemented",
        }
    return {
        "tier": "T0",
        "report_status": STATUS_WARN,
        "disposition": "needs_review",
        "reasons": ["no_supported_manifest_or_dependency_surface"],
        "live_eligibility": "not_a_candidate",
    }


def profile_unknown_repo(repo_path: str | Path) -> dict[str, Any]:
    """Build a redacted, read-only unknown-repository profile without execution."""
    root = Path(repo_path).resolve()
    limitations: list[str] = [
        "Profile analysis is static and cannot establish runtime behavior or safety.",
        "No Docker, dependency fetch, approval draft, or repository command execution was performed.",
    ]
    symlinks = {"count": 0, "outside_repo_count": 0, "broken_count": 0}
    indicators = {
        "native_binary_count": 0,
        "suspicious_file_count": 0,
        "credential_path_reference_count": 0,
        "network_related_reference_count": 0,
        "shell_command_reference_count": 0,
        "curl_reference_count": 0,
        "wget_reference_count": 0,
        "powershell_reference_count": 0,
        "bash_reference_count": 0,
        "docker_socket_reference_count": 0,
        "host_home_reference_count": 0,
        "obfuscation_indicator_count": 0,
        "large_binary_or_archive_count": 0,
        "destructive_reference_count": 0,
        "persistence_reference_count": 0,
    }
    analysis = {"parse_error_count": 0, "read_error_count": 0, "ambiguous_field_count": 0}
    dependency_counts = {
        "regular_count": 0,
        "direct_url_count": 0,
        "vcs_count": 0,
        "editable_count": 0,
        "local_path_count": 0,
        "ambiguous_count": 0,
    }
    manifest_files: list[dict[str, str]] = []
    identity_paths: list[str] = []
    package_managers: list[str] = []
    npm_scripts: list[dict[str, str]] = []
    lifecycle_scripts: list[dict[str, str]] = []
    python_build = {
        "backend_status": "not_declared",
        "build_system_requires": {"status": "not_declared", "count": 0, "dependency_classes": []},
    }

    if not root.is_dir():
        analysis["ambiguous_field_count"] += 1
        limitations.append("profile_target_is_not_a_directory")
    else:
        files = list(_iter_repo_files(root, symlinks, limitations))
        identity_paths = [_safe_relative(root, path) for path in files]
        for path in files:
            _scan_file(path, root, indicators, analysis)
            relative = _safe_relative(root, path)
            kind = MANIFEST_KINDS.get(relative)
            if kind is not None:
                manifest_files.append({"path": relative, "kind": kind})
            elif path.name.startswith("requirements") and path.suffix == ".txt":
                manifest_files.append({"path": relative, "kind": "python_requirements"})

        relative_paths = {item["path"] for item in manifest_files}
        if any(path in relative_paths for path in ("package.json", "package-lock.json", "npm-shrinkwrap.json")):
            package_managers.append("npm")
        if any(item["kind"].startswith("python") for item in manifest_files):
            package_managers.append("pip")
        if "poetry.lock" in relative_paths:
            package_managers.append("poetry")
        if "uv.lock" in relative_paths:
            package_managers.append("uv")
        if "Pipfile" in relative_paths or "Pipfile.lock" in relative_paths:
            package_managers.append("pipenv")

        package_json = root / "package.json"
        if package_json.is_file() and not package_json.is_symlink():
            npm_scripts, lifecycle_scripts = _profile_package_json(root, package_json, dependency_counts, analysis)
        pyproject = root / "pyproject.toml"
        if pyproject.is_file() and not pyproject.is_symlink():
            python_build = _profile_pyproject(pyproject, dependency_counts, analysis)
        for path in files:
            if path.name.startswith("requirements") and path.suffix == ".txt":
                _profile_requirements(path, dependency_counts, analysis)

    profile = {
        "package_managers": sorted(dict.fromkeys(package_managers)),
        "manifest_files": sorted(manifest_files, key=lambda item: item["path"]),
        "package_scripts": npm_scripts,
        "lifecycle_scripts": lifecycle_scripts,
        "python_build": python_build,
        "npm_scripts": npm_scripts,
        "dependency_sources": dependency_counts,
        "native_binaries": {"count": indicators["native_binary_count"]},
        "suspicious_files": {"count": indicators["suspicious_file_count"]},
        "symlink_risks": symlinks,
        "credential_path_references": {"count": indicators["credential_path_reference_count"]},
        "network_related_references": {"count": indicators["network_related_reference_count"]},
        "shell_command_references": {"count": indicators["shell_command_reference_count"]},
        "command_references": {
            "curl_count": indicators["curl_reference_count"],
            "wget_count": indicators["wget_reference_count"],
            "powershell_count": indicators["powershell_reference_count"],
            "bash_count": indicators["bash_reference_count"],
        },
        "docker_socket_references": {"count": indicators["docker_socket_reference_count"]},
        "host_home_references": {"count": indicators["host_home_reference_count"]},
        "obfuscation_indicators": {"count": indicators["obfuscation_indicator_count"]},
        "large_binary_or_archive_indicators": {"count": indicators["large_binary_or_archive_count"]},
        "analysis": analysis,
        "indicators": indicators,
    }
    risk = _risk_for(profile)
    report = {
        "tool": "repo-health-doctor",
        "version": TOOL_VERSION,
        "schema_version": UNKNOWN_PROFILE_SCHEMA_VERSION,
        "report_kind": REPORT_KIND_UNKNOWN_REPO_PROFILE,
        "repo_path": "<repo>",
        "mode": "plan_only",
        "overall_status": risk["report_status"],
        "execution_permitted": False,
        "execution": {
            "docker_used": False,
            "image_pull_performed": False,
            "network_allowed": False,
            "shell_allowed": False,
            "phase1_fetch_requested": False,
            "phase2_live_requested": False,
            "phase3_live_requested": False,
        },
        "approval_status": "not_generated",
        "approval": {"draft_generated": False, "approved": False, "candidate_count": 0},
        "repo_scope": {
            "repository_identity": _fingerprint("\n".join(identity_paths)),
            "commit": "unavailable_read_only",
            "path": "<repo>",
        },
        "profile": profile,
        "risk": risk,
        "redaction": {"raw_host_paths_redacted": True, "secret_like_values_redacted": True},
        "limitations": list(dict.fromkeys(limitations)),
        "residual_risks": [
            "static_profile_not_runtime_safety_proof",
            "unknown_repo_live_execution_not_implemented",
            "docker_runtime_and_kernel_risks_not_evaluated",
        ],
    }
    return _redact_value(report, root)
