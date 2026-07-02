from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import re
import shutil
import tempfile
from typing import Any


WORKSPACE_PATH = "/workspace"
HOME_PATH = "/tmp/home"
NPM_CACHE_PATH = "/tmp/npm-cache"
PIP_CACHE_PATH = "/tmp/pip-cache"
XDG_CACHE_PATH = "/tmp/xdg-cache"
TMP_PATH = "/tmp/tmp"

PATH_HANDLE_MAP = {
    "repo_source": "<repo>",
    "sandbox_root": "<sandbox-root>",
    "workspace": "<workspace>",
    "home": "<home>",
    "npm_cache": "<npm-cache>",
    "pip_cache": "<pip-cache>",
    "xdg_cache": "<xdg-cache>",
    "tmp": "<tmp>",
}

DIRECTORY_EXCLUSIONS = {
    ".git": "vcs_metadata",
    ".venv": "virtualenv",
    "venv": "virtualenv",
    "node_modules": "dependency_tree",
    ".mypy_cache": "cache",
    ".pytest_cache": "cache",
    "__pycache__": "cache",
    ".ruff_cache": "cache",
    ".tox": "cache",
    ".nox": "cache",
    "dist": "build_output",
    "build": "build_output",
    ".cache": "cache",
    ".aws": "credential_like",
    ".azure": "credential_like",
    ".gcp": "credential_like",
    ".gnupg": "credential_like",
    ".ssh": "credential_like",
    ".kube": "credential_like",
    ".config/gcloud": "credential_like",
    ".idea": "ide_metadata",
    ".vscode": "ide_metadata",
    ".history": "history",
    ".Trash": "os_metadata",
    "$RECYCLE.BIN": "os_metadata",
    "coverage": "coverage_artifact",
    "htmlcov": "coverage_artifact",
    ".coverage": "coverage_artifact",
}

FILE_EXCLUSIONS = {
    ".env": "credential_like",
    ".bash_history": "history",
    ".zsh_history": "history",
    ".python_history": "history",
    ".psql_history": "history",
    ".mysql_history": "history",
    ".npmrc": "credential_like",
    ".pypirc": "credential_like",
    ".netrc": "credential_like",
    ".git-credentials": "credential_like",
    ".gitconfig": "credential_like",
    "credentials": "credential_like",
    ".DS_Store": "os_metadata",
    "Thumbs.db": "os_metadata",
    "Desktop.ini": "os_metadata",
    ".coverage": "coverage_artifact",
}

FILE_SUFFIX_EXCLUSIONS = {
    ".pyc": "bytecode",
    ".pyo": "bytecode",
    ":Zone.Identifier": "os_metadata",
    ".cover": "coverage_artifact",
    ".lcov": "coverage_artifact",
}

HONEYPOT_ENVIRONMENTS = {
    "AWS_SECRET_ACCESS_KEY": "rhd_honeypot_aws_secret_access_key",
    "GITHUB_TOKEN": "rhd_honeypot_github_token",
    "NPM_TOKEN": "rhd_honeypot_npm_token",
}

HONEYPOT_FILE_SPECS = (
    (
        "home",
        ".aws/credentials",
        "[default]\naws_access_key_id = RHD_HONEYPOT\naws_secret_access_key = RHD_HONEYPOT_SECRET\n",
    ),
    (
        "home",
        ".ssh/id_rsa",
        "RHD_HONEYPOT_SSH_PRIVATE_KEY_PLACEHOLDER\n",
    ),
    (
        "home",
        ".netrc",
        "machine example.invalid login rhd password RHD_HONEYPOT\n",
    ),
    (
        "home",
        ".npmrc",
        "//registry.npmjs.org/:_authToken=RHD_HONEYPOT\n",
    ),
    (
        "home",
        ".pypirc",
        "[distutils]\nindex-servers = pypi\n[pypi]\npassword = RHD_HONEYPOT\n",
    ),
    (
        "workspace",
        ".env",
        "AWS_SECRET_ACCESS_KEY=RHD_HONEYPOT\nGITHUB_TOKEN=RHD_HONEYPOT\nNPM_TOKEN=RHD_HONEYPOT\n",
    ),
)

REPORT_REDACTION_VALUES = (
    *HONEYPOT_ENVIRONMENTS.values(),
    "RHD_HONEYPOT_SSH_PRIVATE_KEY_PLACEHOLDER",
    "RHD_HONEYPOT_SECRET",
    "RHD_HONEYPOT",
)

REDACTED_VALUE = "***REDACTED***"
GENERIC_SECRET_PATTERNS = (
    re.compile(
        r"-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----.*?-----END(?: [A-Z0-9]+)* PRIVATE KEY-----",
        re.IGNORECASE | re.DOTALL,
    ),
    re.compile(r"(?<![A-Za-z0-9_-])sk-[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])"),
    re.compile(r"(?<![A-Za-z0-9])ghp_[A-Za-z0-9]{20,}(?![A-Za-z0-9])"),
    re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])"),
    re.compile(
        r"(?ix)\b(?:password|token|api[_-]?key|secret)\b\s*['\"]?\s*[:=]\s*['\"]?[^\s,;}\]\r\n]+"
    ),
)


def build_disposable_workspace_plan() -> dict[str, Any]:
    logical_paths = {
        "workspace": WORKSPACE_PATH,
        "home": HOME_PATH,
        "npm_cache": NPM_CACHE_PATH,
        "pip_cache": PIP_CACHE_PATH,
        "xdg_cache": XDG_CACHE_PATH,
        "tmp": TMP_PATH,
    }
    host_path_placeholders = {
        "workspace": "${RHD_DISPOSABLE_WORKSPACE}",
        "home": "${RHD_DISPOSABLE_HOME}",
        "npm_cache": "${RHD_DISPOSABLE_NPM_CACHE}",
        "pip_cache": "${RHD_DISPOSABLE_PIP_CACHE}",
        "xdg_cache": "${RHD_DISPOSABLE_XDG_CACHE}",
        "tmp": "${RHD_DISPOSABLE_TMP}",
    }
    return {
        "mode": "plan_only",
        "copy_strategy": "repo_copy_into_disposable_workspace_before_container_start",
        "cleanup_strategy": "finally_cleanup_fail_closed_once_execution_is_enabled",
        "source_repo": "redacted_repo_root",
        "logical_paths": logical_paths,
        "host_path_placeholders": host_path_placeholders,
        "path_handles": dict(PATH_HANDLE_MAP),
        "environment": {
            "HOME": HOME_PATH,
            "NPM_CONFIG_CACHE": NPM_CACHE_PATH,
            "PIP_CACHE_DIR": PIP_CACHE_PATH,
            "XDG_CACHE_HOME": XDG_CACHE_PATH,
            "TMPDIR": TMP_PATH,
        },
        "blocked_host_inputs": [
            "host_home",
            "host_ssh_agent",
            "host_git_credentials",
            "host_npmrc",
            "host_pypirc",
            "host_netrc",
            "host_docker_socket",
        ],
        "materialization_status": "not_started",
        "cleanup_status": "not_started",
        "execution_enabled": False,
    }


@dataclass
class MaterializedWorkspace:
    source_repo: Path
    plan: dict[str, Any]
    sandbox_root: Path | None = None
    host_paths: dict[str, Path] = field(default_factory=dict)
    files_copied: int = 0
    directories_created: int = 0
    excluded_counts: dict[str, int] = field(default_factory=dict)
    unsafe_symlinks: list[dict[str, str]] = field(default_factory=list)
    copy_errors: list[dict[str, str]] = field(default_factory=list)
    honeypot_file_handles: list[str] = field(default_factory=list)
    honeypot_env: dict[str, str] = field(default_factory=lambda: dict(HONEYPOT_ENVIRONMENTS))
    limitations: list[str] = field(default_factory=list)
    materialization_status: str = "not_started"
    cleanup_status: str = "not_started"
    cleanup_error: str | None = None

    def record_exclusion(self, category: str) -> None:
        self.excluded_counts[category] = self.excluded_counts.get(category, 0) + 1

    def record_unsafe_symlink(self, relative_path: str, reason: str) -> None:
        self.unsafe_symlinks.append({"path": relative_path, "reason": reason})

    def record_copy_error(self, relative_path: str, detail: str) -> None:
        self.copy_errors.append(
            {
                "path": relative_path,
                "detail": self.redact_text(detail),
            }
        )

    def _replacement_map(self) -> dict[str, str]:
        replacements = {
            str(self.source_repo): PATH_HANDLE_MAP["repo_source"],
        }
        if self.sandbox_root is not None:
            replacements[str(self.sandbox_root)] = PATH_HANDLE_MAP["sandbox_root"]
        for key, path in self.host_paths.items():
            replacements[str(path)] = PATH_HANDLE_MAP[key]
        return replacements

    def redact_text(self, text: str) -> str:
        redacted = text
        for raw_path, handle in sorted(
            self._replacement_map().items(),
            key=lambda item: len(item[0]),
            reverse=True,
        ):
            redacted = redacted.replace(raw_path, handle)
        for value in sorted(REPORT_REDACTION_VALUES, key=len, reverse=True):
            redacted = redacted.replace(value, REDACTED_VALUE)
        for pattern in GENERIC_SECRET_PATTERNS:
            redacted = pattern.sub(REDACTED_VALUE, redacted)
        return redacted

    def redact_report_value(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.redact_text(value)
        if isinstance(value, list):
            return [self.redact_report_value(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self.redact_report_value(item) for item in value)
        if isinstance(value, dict):
            return {
                self.redact_text(key) if isinstance(key, str) else key: self.redact_report_value(item)
                for key, item in value.items()
            }
        return value

    def cleanup(self) -> None:
        if self.cleanup_status == "completed":
            return
        if self.sandbox_root is None:
            self.cleanup_status = "not_started"
            return
        try:
            shutil.rmtree(self.sandbox_root)
        except OSError as exc:
            self.cleanup_status = "failed"
            self.cleanup_error = self.redact_text(str(exc))
            self.limitations.append(
                "Disposable workspace cleanup failed; treat the sandbox materialization result as fail-closed."
            )
        else:
            self.cleanup_status = "completed"

    def observer_environment(self) -> dict[str, str]:
        return dict(self.honeypot_env)

    def as_report_dict(self) -> dict[str, Any]:
        excluded_categories = [
            {"category": category, "count": count}
            for category, count in sorted(self.excluded_counts.items())
        ]
        report = {
            "mode": self.plan["mode"],
            "copy_strategy": self.plan["copy_strategy"],
            "cleanup_strategy": self.plan["cleanup_strategy"],
            "source_repo": PATH_HANDLE_MAP["repo_source"],
            "logical_paths": self.plan["logical_paths"],
            "host_path_placeholders": self.plan["host_path_placeholders"],
            "path_handles": dict(PATH_HANDLE_MAP),
            "environment": self.plan["environment"],
            "blocked_host_inputs": self.plan["blocked_host_inputs"],
            "materialization_status": self.materialization_status,
            "cleanup_status": self.cleanup_status,
            "copy_summary": {
                "files_copied": self.files_copied,
                "directories_created": self.directories_created,
                "excluded_count": sum(self.excluded_counts.values()),
                "unsafe_symlink_count": len(self.unsafe_symlinks),
                "copy_error_count": len(self.copy_errors),
                "git_metadata_copied": False,
            },
            "copy_exclusions": {
                "categories": excluded_categories,
            },
            "honeypots": {
                "file_handle_count": len(self.honeypot_file_handles),
                "file_handles": list(self.honeypot_file_handles),
                "env_names": sorted(self.honeypot_env),
            },
            "unsafe_symlinks": {
                "count": len(self.unsafe_symlinks),
                "samples": self.unsafe_symlinks[:5],
            },
            "copy_errors": {
                "count": len(self.copy_errors),
                "samples": self.copy_errors[:5],
            },
            "limitations": list(dict.fromkeys(self.limitations)),
            "execution_enabled": False,
        }
        if self.cleanup_error is not None:
            report["cleanup_error"] = self.cleanup_error
        return report


def _classify_directory(name: str) -> str | None:
    return DIRECTORY_EXCLUSIONS.get(name)


def _classify_file(name: str) -> str | None:
    if name in FILE_EXCLUSIONS:
        return FILE_EXCLUSIONS[name]
    for suffix, category in FILE_SUFFIX_EXCLUSIONS.items():
        if name.endswith(suffix):
            return category
    return None


def _is_within_repo(path: Path, repo_root: Path) -> bool:
    try:
        path.relative_to(repo_root)
    except ValueError:
        return False
    return True


def _copy_repo_tree(
    source_dir: Path,
    destination_dir: Path,
    *,
    repo_root: Path,
    materialized: MaterializedWorkspace,
) -> None:
    for entry in os.scandir(source_dir):
        source_path = Path(entry.path)
        relative_path = source_path.relative_to(repo_root).as_posix()
        destination_path = destination_dir / entry.name

        if entry.is_symlink():
            try:
                resolved_target = source_path.resolve(strict=True)
            except OSError:
                materialized.record_unsafe_symlink(relative_path, "broken_symlink")
                materialized.limitations.append(
                    "Broken symlinks are not copied into the disposable workspace."
                )
                continue
            if not _is_within_repo(resolved_target, repo_root):
                materialized.record_unsafe_symlink(relative_path, "outside_repo")
                materialized.limitations.append(
                    "Symlinks that resolve outside the repository are skipped during workspace copy."
                )
                continue
            materialized.record_exclusion("symlink")
            continue

        if entry.is_dir(follow_symlinks=False):
            category = _classify_directory(entry.name)
            if category is not None:
                materialized.record_exclusion(category)
                continue
            try:
                destination_path.mkdir()
            except OSError as exc:
                materialized.record_copy_error(relative_path, str(exc))
                continue
            materialized.directories_created += 1
            _copy_repo_tree(
                source_path,
                destination_path,
                repo_root=repo_root,
                materialized=materialized,
            )
            continue

        if entry.is_file(follow_symlinks=False):
            category = _classify_file(entry.name)
            if category is not None:
                materialized.record_exclusion(category)
                continue
            try:
                shutil.copy2(source_path, destination_path)
            except OSError as exc:
                materialized.record_copy_error(relative_path, str(exc))
                continue
            materialized.files_copied += 1
            continue

        materialized.record_copy_error(relative_path, "unsupported filesystem entry")


def _seed_honeypots(materialized: MaterializedWorkspace) -> None:
    for base_key, relative_path, content in HONEYPOT_FILE_SPECS:
        base_path = materialized.host_paths[base_key]
        destination = base_path / relative_path
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(content, encoding="utf-8")
        except OSError as exc:
            materialized.record_copy_error(relative_path, str(exc))
            materialized.limitations.append(
                "One or more sandbox honeypot files could not be created in the disposable workspace."
            )
            continue
        handle = f"{PATH_HANDLE_MAP[base_key]}/{relative_path}".replace("//", "/")
        materialized.honeypot_file_handles.append(handle)
        materialized.files_copied += 1


def materialize_disposable_workspace(
    source_repo: Path,
    workspace_plan: dict[str, Any] | None = None,
) -> MaterializedWorkspace:
    repo_root = source_repo.resolve()
    plan = build_disposable_workspace_plan() if workspace_plan is None else workspace_plan
    materialized = MaterializedWorkspace(source_repo=repo_root, plan=plan)

    sandbox_root = Path(tempfile.mkdtemp(prefix="rhd-sandbox-"))
    materialized.sandbox_root = sandbox_root
    materialized.host_paths = {
        "workspace": sandbox_root / "workspace",
        "home": sandbox_root / "home",
        "npm_cache": sandbox_root / "npm-cache",
        "pip_cache": sandbox_root / "pip-cache",
        "xdg_cache": sandbox_root / "xdg-cache",
        "tmp": sandbox_root / "tmp",
    }

    try:
        for path in materialized.host_paths.values():
            path.mkdir(parents=True, exist_ok=False)
            materialized.directories_created += 1
        _copy_repo_tree(
            repo_root,
            materialized.host_paths["workspace"],
            repo_root=repo_root,
            materialized=materialized,
        )
        _seed_honeypots(materialized)
    except OSError as exc:
        materialized.materialization_status = "failed"
        materialized.record_copy_error(".", str(exc))
        materialized.limitations.append(
            "Disposable workspace materialization did not complete successfully."
        )
        return materialized

    if materialized.copy_errors:
        materialized.materialization_status = "partial"
        materialized.limitations.append(
            "One or more repository entries could not be copied into the disposable workspace."
        )
    else:
        materialized.materialization_status = "completed"
    return materialized
