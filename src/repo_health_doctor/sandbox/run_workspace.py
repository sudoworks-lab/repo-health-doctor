from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
from typing import Any

from .workspace import DIRECTORY_EXCLUSIONS, FILE_EXCLUSIONS, FILE_SUFFIX_EXCLUSIONS


FINGERPRINT_METHOD = "sandbox-run-file-inventory-v1"
WORKSPACE_COPY_POLICY = (
    "copy repository files into a disposable workspace; exclude .git, .env, "
    "common caches, credential-like files, unsafe symlinks, devices, sockets, and FIFOs"
)
DEFAULT_MAX_FILE_COUNT = 20_000
DEFAULT_MAX_TOTAL_BYTES = 250 * 1024 * 1024
DEFAULT_MAX_FILE_BYTES = 25 * 1024 * 1024


@dataclass(frozen=True)
class CopyBudget:
    max_file_count: int = DEFAULT_MAX_FILE_COUNT
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES

    def to_report(self, *, files_copied: int, total_bytes_copied: int, exceeded: bool, reason: str | None) -> dict[str, Any]:
        return {
            "max_file_count": self.max_file_count,
            "max_total_bytes": self.max_total_bytes,
            "max_file_bytes": self.max_file_bytes,
            "files_copied": files_copied,
            "total_bytes_copied": total_bytes_copied,
            "copy_budget_exceeded": exceeded,
            "copy_budget_exceeded_reason": reason,
        }


@dataclass
class InventoryResult:
    fingerprint: str
    file_count: int
    total_bytes: int
    files: dict[str, str]
    excluded_counts: dict[str, int] = field(default_factory=dict)
    unsafe_symlinks: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def limitations(self) -> list[str]:
        limitations: list[str] = []
        if self.unsafe_symlinks:
            limitations.append("One or more symlinks were skipped because they are unsafe or unsupported.")
        if self.errors:
            limitations.append("One or more filesystem entries could not be inventoried.")
        return limitations


@dataclass
class DisposableWorkspace:
    source_root: Path
    root: Path
    workspace: Path
    out: Path
    copy_budget: CopyBudget = field(default_factory=CopyBudget)
    created: bool = False
    cleanup_status: str = "not_started"
    cleanup_error: str | None = None
    excluded_counts: dict[str, int] = field(default_factory=dict)
    unsafe_symlinks: list[str] = field(default_factory=list)
    copy_errors: list[str] = field(default_factory=list)
    files_copied: int = 0
    total_bytes_copied: int = 0
    copy_budget_exceeded: bool = False
    copy_budget_exceeded_reason: str | None = None

    @property
    def copy_safety_ok(self) -> bool:
        return not self.unsafe_symlinks and not self.copy_errors and not self.copy_budget_exceeded

    def cleanup(self) -> None:
        if self.cleanup_status == "ok":
            return
        try:
            shutil.rmtree(self.root)
        except OSError as exc:
            self.cleanup_status = "failed"
            self.cleanup_error = str(exc)
        else:
            self.cleanup_status = "ok"

    def to_report(self) -> dict[str, Any]:
        return {
            "created": self.created,
            "cleanup": self.cleanup_status,
            "copy_policy": WORKSPACE_COPY_POLICY,
            "excluded_path_categories": _categories(self.excluded_counts),
            "files_copied": self.files_copied,
            "total_bytes_copied": self.total_bytes_copied,
            "copy_safety_ok": self.copy_safety_ok,
            "unsafe_symlink_count": len(self.unsafe_symlinks),
            "copy_error_count": len(self.copy_errors),
            "copy_budget": self.copy_budget.to_report(
                files_copied=self.files_copied,
                total_bytes_copied=self.total_bytes_copied,
                exceeded=self.copy_budget_exceeded,
                reason=self.copy_budget_exceeded_reason,
            ),
            "symlink_policy": {
                "follow_symlinks": False,
                "absolute_symlinks": "skip",
                "outside_repo_symlinks": "skip",
                "copied_symlink_count": 0,
                "unsafe_symlink_count": len(self.unsafe_symlinks),
            },
            "special_file_policy": {
                "copy_special_files": False,
                "unsupported_entry_count": self.excluded_counts.get("unsupported_filesystem_entry", 0),
            },
            "source_path_redacted": "<repo>",
            "workspace_path_redacted": "<disposable-workspace>",
            "out_path_redacted": "<sandbox-out>",
        }


def target_identity(path: Path) -> str:
    resolved = path.resolve()
    return f"path:{resolved.name}"


def inspect_git_worktree(path: Path) -> dict[str, object]:
    """Read the live Git subject immediately before a workspace copy.

    This probe intentionally does not use the file inventory. Its values are
    returned in memory only; callers must not persist raw paths or Git output.
    """
    target = path.resolve()
    repo_root_output = _git_output(target, ("rev-parse", "--show-toplevel"))
    if repo_root_output is None:
        return {
            "git_available": False,
            "repo_identity": None,
            "repo_root_matches_target": False,
            "commit": None,
            "tree_hash": None,
            "dirty_state": "unknown",
        }

    repo_root = Path(repo_root_output).resolve()
    commit = _git_object_id(target, ("rev-parse", "HEAD"))
    tree_hash = _git_object_id(target, ("rev-parse", "HEAD^{tree}"))
    status_output = _git_output(target, ("status", "--porcelain=v1", "--untracked-files=all"))
    dirty_state = "unknown" if status_output is None else "dirty" if status_output else "clean"
    return {
        "git_available": True,
        "repo_identity": target_identity(repo_root),
        "repo_root_matches_target": repo_root == target,
        "commit": commit,
        "tree_hash": tree_hash,
        "dirty_state": dirty_state,
    }


def _git_output(path: Path, arguments: tuple[str, ...]) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(path), *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


def _git_object_id(path: Path, arguments: tuple[str, ...]) -> str | None:
    value = _git_output(path, arguments)
    if value is None or len(value) not in {40, 64}:
        return None
    if any(character not in "0123456789abcdef" for character in value):
        return None
    return value


def fingerprint_target(path: Path) -> InventoryResult:
    root = path.resolve()
    files, excluded_counts, unsafe_symlinks, errors = _collect_inventory(root)
    return _fingerprint_from_files(root, files, excluded_counts, unsafe_symlinks, errors)


def create_disposable_workspace(source: Path, *, copy_budget: CopyBudget | None = None) -> DisposableWorkspace:
    source_root = source.resolve()
    budget = CopyBudget() if copy_budget is None else copy_budget
    root = Path(tempfile.mkdtemp(prefix="rhd-sandbox-run-"))
    workspace = root / "workspace"
    out = root / "out"
    workspace.mkdir(parents=True, exist_ok=False)
    out.mkdir(parents=True, exist_ok=False)
    result = DisposableWorkspace(source_root=source_root, root=root, workspace=workspace, out=out, copy_budget=budget, created=True)
    _copy_tree(source_root, workspace, source_root, workspace, result)
    return result


def snapshot_workspace(workspace: Path) -> InventoryResult:
    files, excluded_counts, unsafe_symlinks, errors = _collect_inventory(workspace.resolve())
    return _fingerprint_from_files(workspace.resolve(), files, excluded_counts, unsafe_symlinks, errors)


def summarize_workspace_diff(before: InventoryResult | None, after: InventoryResult | None) -> dict[str, Any]:
    if before is None or after is None:
        return {
            "available": False,
            "before_fingerprint": None,
            "after_fingerprint": None,
            "created_count": 0,
            "modified_count": 0,
            "deleted_count": 0,
            "interesting_paths_redacted": [],
            "raw_contents_persisted": False,
            "limitations": ["Workspace diff summary was not available."],
        }
    before_paths = set(before.files)
    after_paths = set(after.files)
    created = sorted(after_paths - before_paths)
    deleted = sorted(before_paths - after_paths)
    modified = sorted(path for path in before_paths & after_paths if before.files[path] != after.files[path])
    interesting = [f"<workspace>/{path}" for path in [*created[:3], *modified[:3], *deleted[:3]][:10]]
    limitations: list[str] = []
    if before.errors or after.errors:
        limitations.append("Workspace inventory had errors; diff evidence is degraded.")
    return {
        "available": not limitations,
        "before_fingerprint": before.fingerprint,
        "after_fingerprint": after.fingerprint,
        "created_count": len(created),
        "modified_count": len(modified),
        "deleted_count": len(deleted),
        "interesting_paths_redacted": interesting,
        "raw_contents_persisted": False,
        "limitations": limitations,
    }


def _collect_inventory(root: Path) -> tuple[list[Path], dict[str, int], list[str], list[str]]:
    files: list[Path] = []
    excluded_counts: dict[str, int] = {}
    unsafe_symlinks: list[str] = []
    errors: list[str] = []
    _walk_inventory(root, root, files, excluded_counts, unsafe_symlinks, errors)
    return files, excluded_counts, unsafe_symlinks, errors


def _walk_inventory(
    current: Path,
    root: Path,
    files: list[Path],
    excluded_counts: dict[str, int],
    unsafe_symlinks: list[str],
    errors: list[str],
) -> None:
    try:
        entries = sorted(os.scandir(current), key=lambda item: item.name)
    except OSError:
        errors.append(_relative(current, root))
        return
    for entry in entries:
        path = Path(entry.path)
        relative = _relative(path, root)
        try:
            mode = entry.stat(follow_symlinks=False).st_mode
        except OSError:
            errors.append(relative)
            continue
        if stat.S_ISLNK(mode):
            unsafe_symlinks.append(relative)
            _count(excluded_counts, "symlink")
            continue
        if stat.S_ISDIR(mode):
            category = DIRECTORY_EXCLUSIONS.get(entry.name)
            if category is not None:
                _count(excluded_counts, category)
                continue
            _walk_inventory(path, root, files, excluded_counts, unsafe_symlinks, errors)
            continue
        if stat.S_ISREG(mode):
            category = _file_exclusion_category(entry.name)
            if category is not None:
                _count(excluded_counts, category)
                continue
            files.append(path)
            continue
        _count(excluded_counts, "unsupported_filesystem_entry")


def _copy_tree(source: Path, destination: Path, root: Path, destination_root: Path, result: DisposableWorkspace) -> None:
    if result.copy_budget_exceeded:
        return
    try:
        entries = sorted(os.scandir(source), key=lambda item: item.name)
    except OSError as exc:
        result.copy_errors.append(f"{_relative(source, root)}: {exc.__class__.__name__}")
        return
    for entry in entries:
        source_path = Path(entry.path)
        destination_path = destination / entry.name
        relative = _relative(source_path, root)
        if not _destination_within_workspace(destination_path, destination_root):
            result.copy_errors.append(f"{relative}: destination_path_traversal")
            continue
        try:
            mode = entry.stat(follow_symlinks=False).st_mode
        except OSError as exc:
            result.copy_errors.append(f"{relative}: {exc.__class__.__name__}")
            continue
        if stat.S_ISLNK(mode):
            result.unsafe_symlinks.append(relative)
            _count(result.excluded_counts, "symlink")
            continue
        if stat.S_ISDIR(mode):
            category = DIRECTORY_EXCLUSIONS.get(entry.name)
            if category is not None:
                _count(result.excluded_counts, category)
                continue
            try:
                destination_path.mkdir()
            except OSError as exc:
                result.copy_errors.append(f"{relative}: {exc.__class__.__name__}")
                continue
            _copy_tree(source_path, destination_path, root, destination_root, result)
            continue
        if stat.S_ISREG(mode):
            category = _file_exclusion_category(entry.name)
            if category is not None:
                _count(result.excluded_counts, category)
                continue
            try:
                file_size = entry.stat(follow_symlinks=False).st_size
            except OSError as exc:
                result.copy_errors.append(f"{relative}: {exc.__class__.__name__}")
                continue
            if not _copy_budget_allows(result, relative, file_size):
                return
            try:
                shutil.copy2(source_path, destination_path, follow_symlinks=False)
            except OSError as exc:
                result.copy_errors.append(f"{relative}: {exc.__class__.__name__}")
                continue
            result.files_copied += 1
            result.total_bytes_copied += file_size
            continue
        _count(result.excluded_counts, "unsupported_filesystem_entry")


def _fingerprint_from_files(
    root: Path,
    files: list[Path],
    excluded_counts: dict[str, int],
    unsafe_symlinks: list[str],
    errors: list[str],
) -> InventoryResult:
    digest = hashlib.sha256()
    file_hashes: dict[str, str] = {}
    total_bytes = 0
    for path in sorted(files, key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        try:
            content = path.read_bytes()
        except OSError:
            errors.append(relative)
            continue
        file_digest = hashlib.sha256(content).hexdigest()
        total_bytes += len(content)
        file_hashes[relative] = f"sha256:{file_digest}"
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(len(content)).encode("ascii"))
        digest.update(b"\0")
        digest.update(file_digest.encode("ascii"))
        digest.update(b"\n")
    return InventoryResult(
        fingerprint=f"sha256:{digest.hexdigest()}",
        file_count=len(file_hashes),
        total_bytes=total_bytes,
        files=file_hashes,
        excluded_counts=dict(sorted(excluded_counts.items())),
        unsafe_symlinks=list(unsafe_symlinks),
        errors=list(errors),
    )


def _file_exclusion_category(name: str) -> str | None:
    if name.startswith(".env."):
        return "credential_like"
    if name in FILE_EXCLUSIONS:
        return FILE_EXCLUSIONS[name]
    for suffix, category in FILE_SUFFIX_EXCLUSIONS.items():
        if name.endswith(suffix):
            return category
    return None


def _relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return "<outside-repo>"


def _destination_within_workspace(path: Path, workspace_root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(workspace_root.resolve(strict=False))
    except ValueError:
        return False
    return True


def _copy_budget_allows(result: DisposableWorkspace, relative: str, file_size: int) -> bool:
    budget = result.copy_budget
    reason: str | None = None
    if file_size > budget.max_file_bytes:
        reason = "max_file_bytes"
    elif result.files_copied + 1 > budget.max_file_count:
        reason = "max_file_count"
    elif result.total_bytes_copied + file_size > budget.max_total_bytes:
        reason = "max_total_bytes"
    if reason is None:
        return True
    result.copy_budget_exceeded = True
    result.copy_budget_exceeded_reason = reason
    result.copy_errors.append(f"{relative}: copy_budget_exceeded:{reason}")
    _count(result.excluded_counts, "copy_budget_exceeded")
    return False


def _count(counts: dict[str, int], category: str) -> None:
    counts[category] = counts.get(category, 0) + 1


def _categories(counts: dict[str, int]) -> list[dict[str, Any]]:
    return [{"category": category, "count": count} for category, count in sorted(counts.items())]
