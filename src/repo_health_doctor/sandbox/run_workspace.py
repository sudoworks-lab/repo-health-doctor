from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import stat
import subprocess
import tempfile
import time
from typing import Any, BinaryIO, Callable, Iterable

from .workspace import DIRECTORY_EXCLUSIONS, FILE_EXCLUSIONS, FILE_SUFFIX_EXCLUSIONS


SNAPSHOT_SCHEMA_VERSION = "1.0"
COPY_POLICY_VERSION = "verified-snapshot-copy-policy-v1"
FINGERPRINT_METHOD = "verified-snapshot-canonical-manifest-v1"
WORKSPACE_COPY_POLICY = (
    "create a bounded no-follow immutable snapshot; exclude .git, .env, "
    "common caches, and credential-like files; refuse symlinks and special files"
)
DEFAULT_MAX_FILE_COUNT = 20_000
DEFAULT_MAX_DIRECTORY_COUNT = 10_000
DEFAULT_MAX_DEPTH = 64
DEFAULT_MAX_TOTAL_BYTES = 250 * 1024 * 1024
DEFAULT_MAX_FILE_BYTES = 25 * 1024 * 1024
DEFAULT_MAX_RELATIVE_PATH_BYTES = 4096
STREAM_CHUNK_BYTES = 64 * 1024
GIT_MINIMUM_VERSION = (2, 42, 0)
GIT_COMMAND_TIMEOUT_SECONDS = 15
GIT_STDERR_LIMIT_BYTES = 64 * 1024
GIT_ALLOWED_SUBCOMMANDS = frozenset({"rev-parse", "ls-tree", "cat-file"})
TRUSTED_GIT_EXECUTABLE_CANDIDATES = ("/usr/bin/git", "/bin/git")
AUTHORIZATION_CONTROL_FILENAME = ".repo-health-doctor.authorization.json"
_GIT_VERSION = re.compile(r"\bgit version (\d+)\.(\d+)\.(\d+)")
_EventHook = Callable[[str, str], None]


@dataclass(frozen=True)
class CopyBudget:
    max_file_count: int = DEFAULT_MAX_FILE_COUNT
    max_directory_count: int = DEFAULT_MAX_DIRECTORY_COUNT
    max_depth: int = DEFAULT_MAX_DEPTH
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    max_relative_path_bytes: int = DEFAULT_MAX_RELATIVE_PATH_BYTES

    def __post_init__(self) -> None:
        values = (
            self.max_file_count,
            self.max_directory_count,
            self.max_depth,
            self.max_total_bytes,
            self.max_file_bytes,
            self.max_relative_path_bytes,
        )
        if any(isinstance(value, bool) or value <= 0 for value in values):
            raise ValueError("copy budget values must be positive integers")

    def to_report(
        self,
        *,
        files_copied: int,
        total_bytes_copied: int,
        directories_examined: int,
        exceeded: bool,
        reason: str | None,
    ) -> dict[str, Any]:
        return {
            "max_file_count": self.max_file_count,
            "max_directory_count": self.max_directory_count,
            "max_depth": self.max_depth,
            "max_total_bytes": self.max_total_bytes,
            "max_file_bytes": self.max_file_bytes,
            "max_relative_path_bytes": self.max_relative_path_bytes,
            "files_copied": files_copied,
            "directories_examined": directories_examined,
            "total_bytes_copied": total_bytes_copied,
            "copy_budget_exceeded": exceeded,
            "copy_budget_exceeded_reason": reason,
        }


@dataclass(frozen=True)
class SnapshotManifestEntry:
    path: str
    entry_type: str
    mode: str
    size: int
    sha256: str | None

    def to_canonical_dict(self) -> dict[str, object]:
        return {
            "entry_type": self.entry_type,
            "mode": self.mode,
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
        }


@dataclass(frozen=True)
class VerifiedSnapshot:
    schema_version: str
    snapshot_id: str
    source_identity_redacted: str
    source_kind: str
    source_commit: str | None
    source_tree: str | None
    manifest_fingerprint: str
    file_count: int
    total_bytes: int
    copied_at: str
    copy_policy_version: str
    budget_policy: dict[str, int]
    integrity_status: str
    limitations: tuple[str, ...]
    refusal_reasons: tuple[str, ...]
    manifest: tuple[SnapshotManifestEntry, ...] = field(repr=False)

    def to_report(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "snapshot_id": self.snapshot_id,
            "source_identity_redacted": self.source_identity_redacted,
            "source_kind": self.source_kind,
            "source_commit": self.source_commit,
            "source_tree": self.source_tree,
            "manifest_fingerprint": self.manifest_fingerprint,
            "file_count": self.file_count,
            "total_bytes": self.total_bytes,
            "copied_at": self.copied_at,
            "copy_policy_version": self.copy_policy_version,
            "budget_policy": dict(self.budget_policy),
            "integrity_status": self.integrity_status,
            "limitations": list(self.limitations),
            "refusal_reasons": list(self.refusal_reasons),
            "raw_host_path_recorded": False,
            "file_contents_recorded": False,
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
            limitations.append("One or more symlinks were refused by snapshot intake.")
        if self.errors:
            limitations.append("Snapshot intake or integrity verification was incomplete.")
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
    refusal_reasons: list[str] = field(default_factory=list)
    files_copied: int = 0
    files_examined: int = 0
    total_bytes_copied: int = 0
    directories_examined: int = 0
    entries_examined: int = 0
    copy_budget_exceeded: bool = False
    copy_budget_exceeded_reason: str | None = None
    verified_snapshot: VerifiedSnapshot | None = None
    observed_source_commit: str | None = None
    observed_source_tree: str | None = None

    @property
    def copy_safety_ok(self) -> bool:
        return (
            self.verified_snapshot is not None
            and self.verified_snapshot.integrity_status == "verified"
            and not self.unsafe_symlinks
            and not self.copy_errors
            and not self.copy_budget_exceeded
            and not self.refusal_reasons
        )

    def cleanup(self) -> None:
        if self.cleanup_status == "ok":
            return
        try:
            _make_tree_cleanup_writable(self.workspace)
            shutil.rmtree(self.root)
        except OSError as exc:
            self.cleanup_status = "failed"
            self.cleanup_error = exc.__class__.__name__
        else:
            self.cleanup_status = "ok"

    def to_report(self) -> dict[str, Any]:
        return {
            "created": self.created,
            "cleanup": self.cleanup_status,
            "copy_policy": WORKSPACE_COPY_POLICY,
            "copy_policy_version": COPY_POLICY_VERSION,
            "excluded_path_categories": _categories(self.excluded_counts),
            "files_copied": self.files_copied,
            "files_examined": self.files_examined,
            "directories_examined": self.directories_examined,
            "entries_examined": self.entries_examined,
            "total_bytes_copied": self.total_bytes_copied,
            "copy_safety_ok": self.copy_safety_ok,
            "unsafe_symlink_count": len(self.unsafe_symlinks),
            "copy_error_count": len(self.copy_errors),
            "refusal_reasons": list(self.refusal_reasons),
            "verified_snapshot": (
                self.verified_snapshot.to_report()
                if self.verified_snapshot is not None
                else None
            ),
            "copy_budget": self.copy_budget.to_report(
                files_copied=self.files_copied,
                total_bytes_copied=self.total_bytes_copied,
                directories_examined=self.directories_examined,
                exceeded=self.copy_budget_exceeded,
                reason=self.copy_budget_exceeded_reason,
            ),
            "symlink_policy": {
                "follow_symlinks": False,
                "absolute_symlinks": "refuse",
                "outside_repo_symlinks": "refuse",
                "copied_symlink_count": 0,
                "unsafe_symlink_count": len(self.unsafe_symlinks),
            },
            "special_file_policy": {
                "copy_special_files": False,
                "unsupported_entry_count": self.excluded_counts.get(
                    "unsupported_filesystem_entry", 0
                ),
            },
            "source_path_redacted": "<repo>",
            "workspace_path_redacted": "<verified-snapshot>",
            "out_path_redacted": "<sandbox-out>",
        }


@dataclass
class _TraversalFrame:
    source_fd: int
    destination_fd: int
    iterator: Any
    relative_parts: tuple[str, ...]
    source_stat: os.stat_result


class _SnapshotRefusal(RuntimeError):
    def __init__(self, reason: str, relative: str | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.relative = relative


class _BoundedPipeReader:
    def __init__(
        self,
        process: subprocess.Popen[bytes],
        *,
        timeout_seconds: int,
        stderr_limit: int,
    ) -> None:
        if process.stdout is None or process.stderr is None:
            raise RuntimeError("git pipe unavailable")
        self.process = process
        self.stdout = process.stdout
        self.stderr = process.stderr
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.stdout, selectors.EVENT_READ, "stdout")
        self.selector.register(self.stderr, selectors.EVENT_READ, "stderr")
        self.stdout_buffer = bytearray()
        self.stderr_buffer = bytearray()
        self.deadline = time.monotonic() + timeout_seconds
        self.stderr_limit = stderr_limit
        self.stdout_eof = False

    def close(self) -> None:
        self.selector.close()

    def readline(self, limit: int) -> bytes:
        while True:
            newline = self.stdout_buffer.find(b"\n")
            if newline >= 0:
                if newline + 1 > limit:
                    raise _SnapshotRefusal("git_output_line_budget_exceeded")
                value = bytes(self.stdout_buffer[: newline + 1])
                del self.stdout_buffer[: newline + 1]
                return value
            if len(self.stdout_buffer) >= limit:
                raise _SnapshotRefusal("git_output_line_budget_exceeded")
            if self.stdout_eof:
                raise _SnapshotRefusal("git_output_truncated")
            self._pump()

    def read_exact(self, size: int) -> Iterable[bytes]:
        remaining = size
        while remaining:
            if not self.stdout_buffer:
                if self.stdout_eof:
                    raise _SnapshotRefusal("git_output_truncated")
                self._pump()
            take = min(remaining, STREAM_CHUNK_BYTES, len(self.stdout_buffer))
            if take == 0:
                continue
            chunk = bytes(self.stdout_buffer[:take])
            del self.stdout_buffer[:take]
            remaining -= len(chunk)
            yield chunk

    def read_delimited(self, delimiter: bytes, limit: int) -> bytes | None:
        if len(delimiter) != 1 or limit <= 0:
            raise ValueError("bounded delimiter reads require one byte and a positive limit")
        while True:
            marker = self.stdout_buffer.find(delimiter)
            if marker >= 0:
                if marker > limit:
                    raise _SnapshotRefusal("git_output_record_budget_exceeded")
                value = bytes(self.stdout_buffer[:marker])
                del self.stdout_buffer[: marker + 1]
                return value
            if len(self.stdout_buffer) > limit:
                raise _SnapshotRefusal("git_output_record_budget_exceeded")
            if self.stdout_eof:
                if self.stdout_buffer:
                    raise _SnapshotRefusal("git_output_truncated")
                return None
            self._pump()

    def _pump(self) -> None:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise _SnapshotRefusal("git_command_timeout")
        events = self.selector.select(remaining)
        if not events:
            raise _SnapshotRefusal("git_command_timeout")
        for key, _ in events:
            stream = key.fileobj
            chunk = os.read(stream.fileno(), STREAM_CHUNK_BYTES)
            if not chunk:
                self.selector.unregister(stream)
                if key.data == "stdout":
                    self.stdout_eof = True
                continue
            if key.data == "stderr":
                if len(self.stderr_buffer) + len(chunk) > self.stderr_limit:
                    raise _SnapshotRefusal("git_stderr_budget_exceeded")
                self.stderr_buffer.extend(chunk)
            else:
                self.stdout_buffer.extend(chunk)


def target_identity(path: Path) -> str:
    canonical_path = os.fsencode(os.path.abspath(path))
    digest = hashlib.sha256(
        b"repo-health-doctor-local-repository-identity-v1\0" + canonical_path
    ).hexdigest()
    return f"sha256:{digest}"


def inspect_git_worktree(path: Path) -> dict[str, object]:
    """Return a safe snapshot-backed Git observation.

    No high-level Git command is used. A worktree is "clean" only when the
    bounded no-follow live manifest exactly matches the exported commit.
    """
    workspace = create_verified_snapshot(path)
    try:
        snapshot = workspace.verified_snapshot
        git_layout = _looks_like_direct_git_repository(path)
        if snapshot is not None and snapshot.source_kind == "git_commit":
            return {
                "git_available": True,
                "repo_identity": target_identity(path),
                "repo_root_matches_target": True,
                "commit": snapshot.source_commit,
                "tree_hash": snapshot.source_tree,
                "snapshot_id": snapshot.snapshot_id,
                "manifest_fingerprint": snapshot.manifest_fingerprint,
                "dirty_state": "clean",
            }
        dirty = (
            "dirty"
            if "source_worktree_not_exact_commit" in workspace.refusal_reasons
            else "unknown"
        )
        return {
            "git_available": git_layout,
            "repo_identity": target_identity(path) if git_layout else None,
            "repo_root_matches_target": git_layout,
            "commit": workspace.observed_source_commit,
            "tree_hash": workspace.observed_source_tree,
            "snapshot_id": None,
            "manifest_fingerprint": None,
            "dirty_state": dirty,
        }
    finally:
        workspace.cleanup()


def fingerprint_target(path: Path) -> InventoryResult:
    workspace = create_verified_snapshot(path)
    try:
        if workspace.verified_snapshot is None:
            return InventoryResult(
                fingerprint="sha256:" + "0" * 64,
                file_count=0,
                total_bytes=0,
                files={},
                excluded_counts=dict(workspace.excluded_counts),
                unsafe_symlinks=list(workspace.unsafe_symlinks),
                errors=list(workspace.copy_errors or workspace.refusal_reasons),
            )
        return _inventory_from_snapshot(workspace.verified_snapshot)
    finally:
        workspace.cleanup()


def create_disposable_workspace(
    source: Path,
    *,
    copy_budget: CopyBudget | None = None,
) -> DisposableWorkspace:
    return create_verified_snapshot(source, copy_budget=copy_budget)


def create_verified_snapshot(
    source: Path,
    *,
    copy_budget: CopyBudget | None = None,
    _event_hook: _EventHook | None = None,
) -> DisposableWorkspace:
    budget = CopyBudget() if copy_budget is None else copy_budget
    source_root = Path(os.path.abspath(source))
    root = Path(tempfile.mkdtemp(prefix="rhd-verified-snapshot-"))
    os.chmod(root, 0o700)
    workspace_path = root / "workspace"
    out_path = root / "out"
    workspace_path.mkdir(mode=0o700)
    out_path.mkdir(mode=0o700)
    workspace = DisposableWorkspace(
        source_root=source_root,
        root=root,
        workspace=workspace_path,
        out=out_path,
        copy_budget=budget,
        created=True,
    )
    try:
        if not _no_follow_platform_supported():
            raise _SnapshotRefusal("snapshot_platform_no_follow_unsupported")
        source_lstat = os.lstat(source_root)
        if stat.S_ISLNK(source_lstat.st_mode):
            raise _SnapshotRefusal("source_root_symlink")
        if not stat.S_ISDIR(source_lstat.st_mode):
            raise _SnapshotRefusal("source_root_not_directory")
        if _looks_like_direct_git_repository(source_root):
            _create_git_snapshot(workspace, _event_hook)
        else:
            entries = _copy_filesystem_tree(
                source_root,
                workspace.workspace,
                workspace,
                _event_hook,
            )
            _finish_snapshot(
                workspace,
                entries,
                source_kind="filesystem",
                source_commit=None,
                source_tree=None,
                limitations=(
                    "non_git_snapshot_static_scan_only",
                    "real_execution_requires_git_commit_tree_binding",
                ),
            )
        if _event_hook is not None:
            _event_hook("before_source_root_recheck", ".")
        final_source_lstat = os.lstat(source_root)
        if not _same_directory(source_lstat, final_source_lstat):
            raise _SnapshotRefusal("source_root_swap_detected")
    except _SnapshotRefusal as exc:
        _record_refusal(workspace, exc)
        _invalidate_partial_workspace(workspace)
    except OSError as exc:
        _record_refusal(
            workspace,
            _SnapshotRefusal(
                "snapshot_filesystem_error",
                exc.filename if isinstance(exc.filename, str) else None,
            ),
        )
        _invalidate_partial_workspace(workspace)
    return workspace


def verify_verified_snapshot(workspace: DisposableWorkspace) -> bool:
    snapshot = workspace.verified_snapshot
    if snapshot is None or snapshot.integrity_status != "verified":
        return False
    try:
        entries, _, _, _ = _inventory_existing_tree(
            workspace.workspace,
            workspace.copy_budget,
        )
    except _SnapshotRefusal:
        return False
    _, snapshot_id, manifest_fingerprint = _manifest_identity(entries)
    return (
        snapshot_id == snapshot.snapshot_id
        and manifest_fingerprint == snapshot.manifest_fingerprint
        and tuple(entries) == snapshot.manifest
    )


def snapshot_workspace(workspace: Path) -> InventoryResult:
    try:
        entries, excluded_counts, unsafe_symlinks, errors = _inventory_existing_tree(
            workspace,
            CopyBudget(),
        )
    except _SnapshotRefusal as exc:
        return InventoryResult(
            fingerprint="sha256:" + "0" * 64,
            file_count=0,
            total_bytes=0,
            files={},
            errors=[exc.reason],
        )
    _, _, manifest_fingerprint = _manifest_identity(entries)
    files = {
        entry.path: f"sha256:{entry.sha256}"
        for entry in entries
        if entry.entry_type == "file" and entry.sha256 is not None
    }
    return InventoryResult(
        fingerprint=manifest_fingerprint,
        file_count=len(files),
        total_bytes=sum(
            entry.size for entry in entries if entry.entry_type == "file"
        ),
        files=files,
        excluded_counts=excluded_counts,
        unsafe_symlinks=unsafe_symlinks,
        errors=errors,
    )


def summarize_workspace_diff(
    before: InventoryResult | None,
    after: InventoryResult | None,
) -> dict[str, Any]:
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
    modified = sorted(
        path
        for path in before_paths & after_paths
        if before.files[path] != after.files[path]
    )
    interesting = [
        f"<workspace>/{path}"
        for path in [*created[:3], *modified[:3], *deleted[:3]][:10]
    ]
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


def _create_git_snapshot(
    workspace: DisposableWorkspace,
    event_hook: _EventHook | None,
) -> None:
    source = workspace.source_root
    git_dir = source / ".git"
    git_lstat = os.lstat(git_dir)
    if stat.S_ISLNK(git_lstat.st_mode) or not stat.S_ISDIR(git_lstat.st_mode):
        raise _SnapshotRefusal("unsupported_git_layout")
    for unsupported in (
        git_dir / "objects" / "info" / "alternates",
        git_dir / "commondir",
    ):
        try:
            os.lstat(unsupported)
        except FileNotFoundError:
            pass
        else:
            raise _SnapshotRefusal("unsupported_git_object_layout")

    git_path = _git_executable()
    environment = _git_environment(workspace.root)
    version = _git_version(git_path, environment)
    if version is None or version < GIT_MINIMUM_VERSION:
        raise _SnapshotRefusal("unsupported_git_version")

    commit = _git_object_id(
        git_path,
        git_dir,
        source,
        ("rev-parse", "--verify", "HEAD^{commit}"),
        environment,
    )
    tree = _git_object_id(
        git_path,
        git_dir,
        source,
        ("rev-parse", "--verify", "HEAD^{tree}"),
        environment,
    )
    workspace.observed_source_commit = commit
    workspace.observed_source_tree = tree
    if commit is None or tree is None:
        raise _SnapshotRefusal("git_subject_unresolved")

    git_entries = _git_tree_entries(
        git_path,
        git_dir,
        source,
        tree,
        environment,
        workspace,
    )
    exported_entries = _export_git_blobs(
        git_path,
        git_dir,
        source,
        environment,
        git_entries,
        workspace,
    )

    comparison = workspace.root / "live-comparison"
    comparison.mkdir(mode=0o700)
    comparison_workspace = DisposableWorkspace(
        source_root=source,
        root=workspace.root,
        workspace=comparison,
        out=workspace.out,
        copy_budget=workspace.copy_budget,
        created=True,
    )
    try:
        live_entries = _copy_filesystem_tree(
            source,
            comparison,
            comparison_workspace,
            event_hook,
        )
    except _SnapshotRefusal:
        raise
    finally:
        workspace.entries_examined += comparison_workspace.entries_examined
        workspace.files_examined = max(
            workspace.files_examined,
            comparison_workspace.files_examined,
        )
        workspace.directories_examined = max(
            workspace.directories_examined,
            comparison_workspace.directories_examined,
        )
        for category, count in comparison_workspace.excluded_counts.items():
            workspace.excluded_counts[category] = (
                workspace.excluded_counts.get(category, 0) + count
            )
        workspace.unsafe_symlinks.extend(comparison_workspace.unsafe_symlinks)

    if tuple(live_entries) != tuple(exported_entries):
        raise _SnapshotRefusal("source_worktree_not_exact_commit")

    final_commit = _git_object_id(
        git_path,
        git_dir,
        source,
        ("rev-parse", "--verify", "HEAD^{commit}"),
        environment,
    )
    final_tree = _git_object_id(
        git_path,
        git_dir,
        source,
        ("rev-parse", "--verify", "HEAD^{tree}"),
        environment,
    )
    if final_commit != commit or final_tree != tree:
        raise _SnapshotRefusal("git_subject_changed_during_intake")
    shutil.rmtree(comparison)
    workspace.files_copied = sum(
        1 for entry in exported_entries if entry.entry_type == "file"
    )
    workspace.total_bytes_copied = sum(
        entry.size for entry in exported_entries if entry.entry_type == "file"
    )
    _finish_snapshot(
        workspace,
        exported_entries,
        source_kind="git_commit",
        source_commit=commit,
        source_tree=tree,
        limitations=(
            "snapshot_uses_copy_policy_exclusions",
            "linked_worktrees_and_object_alternates_are_unsupported",
        ),
    )


def _copy_filesystem_tree(
    source: Path,
    destination: Path,
    workspace: DisposableWorkspace,
    event_hook: _EventHook | None,
) -> list[SnapshotManifestEntry]:
    root_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    root_flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    source_fd = os.open(source, root_flags)
    destination_fd = os.open(destination, root_flags)
    source_stat = os.fstat(source_fd)
    if not stat.S_ISDIR(source_stat.st_mode):
        os.close(source_fd)
        os.close(destination_fd)
        raise _SnapshotRefusal("source_root_not_directory")
    workspace.directories_examined = 1
    if workspace.directories_examined > workspace.copy_budget.max_directory_count:
        os.close(source_fd)
        os.close(destination_fd)
        _budget_refusal(workspace, "max_directory_count")
    frames: list[_TraversalFrame] = [
        _TraversalFrame(
            source_fd=source_fd,
            destination_fd=destination_fd,
            iterator=os.scandir(source_fd),
            relative_parts=(),
            source_stat=source_stat,
        )
    ]
    entries: list[SnapshotManifestEntry] = []
    try:
        while frames:
            frame = frames[-1]
            try:
                entry = next(frame.iterator)
            except StopIteration:
                after = os.fstat(frame.source_fd)
                if not _same_directory(frame.source_stat, after):
                    raise _SnapshotRefusal(
                        "source_directory_mutated",
                        "/".join(frame.relative_parts) or ".",
                    )
                frame.iterator.close()
                os.close(frame.source_fd)
                os.close(frame.destination_fd)
                frames.pop()
                continue
            workspace.entries_examined += 1
            relative_parts = (*frame.relative_parts, entry.name)
            relative = "/".join(relative_parts)
            _validate_relative_path(relative, workspace.copy_budget)
            try:
                before = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise _SnapshotRefusal(
                    "source_entry_lstat_failed",
                    relative,
                ) from exc
            mode = before.st_mode
            if stat.S_ISLNK(mode):
                workspace.unsafe_symlinks.append(relative)
                _count(workspace.excluded_counts, "symlink")
                raise _SnapshotRefusal("source_symlink_refused", relative)
            if stat.S_ISDIR(mode):
                category = DIRECTORY_EXCLUSIONS.get(entry.name)
                if category is not None:
                    _count(workspace.excluded_counts, category)
                    continue
                depth = len(relative_parts)
                if depth > workspace.copy_budget.max_depth:
                    _budget_refusal(workspace, "max_depth", relative)
                workspace.directories_examined += 1
                if (
                    workspace.directories_examined
                    > workspace.copy_budget.max_directory_count
                ):
                    _budget_refusal(
                        workspace,
                        "max_directory_count",
                        relative,
                    )
                os.mkdir(entry.name, 0o700, dir_fd=frame.destination_fd)
                child_source_fd = os.open(entry.name, root_flags, dir_fd=frame.source_fd)
                child_destination_fd = os.open(
                    entry.name,
                    root_flags,
                    dir_fd=frame.destination_fd,
                )
                child_stat = os.fstat(child_source_fd)
                if not _same_identity(before, child_stat) or not stat.S_ISDIR(
                    child_stat.st_mode
                ):
                    os.close(child_source_fd)
                    os.close(child_destination_fd)
                    raise _SnapshotRefusal("source_directory_swap_detected", relative)
                entries.append(
                    SnapshotManifestEntry(
                        path=relative,
                        entry_type="directory",
                        mode="040755",
                        size=0,
                        sha256=None,
                    )
                )
                frames.append(
                    _TraversalFrame(
                        source_fd=child_source_fd,
                        destination_fd=child_destination_fd,
                        iterator=os.scandir(child_source_fd),
                        relative_parts=relative_parts,
                        source_stat=child_stat,
                    )
                )
                continue
            if stat.S_ISREG(mode):
                _register_file_examined(workspace, relative)
                category = _file_exclusion_category(entry.name)
                if category is not None:
                    _count(workspace.excluded_counts, category)
                    continue
                _preflight_file_budget(workspace, relative, before.st_size)
                if event_hook is not None:
                    event_hook("before_open", relative)
                manifest_entry = _copy_regular_file(
                    frame.source_fd,
                    frame.destination_fd,
                    entry.name,
                    relative,
                    before,
                    event_hook,
                )
                entries.append(manifest_entry)
                workspace.files_copied += 1
                workspace.total_bytes_copied += before.st_size
                continue
            _count(workspace.excluded_counts, "unsupported_filesystem_entry")
            raise _SnapshotRefusal("source_special_file_refused", relative)
    finally:
        for frame in reversed(frames):
            try:
                frame.iterator.close()
            except OSError:
                pass
            for descriptor in (frame.source_fd, frame.destination_fd):
                try:
                    os.close(descriptor)
                except OSError:
                    pass
    return _sort_manifest(entries)


def _copy_regular_file(
    source_directory_fd: int,
    destination_directory_fd: int,
    name: str,
    relative: str,
    before: os.stat_result,
    event_hook: _EventHook | None,
) -> SnapshotManifestEntry:
    source_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    source_flags |= getattr(os, "O_CLOEXEC", 0)
    destination_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    destination_flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(
        os, "O_CLOEXEC", 0
    )
    try:
        source_fd = os.open(name, source_flags, dir_fd=source_directory_fd)
    except OSError as exc:
        raise _SnapshotRefusal("source_open_no_follow_failed", relative) from exc
    destination_fd: int | None = None
    try:
        opened = os.fstat(source_fd)
        if not _same_file_metadata(before, opened):
            raise _SnapshotRefusal("source_file_swap_detected", relative)
        destination_fd = os.open(
            name,
            destination_flags,
            0o600,
            dir_fd=destination_directory_fd,
        )
        digest = hashlib.sha256()
        bytes_read = 0
        while True:
            chunk = os.read(source_fd, STREAM_CHUNK_BYTES)
            if not chunk:
                break
            bytes_read += len(chunk)
            if bytes_read > before.st_size:
                raise _SnapshotRefusal("source_file_grew_during_copy", relative)
            digest.update(chunk)
            _write_all(destination_fd, chunk)
            if event_hook is not None:
                event_hook("after_chunk", relative)
        os.fsync(destination_fd)
        after = os.fstat(source_fd)
        destination_stat = os.fstat(destination_fd)
        os.lseek(source_fd, 0, os.SEEK_SET)
        validation_digest = hashlib.sha256()
        validation_bytes = 0
        while True:
            validation_chunk = os.read(source_fd, STREAM_CHUNK_BYTES)
            if not validation_chunk:
                break
            validation_bytes += len(validation_chunk)
            validation_digest.update(validation_chunk)
        validated = os.fstat(source_fd)
        if (
            bytes_read != before.st_size
            or not _same_file_metadata(before, after)
            or validation_bytes != bytes_read
            or validation_digest.digest() != digest.digest()
            or not _same_file_metadata(after, validated)
            or not stat.S_ISREG(destination_stat.st_mode)
            or destination_stat.st_size != bytes_read
        ):
            raise _SnapshotRefusal("source_file_mutated_during_copy", relative)
    finally:
        try:
            os.close(source_fd)
        except OSError:
            pass
        if destination_fd is not None:
            try:
                os.close(destination_fd)
            except OSError:
                pass
    mode = _canonical_file_mode(before.st_mode)
    os.chmod(name, 0o555 if mode == "100755" else 0o444, dir_fd=destination_directory_fd)
    return SnapshotManifestEntry(
        path=relative,
        entry_type="file",
        mode=mode,
        size=before.st_size,
        sha256=digest.hexdigest(),
    )


def _inventory_existing_tree(
    root: Path,
    budget: CopyBudget,
) -> tuple[list[SnapshotManifestEntry], dict[str, int], list[str], list[str]]:
    root_path = Path(os.path.abspath(root))
    source_fd = os.open(
        root_path,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    source_stat = os.fstat(source_fd)
    frames: list[tuple[int, Any, tuple[str, ...], os.stat_result]] = [
        (source_fd, os.scandir(source_fd), (), source_stat)
    ]
    entries: list[SnapshotManifestEntry] = []
    excluded_counts: dict[str, int] = {}
    unsafe_symlinks: list[str] = []
    errors: list[str] = []
    file_count = 0
    directory_count = 1
    total_bytes = 0
    try:
        while frames:
            fd, iterator, parts, directory_before = frames[-1]
            try:
                entry = next(iterator)
            except StopIteration:
                if not _same_directory(directory_before, os.fstat(fd)):
                    raise _SnapshotRefusal("snapshot_directory_mutated")
                iterator.close()
                os.close(fd)
                frames.pop()
                continue
            relative_parts = (*parts, entry.name)
            relative = "/".join(relative_parts)
            _validate_relative_path(relative, budget)
            before = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode):
                unsafe_symlinks.append(relative)
                raise _SnapshotRefusal("snapshot_symlink_detected")
            if stat.S_ISDIR(before.st_mode):
                if len(relative_parts) > budget.max_depth:
                    raise _SnapshotRefusal("max_depth")
                directory_count += 1
                if directory_count > budget.max_directory_count:
                    raise _SnapshotRefusal("max_directory_count")
                child = os.open(
                    entry.name,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=fd,
                )
                opened = os.fstat(child)
                if not _same_identity(before, opened):
                    os.close(child)
                    raise _SnapshotRefusal("snapshot_directory_swap_detected")
                entries.append(
                    SnapshotManifestEntry(
                        path=relative,
                        entry_type="directory",
                        mode="040755",
                        size=0,
                        sha256=None,
                    )
                )
                frames.append((child, os.scandir(child), relative_parts, opened))
                continue
            if not stat.S_ISREG(before.st_mode):
                raise _SnapshotRefusal("snapshot_special_file_detected")
            file_count += 1
            total_bytes += before.st_size
            if file_count > budget.max_file_count:
                raise _SnapshotRefusal("max_file_count")
            if before.st_size > budget.max_file_bytes:
                raise _SnapshotRefusal("max_file_bytes")
            if total_bytes > budget.max_total_bytes:
                raise _SnapshotRefusal("max_total_bytes")
            file_fd = os.open(
                entry.name,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=fd,
            )
            try:
                opened = os.fstat(file_fd)
                if not _same_file_metadata(before, opened):
                    raise _SnapshotRefusal("snapshot_file_swap_detected")
                digest = hashlib.sha256()
                observed = 0
                while True:
                    chunk = os.read(file_fd, STREAM_CHUNK_BYTES)
                    if not chunk:
                        break
                    observed += len(chunk)
                    digest.update(chunk)
                after = os.fstat(file_fd)
                if observed != before.st_size or not _same_file_metadata(
                    before, after
                ):
                    raise _SnapshotRefusal("snapshot_file_mutated")
            finally:
                os.close(file_fd)
            entries.append(
                SnapshotManifestEntry(
                    path=relative,
                    entry_type="file",
                    mode=_canonical_file_mode(before.st_mode),
                    size=before.st_size,
                    sha256=digest.hexdigest(),
                )
            )
    finally:
        for fd, iterator, _, _ in reversed(frames):
            try:
                iterator.close()
            except OSError:
                pass
            try:
                os.close(fd)
            except OSError:
                pass
    return _sort_manifest(entries), excluded_counts, unsafe_symlinks, errors


def _git_tree_entries(
    git_path: str,
    git_dir: Path,
    work_tree: Path,
    tree: str,
    environment: dict[str, str],
    workspace: DisposableWorkspace,
) -> list[tuple[str, str, int, str]]:
    arguments = _git_repository_argv(
        git_path,
        git_dir,
        work_tree,
        ("ls-tree", "-rz", "-l", "--full-tree", tree),
    )
    process = subprocess.Popen(
        arguments,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        cwd=workspace.root,
        shell=False,
        bufsize=0,
    )
    reader = _BoundedPipeReader(
        process,
        timeout_seconds=GIT_COMMAND_TIMEOUT_SECONDS,
        stderr_limit=GIT_STDERR_LIMIT_BYTES,
    )
    entries: list[tuple[str, str, int, str]] = []
    directory_paths: set[str] = set()
    total_bytes = 0
    try:
        while True:
            record = reader.read_delimited(
                b"\0",
                workspace.copy_budget.max_relative_path_bytes + 256,
            )
            if record is None:
                break
            workspace.entries_examined += 1
            try:
                metadata, raw_path = record.split(b"\t", 1)
                mode, object_type, object_id, raw_size = metadata.split(b" ", 3)
                relative = raw_path.decode("utf-8", "strict")
            except (ValueError, UnicodeDecodeError) as exc:
                raise _SnapshotRefusal("git_tree_output_invalid") from exc
            _validate_relative_path(relative, workspace.copy_budget)
            _register_file_examined(workspace, relative)
            relative_parts = relative.split("/")
            directory_parts = relative_parts[:-1]
            if len(directory_parts) > workspace.copy_budget.max_depth:
                _budget_refusal(workspace, "max_depth", relative)
            for index in range(1, len(directory_parts) + 1):
                directory = "/".join(directory_parts[:index])
                if directory in directory_paths:
                    continue
                directory_paths.add(directory)
                if (
                    len(directory_paths) + 1
                    > workspace.copy_budget.max_directory_count
                ):
                    _budget_refusal(
                        workspace,
                        "max_directory_count",
                        relative,
                    )
            if object_type != b"blob" or mode not in {b"100644", b"100755"}:
                raise _SnapshotRefusal("git_tree_unsupported_entry", relative)
            try:
                size = int(raw_size)
            except ValueError as exc:
                raise _SnapshotRefusal("git_tree_size_invalid", relative) from exc
            path_name = relative_parts[-1]
            if relative == AUTHORIZATION_CONTROL_FILENAME:
                raise _SnapshotRefusal("tracked_authorization_artifact_refused")
            exclusion = _path_exclusion_category(relative, path_name)
            if exclusion is not None:
                _count(workspace.excluded_counts, exclusion)
                continue
            if size < 0:
                raise _SnapshotRefusal("git_tree_size_invalid", relative)
            _preflight_file_budget_values(
                workspace,
                relative,
                size,
                next_file_count=workspace.files_examined,
                next_total_bytes=total_bytes + size,
            )
            oid = object_id.decode("ascii", "strict")
            if not _valid_object_id(oid):
                raise _SnapshotRefusal("git_tree_object_id_invalid", relative)
            entries.append((relative, mode.decode("ascii"), size, oid))
            total_bytes += size
        try:
            return_code = process.wait(timeout=1)
        except subprocess.TimeoutExpired as exc:
            raise _SnapshotRefusal("git_command_timeout") from exc
        if return_code != 0 or reader.stderr_buffer:
            raise _SnapshotRefusal("git_command_failed")
    except BaseException:
        process.kill()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        raise
    finally:
        reader.close()
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                stream.close()
    workspace.directories_examined = max(
        workspace.directories_examined,
        len(directory_paths) + 1,
    )
    return entries


def _export_git_blobs(
    git_path: str,
    git_dir: Path,
    work_tree: Path,
    environment: dict[str, str],
    git_entries: list[tuple[str, str, int, str]],
    workspace: DisposableWorkspace,
) -> list[SnapshotManifestEntry]:
    arguments = _git_repository_argv(
        git_path,
        git_dir,
        work_tree,
        ("cat-file", "--batch"),
    )
    process = subprocess.Popen(
        arguments,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        cwd=workspace.root,
        shell=False,
        bufsize=0,
    )
    reader = _BoundedPipeReader(
        process,
        timeout_seconds=GIT_COMMAND_TIMEOUT_SECONDS,
        stderr_limit=GIT_STDERR_LIMIT_BYTES,
    )
    manifest: list[SnapshotManifestEntry] = []
    created_directories: set[str] = set()
    try:
        if process.stdin is None:
            raise _SnapshotRefusal("git_batch_input_unavailable")
        for relative, mode, expected_size, expected_oid in git_entries:
            process.stdin.write(expected_oid.encode("ascii") + b"\n")
            process.stdin.flush()
            header = reader.readline(512).rstrip(b"\n")
            parts = header.split(b" ")
            if len(parts) != 3:
                raise _SnapshotRefusal("git_batch_header_invalid")
            returned_oid, object_type, raw_size = parts
            try:
                observed_size = int(raw_size)
            except ValueError as exc:
                raise _SnapshotRefusal("git_batch_size_invalid") from exc
            if (
                returned_oid.decode("ascii", "strict") != expected_oid
                or object_type != b"blob"
                or observed_size != expected_size
            ):
                raise _SnapshotRefusal("git_batch_object_mismatch")
            destination = workspace.workspace / relative
            _create_git_destination_directories(
                destination.parent,
                workspace.workspace,
                created_directories,
                manifest,
            )
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            destination_fd = os.open(destination, flags, 0o600)
            digest = hashlib.sha256()
            object_digest = hashlib.sha1() if len(expected_oid) == 40 else hashlib.sha256()
            object_digest.update(f"blob {expected_size}\0".encode("ascii"))
            observed_bytes = 0
            try:
                for chunk in reader.read_exact(expected_size):
                    observed_bytes += len(chunk)
                    digest.update(chunk)
                    object_digest.update(chunk)
                    _write_all(destination_fd, chunk)
                separator = b"".join(reader.read_exact(1))
                if separator != b"\n":
                    raise _SnapshotRefusal("git_batch_separator_invalid")
                os.fsync(destination_fd)
                destination_stat = os.fstat(destination_fd)
                if (
                    observed_bytes != expected_size
                    or destination_stat.st_size != expected_size
                    or object_digest.hexdigest() != expected_oid
                ):
                    raise _SnapshotRefusal("git_blob_integrity_mismatch")
            finally:
                os.close(destination_fd)
            os.chmod(destination, 0o555 if mode == "100755" else 0o444)
            manifest.append(
                SnapshotManifestEntry(
                    path=relative,
                    entry_type="file",
                    mode=mode,
                    size=expected_size,
                    sha256=digest.hexdigest(),
                )
            )
        process.stdin.close()
        try:
            return_code = process.wait(timeout=GIT_COMMAND_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired as exc:
            process.kill()
            process.wait()
            raise _SnapshotRefusal("git_command_timeout") from exc
        if return_code != 0 or reader.stderr_buffer:
            raise _SnapshotRefusal("git_batch_failed")
    except BaseException:
        process.kill()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        raise
    finally:
        reader.close()
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
    return _sort_manifest(manifest)


def _create_git_destination_directories(
    destination_parent: Path,
    workspace_root: Path,
    created: set[str],
    manifest: list[SnapshotManifestEntry],
) -> None:
    try:
        relative_parent = destination_parent.relative_to(workspace_root)
    except ValueError as exc:
        raise _SnapshotRefusal("git_destination_path_escape") from exc
    current = workspace_root
    for part in relative_parent.parts:
        current = current / part
        relative = current.relative_to(workspace_root).as_posix()
        if relative in created:
            continue
        current.mkdir(mode=0o700)
        created.add(relative)
        manifest.append(
            SnapshotManifestEntry(
                path=relative,
                entry_type="directory",
                mode="040755",
                size=0,
                sha256=None,
            )
        )


def _finish_snapshot(
    workspace: DisposableWorkspace,
    entries: list[SnapshotManifestEntry],
    *,
    source_kind: str,
    source_commit: str | None,
    source_tree: str | None,
    limitations: tuple[str, ...],
) -> None:
    sorted_entries, snapshot_id, manifest_fingerprint = _manifest_identity(entries)
    _make_snapshot_read_only(workspace.workspace)
    budget = workspace.copy_budget
    snapshot = VerifiedSnapshot(
        schema_version=SNAPSHOT_SCHEMA_VERSION,
        snapshot_id=snapshot_id,
        source_identity_redacted=target_identity(workspace.source_root),
        source_kind=source_kind,
        source_commit=source_commit,
        source_tree=source_tree,
        manifest_fingerprint=manifest_fingerprint,
        file_count=sum(
            1 for entry in sorted_entries if entry.entry_type == "file"
        ),
        total_bytes=sum(
            entry.size for entry in sorted_entries if entry.entry_type == "file"
        ),
        copied_at=_utc_now(),
        copy_policy_version=COPY_POLICY_VERSION,
        budget_policy={
            "max_file_count": budget.max_file_count,
            "max_directory_count": budget.max_directory_count,
            "max_depth": budget.max_depth,
            "max_total_bytes": budget.max_total_bytes,
            "max_file_bytes": budget.max_file_bytes,
            "max_relative_path_bytes": budget.max_relative_path_bytes,
        },
        integrity_status="verified",
        limitations=limitations,
        refusal_reasons=(),
        manifest=tuple(sorted_entries),
    )
    workspace.verified_snapshot = snapshot
    workspace.files_copied = snapshot.file_count
    workspace.total_bytes_copied = snapshot.total_bytes
    if not verify_verified_snapshot(workspace):
        workspace.verified_snapshot = None
        raise _SnapshotRefusal("snapshot_post_copy_verification_failed")


def _manifest_identity(
    entries: Iterable[SnapshotManifestEntry],
) -> tuple[list[SnapshotManifestEntry], str, str]:
    sorted_entries = _sort_manifest(entries)
    canonical = json.dumps(
        {
            "copy_policy_version": COPY_POLICY_VERSION,
            "entries": [entry.to_canonical_dict() for entry in sorted_entries],
            "schema_version": SNAPSHOT_SCHEMA_VERSION,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    manifest_digest = hashlib.sha256(canonical).hexdigest()
    snapshot_digest = hashlib.sha256(
        b"repo-health-doctor-verified-snapshot-v1\0" + canonical
    ).hexdigest()
    return (
        sorted_entries,
        f"sha256:{snapshot_digest}",
        f"sha256:{manifest_digest}",
    )


def _inventory_from_snapshot(snapshot: VerifiedSnapshot) -> InventoryResult:
    files = {
        entry.path: f"sha256:{entry.sha256}"
        for entry in snapshot.manifest
        if entry.entry_type == "file" and entry.sha256 is not None
    }
    return InventoryResult(
        fingerprint=snapshot.manifest_fingerprint,
        file_count=snapshot.file_count,
        total_bytes=snapshot.total_bytes,
        files=files,
    )


def _git_executable() -> str:
    for candidate in TRUSTED_GIT_EXECUTABLE_CANDIDATES:
        try:
            candidate_stat = os.stat(candidate)
        except OSError:
            continue
        if not stat.S_ISREG(candidate_stat.st_mode):
            continue
        if candidate_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            continue
        return str(Path(candidate).resolve())
    raise _SnapshotRefusal("git_executable_unavailable")


def _git_environment(private_home: Path) -> dict[str, str]:
    return {
        "HOME": str(private_home),
        "XDG_CONFIG_HOME": str(private_home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/false",
        "SSH_ASKPASS": "/bin/false",
        "GIT_EDITOR": "/bin/false",
        "GIT_SEQUENCE_EDITOR": "/bin/false",
        "GIT_PAGER": "",
        "PAGER": "",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_LITERAL_PATHSPECS": "1",
        "GIT_PROTOCOL_FROM_USER": "0",
        "GIT_ALLOW_PROTOCOL": "",
        "GIT_SSH": "/bin/false",
        "GIT_SSH_COMMAND": "/bin/false",
        "GIT_PROXY_COMMAND": "/bin/false",
        "TMPDIR": str(private_home),
    }


def _git_version(
    git_path: str,
    environment: dict[str, str],
) -> tuple[int, int, int] | None:
    output = _run_standalone_git_capture(
        (git_path, "--version"),
        environment,
        stdout_limit=256,
    )
    match = _GIT_VERSION.search(output.decode("ascii", "replace"))
    if match is None:
        return None
    return tuple(int(item) for item in match.groups())  # type: ignore[return-value]


def _git_object_id(
    git_path: str,
    git_dir: Path,
    work_tree: Path,
    arguments: tuple[str, ...],
    environment: dict[str, str],
) -> str | None:
    try:
        output = _run_git_capture(
            git_path,
            git_dir,
            work_tree,
            arguments,
            environment,
            stdout_limit=256,
        ).strip()
    except _SnapshotRefusal:
        return None
    try:
        value = output.decode("ascii")
    except UnicodeDecodeError:
        return None
    return value if _valid_object_id(value) else None


def _run_git_capture(
    git_path: str,
    git_dir: Path,
    work_tree: Path,
    arguments: tuple[str, ...],
    environment: dict[str, str],
    *,
    stdout_limit: int,
) -> bytes:
    if not arguments or arguments[0] not in GIT_ALLOWED_SUBCOMMANDS:
        raise _SnapshotRefusal("git_command_not_allowlisted")
    return _run_standalone_git_capture(
        tuple(_git_repository_argv(git_path, git_dir, work_tree, arguments)),
        environment,
        stdout_limit=stdout_limit,
    )


def _run_standalone_git_capture(
    argv: tuple[str, ...],
    environment: dict[str, str],
    *,
    stdout_limit: int,
) -> bytes:
    process = subprocess.Popen(
        list(argv),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        cwd=environment["HOME"],
        shell=False,
        bufsize=0,
    )
    reader = _BoundedPipeReader(
        process,
        timeout_seconds=GIT_COMMAND_TIMEOUT_SECONDS,
        stderr_limit=GIT_STDERR_LIMIT_BYTES,
    )
    output = bytearray()
    try:
        while True:
            if reader.stdout_eof and not reader.stdout_buffer:
                break
            if reader.stdout_buffer:
                chunk = bytes(reader.stdout_buffer[:STREAM_CHUNK_BYTES])
                del reader.stdout_buffer[: len(chunk)]
            else:
                reader._pump()
                continue
            if len(output) + len(chunk) > stdout_limit:
                raise _SnapshotRefusal("git_stdout_budget_exceeded")
            output.extend(chunk)
        try:
            return_code = process.wait(timeout=1)
        except subprocess.TimeoutExpired as exc:
            raise _SnapshotRefusal("git_command_timeout") from exc
        while reader.stdout_buffer:
            take = min(STREAM_CHUNK_BYTES, len(reader.stdout_buffer))
            if len(output) + take > stdout_limit:
                raise _SnapshotRefusal("git_stdout_budget_exceeded")
            output.extend(reader.stdout_buffer[:take])
            del reader.stdout_buffer[:take]
        if return_code != 0 or reader.stderr_buffer:
            raise _SnapshotRefusal("git_command_failed")
        return bytes(output)
    except BaseException:
        process.kill()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        raise
    finally:
        reader.close()
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                stream.close()


def _git_repository_argv(
    git_path: str,
    git_dir: Path,
    work_tree: Path,
    arguments: tuple[str, ...],
) -> list[str]:
    if not arguments or arguments[0] not in GIT_ALLOWED_SUBCOMMANDS:
        raise _SnapshotRefusal("git_command_not_allowlisted")
    return [
        git_path,
        "--no-pager",
        "--no-replace-objects",
        f"--git-dir={git_dir}",
        f"--work-tree={work_tree}",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "credential.helper=",
        "-c",
        "core.attributesFile=/dev/null",
        "-c",
        "protocol.allow=never",
        "-c",
        "submodule.recurse=false",
        "-c",
        "diff.external=",
        *arguments,
    ]


def _looks_like_direct_git_repository(source: Path) -> bool:
    git_dir = source / ".git"
    try:
        git_stat = os.lstat(git_dir)
        head_stat = os.lstat(git_dir / "HEAD")
        objects_stat = os.lstat(git_dir / "objects")
    except OSError:
        return False
    return (
        stat.S_ISDIR(git_stat.st_mode)
        and not stat.S_ISLNK(git_stat.st_mode)
        and stat.S_ISREG(head_stat.st_mode)
        and not stat.S_ISLNK(head_stat.st_mode)
        and stat.S_ISDIR(objects_stat.st_mode)
        and not stat.S_ISLNK(objects_stat.st_mode)
    )


def _valid_object_id(value: str) -> bool:
    return (
        len(value) in {40, 64}
        and value == value.lower()
        and all(character in "0123456789abcdef" for character in value)
    )


def _preflight_file_budget(
    workspace: DisposableWorkspace,
    relative: str,
    file_size: int,
) -> None:
    _preflight_file_budget_values(
        workspace,
        relative,
        file_size,
        next_file_count=workspace.files_examined,
        next_total_bytes=workspace.total_bytes_copied + file_size,
    )


def _register_file_examined(
    workspace: DisposableWorkspace,
    relative: str,
) -> None:
    workspace.files_examined += 1
    if workspace.files_examined > workspace.copy_budget.max_file_count:
        _budget_refusal(workspace, "max_file_count", relative)


def _preflight_file_budget_values(
    workspace: DisposableWorkspace,
    relative: str,
    file_size: int,
    *,
    next_file_count: int,
    next_total_bytes: int,
) -> None:
    if file_size > workspace.copy_budget.max_file_bytes:
        _budget_refusal(workspace, "max_file_bytes", relative)
    if next_file_count > workspace.copy_budget.max_file_count:
        _budget_refusal(workspace, "max_file_count", relative)
    if next_total_bytes > workspace.copy_budget.max_total_bytes:
        _budget_refusal(workspace, "max_total_bytes", relative)


def _budget_refusal(
    workspace: DisposableWorkspace,
    reason: str,
    relative: str | None = None,
) -> None:
    workspace.copy_budget_exceeded = True
    workspace.copy_budget_exceeded_reason = reason
    _count(workspace.excluded_counts, "copy_budget_exceeded")
    raise _SnapshotRefusal(reason, relative)


def _validate_relative_path(relative: str, budget: CopyBudget) -> None:
    if not relative or relative.startswith("/") or "\\" in relative:
        raise _SnapshotRefusal("relative_path_invalid")
    parts = relative.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise _SnapshotRefusal("relative_path_invalid")
    try:
        encoded = relative.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise _SnapshotRefusal("relative_path_not_utf8") from exc
    if len(encoded) > budget.max_relative_path_bytes:
        raise _SnapshotRefusal("max_relative_path_bytes")


def _path_exclusion_category(relative: str, name: str) -> str | None:
    for part in relative.split("/")[:-1]:
        category = DIRECTORY_EXCLUSIONS.get(part)
        if category is not None:
            return category
    return _file_exclusion_category(name)


def _file_exclusion_category(name: str) -> str | None:
    if name == AUTHORIZATION_CONTROL_FILENAME or name.startswith(
        AUTHORIZATION_CONTROL_FILENAME + "."
    ):
        return "control_plane_artifact"
    if name.startswith(".env."):
        return "credential_like"
    if name in FILE_EXCLUSIONS:
        return FILE_EXCLUSIONS[name]
    for suffix, category in FILE_SUFFIX_EXCLUSIONS.items():
        if name.endswith(suffix):
            return category
    return None


def _same_identity(before: os.stat_result, after: os.stat_result) -> bool:
    return before.st_dev == after.st_dev and before.st_ino == after.st_ino


def _same_file_metadata(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        _same_identity(before, after)
        and stat.S_ISREG(before.st_mode)
        and stat.S_ISREG(after.st_mode)
        and stat.S_IMODE(before.st_mode) == stat.S_IMODE(after.st_mode)
        and before.st_size == after.st_size
        and before.st_mtime_ns == after.st_mtime_ns
        and before.st_ctime_ns == after.st_ctime_ns
    )


def _same_directory(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        _same_identity(before, after)
        and stat.S_ISDIR(before.st_mode)
        and stat.S_ISDIR(after.st_mode)
        and before.st_mtime_ns == after.st_mtime_ns
        and before.st_ctime_ns == after.st_ctime_ns
    )


def _no_follow_platform_supported() -> bool:
    return bool(
        getattr(os, "O_NOFOLLOW", 0)
        and getattr(os, "O_DIRECTORY", 0)
        and os.open in os.supports_dir_fd
        and os.stat in os.supports_follow_symlinks
    )


def _canonical_file_mode(mode: int) -> str:
    return "100755" if mode & 0o111 else "100644"


def _write_all(descriptor: int, value: bytes) -> None:
    view = memoryview(value)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise _SnapshotRefusal("snapshot_write_made_no_progress")
        view = view[written:]


def _make_snapshot_read_only(root: Path) -> None:
    pending = [root]
    while pending:
        current = pending.pop()
        try:
            iterator = os.scandir(current)
        except OSError as exc:
            raise _SnapshotRefusal("snapshot_directory_open_failed") from exc
        with iterator:
            for entry in iterator:
                mode = entry.stat(follow_symlinks=False).st_mode
                path = Path(entry.path)
                if stat.S_ISLNK(mode):
                    raise _SnapshotRefusal("snapshot_symlink_detected")
                if stat.S_ISDIR(mode):
                    pending.append(path)
                    continue
                if not stat.S_ISREG(mode):
                    raise _SnapshotRefusal("snapshot_special_file_detected")
                path.chmod(0o555 if mode & 0o111 else 0o444)
        current.chmod(0o555)


def _invalidate_partial_workspace(workspace: DisposableWorkspace) -> None:
    workspace.verified_snapshot = None
    workspace.files_copied = 0
    workspace.total_bytes_copied = 0
    _make_tree_cleanup_writable(workspace.workspace)
    try:
        shutil.rmtree(workspace.workspace)
        workspace.workspace.mkdir(mode=0o700)
    except OSError:
        if "partial_snapshot_cleanup_failed" not in workspace.refusal_reasons:
            workspace.refusal_reasons.append("partial_snapshot_cleanup_failed")


def _make_tree_cleanup_writable(root: Path) -> None:
    try:
        root_stat = os.lstat(root)
    except OSError:
        return
    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
        return
    pending = [root]
    while pending:
        current = pending.pop()
        try:
            os.chmod(current, 0o700, follow_symlinks=False)
            iterator = os.scandir(current)
        except OSError:
            continue
        with iterator:
            for entry in iterator:
                try:
                    mode = entry.stat(follow_symlinks=False).st_mode
                except OSError:
                    continue
                if stat.S_ISDIR(mode) and not stat.S_ISLNK(mode):
                    pending.append(Path(entry.path))


def _record_refusal(
    workspace: DisposableWorkspace,
    refusal: _SnapshotRefusal,
) -> None:
    if refusal.reason not in workspace.refusal_reasons:
        workspace.refusal_reasons.append(refusal.reason)
    if refusal.reason.startswith("source_symlink"):
        if refusal.relative and refusal.relative not in workspace.unsafe_symlinks:
            workspace.unsafe_symlinks.append(refusal.relative)
    message = refusal.reason
    if refusal.relative and refusal.relative not in {".", ""}:
        message = f"{refusal.relative}: {refusal.reason}"
    if message not in workspace.copy_errors:
        workspace.copy_errors.append(message)


def _sort_manifest(
    entries: Iterable[SnapshotManifestEntry],
) -> list[SnapshotManifestEntry]:
    values = list(entries)
    values.sort(key=lambda entry: (entry.path.encode("utf-8"), entry.entry_type))
    return values


def _count(counts: dict[str, int], category: str) -> None:
    counts[category] = counts.get(category, 0) + 1


def _categories(counts: dict[str, int]) -> list[dict[str, Any]]:
    return [
        {"category": category, "count": count}
        for category, count in sorted(counts.items())
    ]


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
