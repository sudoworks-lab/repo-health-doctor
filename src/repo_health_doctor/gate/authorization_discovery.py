"""Fail-closed discovery of an untracked execution authorization artifact."""

from __future__ import annotations

from dataclasses import dataclass
import errno
import json
import os
from pathlib import Path
import stat
from typing import Any, Mapping

from ..sandbox.run_workspace import create_verified_snapshot


AUTHORIZATION_DISCOVERY_FILENAME = ".repo-health-doctor.authorization.json"
AUTHORIZATION_DISCOVERY_MAX_BYTES = 64 * 1024

TRACKED_REFUSED = "tracked_refused"
NOT_A_GIT_REPO = "not_a_git_repo"
SYMLINK_REFUSED = "symlink_refused"
NOT_FOUND = "not_found"
PARSE_FAILED = "parse_failed"
TOO_LARGE = "too_large"
GIT_ERROR = "git_error"
FILE_CHANGED = "file_changed"

AUTHORIZATION_DISCOVERY_REFUSAL_REASONS = frozenset(
    {
        TRACKED_REFUSED,
        NOT_A_GIT_REPO,
        SYMLINK_REFUSED,
        NOT_FOUND,
        PARSE_FAILED,
        TOO_LARGE,
        GIT_ERROR,
        FILE_CHANGED,
    }
)


@dataclass(frozen=True)
class AuthorizationDiscoveryResult:
    """A discovered JSON object or a bounded machine-readable refusal."""

    discovered: bool
    authorization: Mapping[str, Any] | None
    reason: str | None


def discover_execution_authorization(
    repo_path: str | Path,
    *,
    max_bytes: int = AUTHORIZATION_DISCOVERY_MAX_BYTES,
    tracked_relative_paths: tuple[str, ...] | None = None,
) -> AuthorizationDiscoveryResult:
    """Read the single untracked authorization candidate at a Git top-level.

    Discovery does not validate or authorize the artifact. Callers must pass a
    successful result through the existing execution authorization validator.
    """
    if max_bytes < 1:
        return _refused(TOO_LARGE)

    try:
        requested_root = Path(repo_path).resolve(strict=False)
    except (OSError, RuntimeError):
        return _refused(NOT_A_GIT_REPO)
    if tracked_relative_paths is None:
        try:
            workspace = create_verified_snapshot(requested_root)
        except OSError:
            return _refused(GIT_ERROR)
        try:
            snapshot = workspace.verified_snapshot
            if snapshot is None or snapshot.source_kind != "git_commit":
                return _refused(NOT_A_GIT_REPO)
            tracked_relative_paths = tuple(
                entry.path
                for entry in snapshot.manifest
                if entry.entry_type == "file"
            )
        finally:
            workspace.cleanup()
    if AUTHORIZATION_DISCOVERY_FILENAME in tracked_relative_paths:
        return _refused(TRACKED_REFUSED)

    candidate = requested_root / AUTHORIZATION_DISCOVERY_FILENAME
    return _read_candidate(candidate, max_bytes=max_bytes)


def discover_authorization(
    repo_path: str | Path,
    *,
    max_bytes: int = AUTHORIZATION_DISCOVERY_MAX_BYTES,
) -> AuthorizationDiscoveryResult:
    """Compatibility name for callers that do not need the longer function name."""
    return discover_execution_authorization(repo_path, max_bytes=max_bytes)


def _read_candidate(candidate: Path, *, max_bytes: int) -> AuthorizationDiscoveryResult:
    try:
        before = candidate.lstat()
    except FileNotFoundError:
        return _refused(NOT_FOUND)
    except OSError:
        return _refused(FILE_CHANGED)

    if stat.S_ISLNK(before.st_mode):
        return _refused(SYMLINK_REFUSED)
    if not stat.S_ISREG(before.st_mode):
        return _refused(FILE_CHANGED)
    if before.st_size > max_bytes:
        return _refused(TOO_LARGE)

    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(candidate, flags)
    except OSError as error:
        if error.errno == errno.ELOOP:
            return _refused(SYMLINK_REFUSED)
        return _refused(FILE_CHANGED)

    try:
        try:
            opened = os.fstat(descriptor)
        except OSError:
            return _refused(FILE_CHANGED)
        if not stat.S_ISREG(opened.st_mode) or not _same_file_state(before, opened):
            return _refused(FILE_CHANGED)
        if opened.st_size > max_bytes:
            return _refused(TOO_LARGE)

        try:
            content = _bounded_read(descriptor, max_bytes=max_bytes)
            after = os.fstat(descriptor)
        except OSError:
            return _refused(FILE_CHANGED)
        if content is None:
            return _refused(TOO_LARGE)
        if not _same_file_state(opened, after) or len(content) != after.st_size:
            return _refused(FILE_CHANGED)
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass

    try:
        authorization = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return _refused(PARSE_FAILED)
    if not isinstance(authorization, dict):
        return _refused(PARSE_FAILED)
    return AuthorizationDiscoveryResult(
        discovered=True,
        authorization=authorization,
        reason=None,
    )


def _bounded_read(descriptor: int, *, max_bytes: int) -> bytes | None:
    remaining = max_bytes + 1
    chunks: list[bytes] = []
    while remaining:
        chunk = _read_descriptor(descriptor, min(8192, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    content = b"".join(chunks)
    if len(content) > max_bytes:
        return None
    return content


def _read_descriptor(descriptor: int, size: int) -> bytes:
    return os.read(descriptor, size)


def _same_file_state(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        left.st_mode,
        left.st_size,
        left.st_mtime_ns,
        left.st_ctime_ns,
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_mode,
        right.st_size,
        right.st_mtime_ns,
        right.st_ctime_ns,
    )


def _refused(reason: str) -> AuthorizationDiscoveryResult:
    return AuthorizationDiscoveryResult(
        discovered=False,
        authorization=None,
        reason=reason,
    )
