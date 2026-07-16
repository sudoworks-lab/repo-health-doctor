"""Fail-closed discovery of an untracked execution authorization artifact."""

from __future__ import annotations

from dataclasses import dataclass
import errno
import json
import os
from pathlib import Path
import stat
import subprocess
from typing import Any, Mapping


AUTHORIZATION_DISCOVERY_FILENAME = ".repo-health-doctor.authorization.json"
AUTHORIZATION_DISCOVERY_MAX_BYTES = 64 * 1024
GIT_TIMEOUT_SECONDS = 5.0

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
    top_level = _git_top_level(requested_root)
    if isinstance(top_level, AuthorizationDiscoveryResult):
        return top_level
    if top_level != requested_root:
        return _refused(NOT_A_GIT_REPO)

    tracked = _git_tracked(top_level)
    if isinstance(tracked, AuthorizationDiscoveryResult):
        return tracked
    if tracked:
        return _refused(TRACKED_REFUSED)

    candidate = top_level / AUTHORIZATION_DISCOVERY_FILENAME
    return _read_candidate(candidate, max_bytes=max_bytes)


def discover_authorization(
    repo_path: str | Path,
    *,
    max_bytes: int = AUTHORIZATION_DISCOVERY_MAX_BYTES,
) -> AuthorizationDiscoveryResult:
    """Compatibility name for callers that do not need the longer function name."""
    return discover_execution_authorization(repo_path, max_bytes=max_bytes)


def _git_top_level(root: Path) -> Path | AuthorizationDiscoveryResult:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return _refused(GIT_ERROR)

    if completed.returncode != 0:
        if b"not a git repository" in completed.stderr.lower():
            return _refused(NOT_A_GIT_REPO)
        return _refused(GIT_ERROR)

    try:
        raw_top_level = completed.stdout.rstrip(b"\r\n")
        if not raw_top_level or b"\n" in raw_top_level or b"\r" in raw_top_level:
            return _refused(GIT_ERROR)
        return Path(os.fsdecode(raw_top_level)).resolve(strict=False)
    except (OSError, UnicodeError, ValueError):
        return _refused(GIT_ERROR)


def _git_tracked(root: Path) -> bool | AuthorizationDiscoveryResult:
    try:
        completed = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "ls-files",
                "--error-unmatch",
                "--",
                AUTHORIZATION_DISCOVERY_FILENAME,
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return _refused(GIT_ERROR)

    if completed.returncode == 0:
        return True
    if completed.returncode == 1:
        return False
    return _refused(GIT_ERROR)


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
