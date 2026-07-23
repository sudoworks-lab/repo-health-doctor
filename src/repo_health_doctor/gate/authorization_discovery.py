"""Fail-closed discovery of an untracked execution authorization artifact."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from typing import Any, Mapping

from ..control_file import (
    CONTROL_FILE_MAX_BYTES,
    ControlFileReadError,
    load_bounded_json_document,
)
from ..sandbox.run_workspace import create_verified_snapshot


AUTHORIZATION_DISCOVERY_FILENAME = ".repo-health-doctor.authorization.json"
AUTHORIZATION_DISCOVERY_MAX_BYTES = CONTROL_FILE_MAX_BYTES

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
        document = load_bounded_json_document(
            candidate,
            label="authorization",
            max_bytes=max_bytes,
            _open=os.open,
            _fstat=os.fstat,
            _read=_read_descriptor,
        )
    except ControlFileReadError as exc:
        reason = {
            "not_found": NOT_FOUND,
            "symlink_refused": SYMLINK_REFUSED,
            "too_large": TOO_LARGE,
            "parse_failed": PARSE_FAILED,
        }.get(exc.reason, FILE_CHANGED)
        return _refused(reason)
    authorization = document.payload
    if not isinstance(authorization, dict):
        return _refused(PARSE_FAILED)
    return AuthorizationDiscoveryResult(
        discovered=True,
        authorization=authorization,
        reason=None,
    )


def _read_descriptor(descriptor: int, size: int) -> bytes:
    return os.read(descriptor, size)
def _refused(reason: str) -> AuthorizationDiscoveryResult:
    return AuthorizationDiscoveryResult(
        discovered=False,
        authorization=None,
        reason=reason,
    )
