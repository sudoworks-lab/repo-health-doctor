"""Bounded, no-follow reads for operator-controlled input files."""

from __future__ import annotations

from dataclasses import dataclass
import errno
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any, Callable


CONTROL_FILE_MAX_BYTES = 64 * 1024
CONTROL_FILE_READ_CHUNK_BYTES = 8192


@dataclass(frozen=True)
class ControlFileState:
    device: int
    inode: int
    mode: int
    size: int
    mtime_ns: int
    ctime_ns: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> "ControlFileState":
        return cls(
            device=value.st_dev,
            inode=value.st_ino,
            mode=value.st_mode,
            size=value.st_size,
            mtime_ns=value.st_mtime_ns,
            ctime_ns=value.st_ctime_ns,
        )


@dataclass(frozen=True)
class BoundedControlFile:
    content: bytes
    sha256: str
    state: ControlFileState


@dataclass(frozen=True)
class BoundedJsonDocument:
    payload: Any
    sha256: str
    state: ControlFileState


class ControlFileReadError(ValueError):
    def __init__(self, reason: str, label: str) -> None:
        super().__init__(f"{label} could not be read safely: {reason}")
        self.reason = reason
        self.label = label


def read_bounded_control_file(
    path: str | Path,
    *,
    label: str,
    max_bytes: int = CONTROL_FILE_MAX_BYTES,
    _open: Callable[[os.PathLike[str] | str, int], int] = os.open,
    _fstat: Callable[[int], os.stat_result] = os.fstat,
    _read: Callable[[int, int], bytes] = os.read,
) -> BoundedControlFile:
    if max_bytes < 1:
        raise ControlFileReadError("too_large", label)
    if not hasattr(os, "O_NOFOLLOW"):
        raise ControlFileReadError("no_follow_unsupported", label)
    candidate = Path(path)
    try:
        before = candidate.lstat()
    except FileNotFoundError as exc:
        raise ControlFileReadError("not_found", label) from exc
    except OSError as exc:
        raise ControlFileReadError("file_changed", label) from exc
    if stat.S_ISLNK(before.st_mode):
        raise ControlFileReadError("symlink_refused", label)
    if not stat.S_ISREG(before.st_mode):
        raise ControlFileReadError("not_regular", label)
    if before.st_size > max_bytes:
        raise ControlFileReadError("too_large", label)

    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = _open(candidate, flags)
    except OSError as exc:
        reason = "symlink_refused" if exc.errno == errno.ELOOP else "file_changed"
        raise ControlFileReadError(reason, label) from exc
    try:
        try:
            opened = _fstat(descriptor)
        except OSError as exc:
            raise ControlFileReadError("file_changed", label) from exc
        if (
            not stat.S_ISREG(opened.st_mode)
            or not _same_file_state(before, opened)
        ):
            raise ControlFileReadError("file_changed", label)
        if opened.st_size > max_bytes:
            raise ControlFileReadError("too_large", label)

        content = _bounded_read(
            descriptor,
            max_bytes=max_bytes,
            read_descriptor=_read,
        )
        if content is None:
            raise ControlFileReadError("too_large", label)
        try:
            after = _fstat(descriptor)
        except OSError as exc:
            raise ControlFileReadError("file_changed", label) from exc
        if (
            not _same_file_state(opened, after)
            or len(content) != after.st_size
        ):
            raise ControlFileReadError("file_changed", label)
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass

    return BoundedControlFile(
        content=content,
        sha256="sha256:" + hashlib.sha256(content).hexdigest(),
        state=ControlFileState.from_stat(after),
    )


def load_bounded_json_document(
    path: str | Path,
    *,
    label: str,
    max_bytes: int = CONTROL_FILE_MAX_BYTES,
    _open: Callable[[os.PathLike[str] | str, int], int] = os.open,
    _fstat: Callable[[int], os.stat_result] = os.fstat,
    _read: Callable[[int, int], bytes] = os.read,
) -> BoundedJsonDocument:
    control_file = read_bounded_control_file(
        path,
        label=label,
        max_bytes=max_bytes,
        _open=_open,
        _fstat=_fstat,
        _read=_read,
    )
    try:
        payload = json.loads(control_file.content)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ControlFileReadError("parse_failed", label) from exc
    return BoundedJsonDocument(
        payload=payload,
        sha256=control_file.sha256,
        state=control_file.state,
    )


def control_file_matches(
    left: BoundedJsonDocument,
    right: BoundedJsonDocument,
) -> bool:
    return left.sha256 == right.sha256 and left.state == right.state


def _bounded_read(
    descriptor: int,
    *,
    max_bytes: int,
    read_descriptor: Callable[[int, int], bytes] = os.read,
) -> bytes | None:
    remaining = max_bytes + 1
    chunks: list[bytes] = []
    while remaining:
        chunk = read_descriptor(
            descriptor,
            min(CONTROL_FILE_READ_CHUNK_BYTES, remaining),
        )
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    content = b"".join(chunks)
    return None if len(content) > max_bytes else content


def _same_file_state(left: os.stat_result, right: os.stat_result) -> bool:
    return ControlFileState.from_stat(left) == ControlFileState.from_stat(right)
