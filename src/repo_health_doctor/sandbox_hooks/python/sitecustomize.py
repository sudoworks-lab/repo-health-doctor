from __future__ import annotations

import builtins
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import shutil
from typing import Any


EVENT_FILE_ENV = "RHD_OBSERVER_EVENT_FILE"
SECRET_ENV_NAMES_ENV = "RHD_SECRET_ENV_NAMES"
ALLOWED_WRITE_ROOTS_ENV = "RHD_ALLOWED_WRITE_ROOTS"
SECRET_PATH_MARKERS = (".aws", ".ssh", ".env", ".netrc", ".npmrc", ".pypirc")
SECRET_ENV_NAMES = frozenset(item for item in os.environ.get(SECRET_ENV_NAMES_ENV, "").split(",") if item)
ALLOWED_WRITE_ROOTS = tuple(item for item in os.environ.get(ALLOWED_WRITE_ROOTS_ENV, "").split(",") if item)


def _event_file() -> Path | None:
    value = os.environ.get(EVENT_FILE_ENV)
    return Path(value) if value else None


def _emit(event_type: str, detail: dict[str, Any]) -> None:
    path = _event_file()
    if path is None:
        return
    payload = {"event_type": event_type, "detail": detail}
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
    except OSError:
        return


def _secret_env_names() -> set[str]:
    return set(SECRET_ENV_NAMES)


def _allowed_write_roots() -> tuple[str, ...]:
    return ALLOWED_WRITE_ROOTS


def _classify_zone(file: Any) -> str:
    try:
        raw_path = os.fspath(file)
    except TypeError:
        return "unknown"
    normalized = str(raw_path)
    return (
        "sandbox_writable"
        if any(normalized.startswith(prefix) for prefix in _allowed_write_roots())
        else "outside_sandbox_writable"
    )


_original_open = builtins.open
_original_io_open = io.open


def _observed_open(file: Any, *args: Any, **kwargs: Any):  # type: ignore[no-untyped-def]
    try:
        raw_path = os.fspath(file)
    except TypeError:
        raw_path = ""
    lowered = raw_path.lower()
    if any(marker in lowered for marker in SECRET_PATH_MARKERS):
        _emit("secret_file_open", {"path_category": "credential_like"})
    return _original_open(file, *args, **kwargs)


builtins.open = _observed_open


def _observed_io_open(file: Any, *args: Any, **kwargs: Any):  # type: ignore[no-untyped-def]
    return _observed_open(file, *args, **kwargs)


io.open = _observed_io_open

_env_type = type(os.environ)
_original_env_getitem = _env_type.__getitem__
_original_env_get = _env_type.get
_original_env_keys = _env_type.keys
_original_env_items = _env_type.items
_original_env_values = _env_type.values
_original_env_iter = _env_type.__iter__
_original_env_copy = _env_type.copy


def _observed_env_getitem(self: Any, key: Any) -> Any:
    if isinstance(key, str) and key in _secret_env_names():
        _emit("secret_env_access", {"name_redacted": True})
    return _original_env_getitem(self, key)


def _observed_env_get(self: Any, key: Any, default: Any = None) -> Any:
    if isinstance(key, str) and key in _secret_env_names():
        _emit("secret_env_access", {"name_redacted": True})
    return _original_env_get(self, key, default)


def _observed_env_keys(self: Any) -> Any:
    _emit("env_sweep", {"method": "keys"})
    return _original_env_keys(self)


def _observed_env_items(self: Any) -> Any:
    _emit("env_sweep", {"method": "items"})
    return _original_env_items(self)


def _observed_env_values(self: Any) -> Any:
    _emit("env_sweep", {"method": "values"})
    return _original_env_values(self)


def _observed_env_iter(self: Any) -> Any:
    _emit("env_sweep", {"method": "iter"})
    return _original_env_iter(self)


def _observed_env_copy(self: Any) -> Any:
    _emit("env_sweep", {"method": "copy"})
    return _original_env_copy(self)


_env_type.__getitem__ = _observed_env_getitem
_env_type.get = _observed_env_get
_env_type.keys = _observed_env_keys
_env_type.items = _observed_env_items
_env_type.values = _observed_env_values
_env_type.__iter__ = _observed_env_iter
_env_type.copy = _observed_env_copy

_original_getaddrinfo = socket.getaddrinfo


def _observed_getaddrinfo(*args: Any, **kwargs: Any):  # type: ignore[no-untyped-def]
    _emit("dns_lookup", {"target": "***REDACTED***"})
    return _original_getaddrinfo(*args, **kwargs)


socket.getaddrinfo = _observed_getaddrinfo

_original_socket = socket.socket


class ObservedSocket(_original_socket):
    def connect(self, address: Any) -> Any:  # type: ignore[override]
        _emit("socket_connect", {"target": "***REDACTED***"})
        return super().connect(address)


socket.socket = ObservedSocket

_original_popen = subprocess.Popen
_original_system = os.system
_original_remove = os.remove
_original_unlink = os.unlink
_original_rmdir = os.rmdir
_original_rmtree = shutil.rmtree


class ObservedPopen(_original_popen):
    def __init__(self, args: Any, *extra: Any, **kwargs: Any) -> None:  # type: ignore[no-untyped-def]
        argv0 = ""
        if isinstance(args, (list, tuple)) and args:
            argv0 = os.path.basename(str(args[0]))
        elif isinstance(args, str):
            argv0 = "shell_string"
        _emit("subprocess_spawn", {"argv0": argv0})
        super().__init__(args, *extra, **kwargs)


subprocess.Popen = ObservedPopen


def _observed_system(command: Any) -> int:
    _emit("subprocess_spawn", {"argv0": "os.system"})
    return _original_system(command)


os.system = _observed_system


def _observed_remove(path: Any, *args: Any, **kwargs: Any):  # type: ignore[no-untyped-def]
    _emit("file_delete_attempt", {"zone": _classify_zone(path)})
    return _original_remove(path, *args, **kwargs)


def _observed_unlink(path: Any, *args: Any, **kwargs: Any):  # type: ignore[no-untyped-def]
    _emit("file_delete_attempt", {"zone": _classify_zone(path)})
    return _original_unlink(path, *args, **kwargs)


def _observed_rmdir(path: Any, *args: Any, **kwargs: Any):  # type: ignore[no-untyped-def]
    _emit("file_delete_attempt", {"zone": _classify_zone(path)})
    return _original_rmdir(path, *args, **kwargs)


def _observed_rmtree(path: Any, *args: Any, **kwargs: Any):  # type: ignore[no-untyped-def]
    _emit("file_delete_attempt", {"zone": _classify_zone(path)})
    return _original_rmtree(path, *args, **kwargs)


os.remove = _observed_remove
os.unlink = _observed_unlink
os.rmdir = _observed_rmdir
shutil.rmtree = _observed_rmtree
