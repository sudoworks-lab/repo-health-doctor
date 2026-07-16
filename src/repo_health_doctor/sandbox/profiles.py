from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from importlib import resources
import os
from pathlib import Path
from typing import Any


PROFILE_LOCKED_DOWN = "locked-down"
PROFILE_INSPECT_ONLY = "inspect-only"
PROFILE_DEV_PERMISSIVE = "dev-permissive"
PROFILE_NO_NETWORK_DEFAULT = "no-network-default"
PROFILE_NO_NETWORK_READONLY = "no-network-readonly"
PROFILE_NETWORK_EXPLICIT = "network-explicit"
PROFILE_MOBY_DEFAULT = "rhd-moby-default-v1"
SECCOMP_RUNTIME_DEFAULT = "runtime-default"
SECCOMP_PROFILE_CHOICES = (SECCOMP_RUNTIME_DEFAULT, PROFILE_MOBY_DEFAULT)
SECCOMP_SOURCE_RUNTIME_DEFAULT = "runtime_default"
SECCOMP_SOURCE_PACKAGE_DATA = "package_data"

_SECCOMP_RESOURCE_PACKAGE = "repo_health_doctor.sandbox.resources"
_SECCOMP_PROFILE_RESOURCE = "rhd-moby-default-v1.json"
_SECCOMP_PROVENANCE_RESOURCE = "rhd-moby-default-v1.provenance.json"
_SECCOMP_LICENSE_RESOURCE = "MOBY-APACHE-2.0.txt"

DEFAULT_MEMORY_LIMIT = "512m"
DEFAULT_CPU_LIMIT = "1.0"
DEFAULT_PIDS_LIMIT = 256
WORKDIR = "/workspace"
OUTDIR = "/out"
HOME = "/tmp/home"
TMPDIR = "/tmp"


@dataclass(frozen=True)
class SandboxProfile:
    name: str
    implemented: bool
    refusal_reason: str | None
    network: str
    read_only_rootfs: bool
    tmpfs: tuple[str, ...]
    memory: str
    cpus: str
    pids_limit: int
    user: str

    @property
    def env(self) -> dict[str, str]:
        return {
            "HOME": HOME,
            "TMPDIR": TMPDIR,
            "PYTHONDONTWRITEBYTECODE": "1",
        }

    @property
    def resource_limits(self) -> dict[str, Any]:
        return {
            "memory": self.memory,
            "cpus": self.cpus,
            "pids_limit": self.pids_limit,
        }

    @property
    def security_options(self) -> dict[str, Any]:
        return {
            "network": self.network,
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges"],
            "privileged": False,
            "stdin": "closed",
            "tty": False,
            "docker_socket_mounted": False,
            "host_home_mounted": False,
            "credential_mounts": False,
            "ssh_agent_mounted": False,
            "read_only_rootfs": self.read_only_rootfs,
            "env_allowlist": sorted(self.env),
        }

    def to_report(self) -> dict[str, Any]:
        filesystem = {
            "workdir": WORKDIR,
            "workspace_mount": "disposable_bind_mount_rw",
            "out_mount": "disposable_bind_mount_rw",
            "original_repo_mounted": False,
            "read_only_rootfs": self.read_only_rootfs,
            "tmpfs": list(self.tmpfs),
        }
        return {
            "name": self.name,
            "implemented": self.implemented,
            "refusal_reason": self.refusal_reason,
            "network": self.network,
            "filesystem": filesystem,
            "user": {
                "value": self.user,
                "root": self.user in {"0", "0:0", "root"},
                "policy": "non_root_numeric_user_when_available",
            },
            "resource_limits": self.resource_limits,
            "security_options": self.security_options,
            "environment": {
                "keys": sorted(self.env),
                "values_recorded": False,
                "host_environment_inherited": False,
            },
        }


@dataclass(frozen=True)
class SeccompProfileResource:
    """A packaged seccomp profile and its bounded provenance metadata."""

    name: str
    profile: dict[str, Any]
    provenance: dict[str, Any]
    license_text: str
    profile_sha256: str


@dataclass(frozen=True)
class SeccompProfileSelection:
    """One of the two supported sandbox-run seccomp selections."""

    profile: str
    profile_sha256: str | None
    source: str

    def to_report(self) -> dict[str, Any]:
        return {
            "profile": self.profile,
            "profile_sha256": self.profile_sha256,
            "source": self.source,
        }


def _read_seccomp_resource(resource_name: str) -> bytes:
    if resource_name not in {
        _SECCOMP_PROFILE_RESOURCE,
        _SECCOMP_PROVENANCE_RESOURCE,
        _SECCOMP_LICENSE_RESOURCE,
    }:
        raise ValueError("unsupported seccomp resource")
    return resources.files(_SECCOMP_RESOURCE_PACKAGE).joinpath(resource_name).read_bytes()


def resolve_seccomp_profile(name: str = PROFILE_MOBY_DEFAULT) -> SeccompProfileResource:
    """Resolve the one package-owned profile without accepting arbitrary paths."""

    if name != PROFILE_MOBY_DEFAULT:
        raise ValueError(f"unsupported packaged seccomp profile: {name}")
    profile_bytes = _read_seccomp_resource(_SECCOMP_PROFILE_RESOURCE)
    provenance_bytes = _read_seccomp_resource(_SECCOMP_PROVENANCE_RESOURCE)
    license_bytes = _read_seccomp_resource(_SECCOMP_LICENSE_RESOURCE)
    profile = json.loads(profile_bytes.decode("utf-8"))
    provenance = json.loads(provenance_bytes.decode("utf-8"))
    if not isinstance(profile, dict) or not isinstance(provenance, dict):
        raise ValueError("packaged seccomp resource must contain JSON objects")
    profile_sha256 = hashlib.sha256(profile_bytes).hexdigest()
    if provenance.get("profile_sha256") != profile_sha256:
        raise ValueError("packaged seccomp profile hash does not match provenance")
    if provenance.get("profile_name") != name:
        raise ValueError("packaged seccomp provenance name does not match profile")
    return SeccompProfileResource(
        name=name,
        profile=profile,
        provenance=provenance,
        license_text=license_bytes.decode("utf-8"),
        profile_sha256=profile_sha256,
    )


def load_seccomp_profile(name: str = PROFILE_MOBY_DEFAULT) -> dict[str, Any]:
    """Return parsed package data for the supported profile."""

    return resolve_seccomp_profile(name).profile


def materialize_seccomp_profile(name: str, destination: Path) -> Path:
    """Write the exact package-owned profile bytes to a controlled path."""

    resolved = resolve_seccomp_profile(name)
    profile_bytes = _read_seccomp_resource(_SECCOMP_PROFILE_RESOURCE)
    if hashlib.sha256(profile_bytes).hexdigest() != resolved.profile_sha256:
        raise ValueError("packaged seccomp profile changed during resolution")
    with destination.open("xb") as profile_file:
        profile_file.write(profile_bytes)
    return destination


def resolve_seccomp_selection(name: str = SECCOMP_RUNTIME_DEFAULT) -> SeccompProfileSelection:
    """Resolve only the runtime default or the package-owned Moby profile."""

    if name == SECCOMP_RUNTIME_DEFAULT:
        return SeccompProfileSelection(
            profile=SECCOMP_RUNTIME_DEFAULT,
            profile_sha256=None,
            source=SECCOMP_SOURCE_RUNTIME_DEFAULT,
        )
    if name != PROFILE_MOBY_DEFAULT:
        raise ValueError("unsupported seccomp profile")
    resource = resolve_seccomp_profile(name)
    return SeccompProfileSelection(
        profile=resource.name,
        profile_sha256=resource.profile_sha256,
        source=SECCOMP_SOURCE_PACKAGE_DATA,
    )


def default_container_user() -> str:
    uid = getattr(os, "getuid", lambda: 0)()
    gid = getattr(os, "getgid", lambda: 0)()
    if uid > 0 and gid > 0:
        return f"{uid}:{gid}"
    return "65532:65532"


def get_sandbox_profile(name: str) -> SandboxProfile:
    user = default_container_user()
    if name in {PROFILE_LOCKED_DOWN, PROFILE_NO_NETWORK_READONLY}:
        return SandboxProfile(
            name=name,
            implemented=True,
            refusal_reason=None,
            network="none",
            read_only_rootfs=True,
            tmpfs=("/tmp:rw,nosuid,nodev,size=64m",),
            memory=DEFAULT_MEMORY_LIMIT,
            cpus=DEFAULT_CPU_LIMIT,
            pids_limit=DEFAULT_PIDS_LIMIT,
            user=user,
        )
    if name == PROFILE_NO_NETWORK_DEFAULT:
        return SandboxProfile(
            name=name,
            implemented=True,
            refusal_reason=None,
            network="none",
            read_only_rootfs=False,
            tmpfs=(),
            memory=DEFAULT_MEMORY_LIMIT,
            cpus=DEFAULT_CPU_LIMIT,
            pids_limit=DEFAULT_PIDS_LIMIT,
            user=user,
        )
    if name == PROFILE_INSPECT_ONLY:
        return SandboxProfile(
            name=name,
            implemented=True,
            refusal_reason=None,
            network="none",
            read_only_rootfs=True,
            tmpfs=("/tmp:rw,nosuid,nodev,size=64m",),
            memory=DEFAULT_MEMORY_LIMIT,
            cpus=DEFAULT_CPU_LIMIT,
            pids_limit=DEFAULT_PIDS_LIMIT,
            user=user,
        )
    if name == PROFILE_DEV_PERMISSIVE:
        return SandboxProfile(
            name=name,
            implemented=False,
            refusal_reason="profile_not_implemented",
            network="explicit",
            read_only_rootfs=False,
            tmpfs=(),
            memory=DEFAULT_MEMORY_LIMIT,
            cpus=DEFAULT_CPU_LIMIT,
            pids_limit=DEFAULT_PIDS_LIMIT,
            user=user,
        )
    if name == PROFILE_NETWORK_EXPLICIT:
        return SandboxProfile(
            name=name,
            implemented=False,
            refusal_reason="profile_not_implemented",
            network="explicit",
            read_only_rootfs=False,
            tmpfs=(),
            memory=DEFAULT_MEMORY_LIMIT,
            cpus=DEFAULT_CPU_LIMIT,
            pids_limit=DEFAULT_PIDS_LIMIT,
            user=user,
        )
    return SandboxProfile(
        name=name,
        implemented=False,
        refusal_reason="profile_unsupported",
        network="unknown",
        read_only_rootfs=False,
        tmpfs=(),
        memory=DEFAULT_MEMORY_LIMIT,
        cpus=DEFAULT_CPU_LIMIT,
        pids_limit=DEFAULT_PIDS_LIMIT,
        user=user,
    )


def recognized_profiles() -> tuple[str, ...]:
    return (
        PROFILE_LOCKED_DOWN,
        PROFILE_INSPECT_ONLY,
        PROFILE_DEV_PERMISSIVE,
        PROFILE_NO_NETWORK_DEFAULT,
        PROFILE_NO_NETWORK_READONLY,
        PROFILE_NETWORK_EXPLICIT,
    )
