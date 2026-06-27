from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Any


PROFILE_NO_NETWORK_DEFAULT = "no-network-default"
PROFILE_NO_NETWORK_READONLY = "no-network-readonly"
PROFILE_NETWORK_EXPLICIT = "network-explicit"

DEFAULT_MEMORY_LIMIT = "512m"
DEFAULT_CPU_LIMIT = "1.0"
DEFAULT_PIDS_LIMIT = 256
WORKDIR = "/workspace"


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
        }

    def to_report(self) -> dict[str, Any]:
        filesystem = {
            "workdir": WORKDIR,
            "workspace_mount": "disposable_bind_mount_rw",
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
        }


def default_container_user() -> str:
    uid = getattr(os, "getuid", lambda: 0)()
    gid = getattr(os, "getgid", lambda: 0)()
    if uid > 0 and gid > 0:
        return f"{uid}:{gid}"
    return "65532:65532"


def get_sandbox_profile(name: str) -> SandboxProfile:
    user = default_container_user()
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
    if name == PROFILE_NO_NETWORK_READONLY:
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
        PROFILE_NO_NETWORK_DEFAULT,
        PROFILE_NO_NETWORK_READONLY,
        PROFILE_NETWORK_EXPLICIT,
    )
