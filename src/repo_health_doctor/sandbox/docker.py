from __future__ import annotations

import json
import os
import re
import subprocess
from typing import Any

from .workspace import MaterializedWorkspace, WORKSPACE_PATH


FALLBACK_DOCKER_USER = "65532:65532"
IMAGE_REFERENCE_PLACEHOLDER = "${RHD_IMAGE_REFERENCE}"

DEFAULT_IMAGE_REFS = {
    "node": "node:20-bookworm-slim",
    "python": "python:3.12-slim-bookworm",
    "generic": "debian:bookworm-slim",
}
FULL_IMAGE_ID_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


def default_docker_user() -> str:
    uid = getattr(os, "getuid", lambda: 0)()
    gid = getattr(os, "getgid", lambda: 0)()
    if uid > 0 and gid > 0:
        return f"{uid}:{gid}"
    return FALLBACK_DOCKER_USER


def is_digest_pinned(image_reference: str) -> bool:
    return "@sha256:" in image_reference


def is_full_image_id(image_id: str | None) -> bool:
    if image_id is None:
        return False
    return bool(FULL_IMAGE_ID_PATTERN.fullmatch(image_id))


def evaluate_image_policy(
    image_reference: str,
    *,
    explicitly_selected: bool,
    allow_local_image: bool = False,
    expected_image_id: str | None = None,
    inspect_timeout_seconds: int = 10,
) -> dict[str, Any]:
    policy = {
        "image_reference": image_reference,
        "image_reference_kind": "tag_only_rejected",
        "expected_image_id": expected_image_id,
        "actual_image_id": None,
        "image_id_match": False,
        "local_sanctioned": False,
        "local_sanctioned_limitations": [],
        "decision": "gated" if not explicitly_selected else "rejected",
        "execution_allowed": False,
        "limitations": [],
    }

    if is_digest_pinned(image_reference):
        policy.update(
            {
                "image_reference_kind": "registry_digest",
                "image_id_match": True,
                "decision": "accepted",
                "execution_allowed": True,
            }
        )
        return policy

    if not explicitly_selected:
        policy["limitations"] = [
            "Default selected Docker image is not digest-pinned; execution remains gated until a digest-pinned or sanctioned local image is provided.",
        ]
        return policy

    if not allow_local_image:
        policy["limitations"] = [
            "Non-digest Docker images remain rejected unless local image use is explicitly allowed with a matching full expected image ID.",
        ]
        return policy

    if image_reference == "latest" or image_reference.endswith(":latest"):
        policy["limitations"] = [
            "latest-tag images cannot be sanctioned for sandbox execution.",
        ]
        return policy

    if expected_image_id is None:
        policy["limitations"] = [
            "Local sanctioned images require an expected full image ID before execution can proceed.",
        ]
        return policy

    if not is_full_image_id(expected_image_id):
        policy["limitations"] = [
            "Expected local image ID must be a full sha256:<64 lowercase hex> value.",
        ]
        return policy

    try:
        completed = subprocess.run(
            ["docker", "image", "inspect", image_reference],
            check=False,
            capture_output=True,
            text=True,
            timeout=inspect_timeout_seconds,
            shell=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        policy["limitations"] = [
            "Local sanctioned image could not be inspected through the local Docker daemon.",
        ]
        return policy

    if completed.returncode != 0:
        policy["limitations"] = [
            "Local sanctioned image could not be inspected through the local Docker daemon.",
        ]
        return policy

    try:
        payload = json.loads(completed.stdout)
        actual_image_id = payload[0]["Id"]
    except (json.JSONDecodeError, IndexError, KeyError, TypeError):
        policy["limitations"] = [
            "Local sanctioned image inspection returned an unreadable image ID.",
        ]
        return policy

    policy["actual_image_id"] = actual_image_id
    policy["image_id_match"] = actual_image_id == expected_image_id
    if not policy["image_id_match"]:
        policy["limitations"] = [
            "Local sanctioned image ID did not match the expected full image ID.",
        ]
        return policy

    policy.update(
        {
            "image_reference_kind": "local_sanctioned_image",
            "local_sanctioned": True,
            "decision": "accepted",
            "execution_allowed": True,
            "local_sanctioned_limitations": [
                "Local sanctioned image acceptance depends on a matching local daemon image ID and is less portable and reproducible than a registry digest reference.",
                "Sandbox execution still forbids implicit image pulls and continues to use --pull=never.",
            ],
            "limitations": [
                "Local sanctioned image acceptance depends on a matching local daemon image ID and is less portable and reproducible than a registry digest reference.",
            ],
        }
    )
    return policy


def _select_image_variants(detected_languages: list[str]) -> list[dict[str, Any]]:
    languages = list(dict.fromkeys(detected_languages))
    if not languages:
        languages = ["generic"]
    variants: list[dict[str, Any]] = []
    for language in languages:
        image_reference = DEFAULT_IMAGE_REFS.get(language, DEFAULT_IMAGE_REFS["generic"])
        variants.append(
            {
                "language": language,
                "image_reference": image_reference,
                "digest_pinned": is_digest_pinned(image_reference),
            }
        )
    return variants


def _select_runtime_image(image_variants: list[dict[str, Any]]) -> str:
    if len(image_variants) == 1:
        return image_variants[0]["image_reference"]
    return DEFAULT_IMAGE_REFS["generic"]


def build_docker_spec(
    *,
    detected_languages: list[str],
    workspace_plan: dict[str, Any],
    image_reference: str | None = None,
) -> dict[str, Any]:
    docker_user = default_docker_user()
    host_placeholders = workspace_plan["host_path_placeholders"]
    logical_paths = workspace_plan["logical_paths"]
    environment = workspace_plan["environment"]
    mounts = [
        {
            "name": "workspace",
            "source": host_placeholders["workspace"],
            "target": logical_paths["workspace"],
            "read_only": False,
        },
        {
            "name": "home",
            "source": host_placeholders["home"],
            "target": logical_paths["home"],
            "read_only": False,
        },
        {
            "name": "npm_cache",
            "source": host_placeholders["npm_cache"],
            "target": logical_paths["npm_cache"],
            "read_only": False,
        },
        {
            "name": "pip_cache",
            "source": host_placeholders["pip_cache"],
            "target": logical_paths["pip_cache"],
            "read_only": False,
        },
        {
            "name": "xdg_cache",
            "source": host_placeholders["xdg_cache"],
            "target": logical_paths["xdg_cache"],
            "read_only": False,
        },
        {
            "name": "tmp",
            "source": host_placeholders["tmp"],
            "target": logical_paths["tmp"],
            "read_only": False,
        },
    ]
    argv = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--read-only",
        "--user",
        docker_user,
        "--pids-limit",
        "256",
        "--memory",
        "512m",
        "--cpus",
        "1.0",
        "--pull=never",
        "--workdir",
        WORKSPACE_PATH,
    ]
    for name, value in environment.items():
        argv.extend(["--env", f"{name}={value}"])
    for mount in mounts:
        mount_spec = f"type=bind,src={mount['source']},dst={mount['target']}"
        if mount["read_only"]:
            mount_spec += ",readonly"
        argv.extend(["--mount", mount_spec])

    if image_reference is None:
        image_variants = _select_image_variants(detected_languages)
        selected_image_reference = _select_runtime_image(image_variants)
    else:
        image_variants = [
            {
                "language": "selected",
                "image_reference": image_reference,
                "digest_pinned": is_digest_pinned(image_reference),
            }
        ]
        selected_image_reference = image_reference
    argv.append(IMAGE_REFERENCE_PLACEHOLDER)
    return {
        "mode": "plan_only",
        "argv": argv,
        "shell": False,
        "image_reference_placeholder": IMAGE_REFERENCE_PLACEHOLDER,
        "image_variants": image_variants,
        "selected_image_reference": selected_image_reference,
        "selected_image_digest_pinned": is_digest_pinned(selected_image_reference),
        "selected_image_execution_allowed": False,
        "image_reference_kind": "tag_only_rejected",
        "expected_image_id": None,
        "actual_image_id": None,
        "image_id_match": False,
        "local_sanctioned": False,
        "local_sanctioned_limitations": [],
        "decision": "gated",
        "pull_policy": "never",
        "network": "none",
        "rootfs": "read_only",
        "user": docker_user,
        "cap_drop": ["ALL"],
        "security_opts": ["no-new-privileges"],
        "memory": "512m",
        "cpus": "1.0",
        "pids_limit": 256,
        "docker_socket_mounted": False,
        "host_home_mounted": False,
        "credential_mounts_blocked": True,
        "path_resolution_status": "not_started",
        "resolved_argv_redacted": [],
        "mount_source_handles": [],
        "execution_enabled": False,
    }


def resolve_docker_argv(
    docker_spec: dict[str, Any],
    materialized: MaterializedWorkspace,
) -> dict[str, Any]:
    placeholder_map = {
        "${RHD_DISPOSABLE_WORKSPACE}": str(materialized.host_paths["workspace"]),
        "${RHD_DISPOSABLE_HOME}": str(materialized.host_paths["home"]),
        "${RHD_DISPOSABLE_NPM_CACHE}": str(materialized.host_paths["npm_cache"]),
        "${RHD_DISPOSABLE_PIP_CACHE}": str(materialized.host_paths["pip_cache"]),
        "${RHD_DISPOSABLE_XDG_CACHE}": str(materialized.host_paths["xdg_cache"]),
        "${RHD_DISPOSABLE_TMP}": str(materialized.host_paths["tmp"]),
        IMAGE_REFERENCE_PLACEHOLDER: docker_spec["selected_image_reference"],
    }
    resolved_argv: list[str] = []
    for token in docker_spec["argv"]:
        resolved = token
        for placeholder, value in placeholder_map.items():
            resolved = resolved.replace(placeholder, value)
        resolved_argv.append(resolved)
    return {
        "raw_argv": resolved_argv,
        "resolved_argv_redacted": [materialized.redact_text(token) for token in resolved_argv],
        "mount_source_handles": [
            "<workspace>",
            "<home>",
            "<npm-cache>",
            "<pip-cache>",
            "<xdg-cache>",
            "<tmp>",
        ],
        "path_resolution_status": "completed",
        "selected_image_reference": docker_spec["selected_image_reference"],
    }


def build_container_command_argv(
    resolved_base_argv: list[str],
    *,
    container_argv: tuple[str, ...] | list[str],
    network_mode: str,
    extra_docker_args: list[str] | tuple[str, ...] = (),
) -> list[str]:
    command_argv = list(container_argv)
    if not command_argv:
        raise ValueError("container argv must not be empty")
    entrypoint = command_argv[0]
    command_args = command_argv[1:]
    argv = list(resolved_base_argv)
    for index, token in enumerate(argv[:-1]):
        if token == "--network":
            argv[index + 1] = network_mode
            break
    else:
        raise ValueError("docker argv is missing --network")
    image_reference = argv.pop()
    return [*argv, *list(extra_docker_args), "--entrypoint", entrypoint, image_reference, *command_args]
