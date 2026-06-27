from __future__ import annotations

from pathlib import Path
from typing import Any

from .workspace import TMP_PATH, WORKSPACE_PATH

NODE_HOOK_LOGICAL_PATH = f"{WORKSPACE_PATH}/src/repo_health_doctor/sandbox_hooks/node/node-hook.js"
NODE_HOOK_LOGICAL_DIR = f"{WORKSPACE_PATH}/src/repo_health_doctor/sandbox_hooks/node"
PYTHON_HOOK_LOGICAL_PATH = f"{WORKSPACE_PATH}/src/repo_health_doctor/sandbox_hooks/python/sitecustomize.py"
PYTHON_HOOK_LOGICAL_DIR = f"{WORKSPACE_PATH}/src/repo_health_doctor/sandbox_hooks/python"
OBSERVER_EVENT_FILE = f"{TMP_PATH}/rhd-observer-events.jsonl"
OBSERVER_STRACE_PREFIX = f"{TMP_PATH}/rhd-strace"
SECRET_ENV_NAMES_ENV = "RHD_SECRET_ENV_NAMES"
ALLOWED_WRITE_ROOTS_ENV = "RHD_ALLOWED_WRITE_ROOTS"


def _observer_source_root() -> Path:
    return Path(__file__).resolve().parents[1] / "sandbox_hooks"


def build_observer_plan(detected_languages: list[str]) -> dict[str, Any]:
    languages = list(dict.fromkeys(detected_languages))
    source_root = _observer_source_root()
    runtime_hooks = [
        {
            "language": "python",
            "implemented": (source_root / "python" / "sitecustomize.py").is_file(),
            "activation": "PYTHONPATH preload via sitecustomize.py",
            "logical_path": PYTHON_HOOK_LOGICAL_PATH,
            "logical_directory": PYTHON_HOOK_LOGICAL_DIR,
            "event_sink": OBSERVER_EVENT_FILE,
            "coverage": [
                "dns_lookup",
                "socket_connect",
                "subprocess_spawn",
                "secret_file_open",
                "secret_env_access",
                "env_sweep",
                "file_delete_attempt",
            ],
            "limitations": [
                "Python runtime hook can be bypassed by direct syscalls, native extensions, or alternate runtimes.",
            ],
        },
        {
            "language": "node",
            "implemented": (source_root / "node" / "node-hook.js").is_file(),
            "activation": "NODE_OPTIONS=--require <node-hook>",
            "logical_path": NODE_HOOK_LOGICAL_PATH,
            "logical_directory": NODE_HOOK_LOGICAL_DIR,
            "event_sink": OBSERVER_EVENT_FILE,
            "coverage": [
                "dns_lookup",
                "socket_connect",
                "child_process_spawn",
                "secret_file_open",
                "secret_env_access",
                "env_sweep",
                "file_delete_attempt",
            ],
            "limitations": [
                "Node runtime hook can be bypassed by native addons, direct syscalls, or non-Node child processes.",
            ],
        },
    ]
    hook_map = {item["language"]: item for item in runtime_hooks}
    active_runtime_languages = [
        language for language in languages if hook_map.get(language, {}).get("implemented")
    ]
    runtime_hook_ready = bool(active_runtime_languages)
    selected_mode = "runtime_hook" if runtime_hook_ready else "degraded"
    limitations: list[str] = []
    limitations.append(
        "strace or equivalent syscall/process observation is not trusted until Docker preflight confirms availability inside the selected image; runtime-hook-only observation remains degraded and dynamic probes cannot PASS."
    )
    if runtime_hook_ready:
        limitations.append(
            "Runtime-hook observation is ready for supported Node.js or Python probes, but direct syscalls, native binaries, and alternate runtimes can bypass it."
        )
    else:
        limitations.append(
            "No runtime-hook coverage is available for the detected languages, so dynamic probes must remain skipped."
        )
    limitations.append("Observer limitations must be surfaced in every dynamic probe result instead of being treated as PASS.")

    if not languages:
        limitations.append("No supported Node.js or Python runtimes were detected for runtime-hook planning.")

    return {
        "mode": selected_mode,
        "status": "ready" if runtime_hook_ready else "degraded",
        "languages": languages,
        "syscall_observer": {
            "kind": "strace",
            "available": False,
            "active": False,
            "binary_name": "strace",
            "limitations": [
                "syscall/process observation remains unverified until Docker preflight confirms strace availability inside the selected image."
            ],
        },
        "runtime_hooks": runtime_hooks,
        "runtime_hook_active_languages": active_runtime_languages,
        "pass_possible": False,
        "event_sink": OBSERVER_EVENT_FILE,
        "phase2_ready": runtime_hook_ready,
        "phase3_ready": runtime_hook_ready,
        "limitations": limitations,
    }
