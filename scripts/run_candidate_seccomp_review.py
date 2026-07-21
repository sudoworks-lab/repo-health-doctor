#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import uuid


ROOT = Path(__file__).resolve().parents[1]
CANDIDATE_PATH = ROOT / "docs" / "human-review" / "rhd-locked-down-v1.candidate.json"
PACKET_PATH = ROOT / "docs" / "human-review" / "seccomp-review-packet.json"
MARKDOWN_PATH = ROOT / "docs" / "human-review" / "seccomp-review-packet.md"
DEFAULT_LOCAL_IMAGE = "python:3.12-slim"
MARKDOWN_START = "<!-- F030_CANDIDATE_REGRESSION_START -->"
MARKDOWN_END = "<!-- F030_CANDIDATE_REGRESSION_END -->"
SAFE_METADATA = re.compile(r"[A-Za-z0-9._+() /-]{1,128}\Z")
CONTENT_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
LOCAL_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class CandidateCase:
    case_id: int
    description: str
    command: tuple[str, ...]
    expected_outcome: str = "completed_exit_0"
    timeout_seconds: int = 15


CASES = (
    CandidateCase(
        1,
        "workspace write under the candidate profile",
        (
            "python3",
            "-c",
        "from pathlib import Path; Path('/out/case-1.txt').write_text('ok\\n', encoding='utf-8')",
        ),
    ),
    CandidateCase(
        2,
        "network namespace remains limited to loopback",
        (
            "python3",
            "-c",
            "import socket; names={name for _, name in socket.if_nameindex()}; assert names <= {'lo'}, names",
        ),
    ),
    CandidateCase(
        3,
        "container root filesystem remains read-only",
        (
            "python3",
            "-c",
            (
                "from pathlib import Path; entries=[line.split() for line in "
                "Path('/proc/self/mountinfo').read_text(encoding='utf-8').splitlines()]; "
                "root=next(parts for parts in entries if parts[4] == '/'); "
                "assert 'ro' in root[5].split(',')"
            ),
        ),
    ),
    CandidateCase(
        4,
        "writable tmpfs remains available",
        (
            "python3",
            "-c",
            (
                "from pathlib import Path; entries=[line.split() for line in "
                "Path('/proc/self/mountinfo').read_text(encoding='utf-8').splitlines()]; "
                "tmp=next(parts for parts in entries if parts[4] == '/tmp'); "
                "assert tmp[tmp.index('-') + 1] == 'tmpfs'; "
                "probe=Path('/tmp/case-4.txt'); probe.write_text('ok\\n', encoding='utf-8')"
            ),
        ),
    ),
    CandidateCase(
        5,
        "container process remains non-root",
        ("python3", "-c", "import os; assert os.getuid() != 0 and os.getgid() != 0"),
    ),
    CandidateCase(
        6,
        "timeout remains bounded and the container is removed",
        ("python3", "-c", "import time; time.sleep(5)"),
        expected_outcome="timed_out",
        timeout_seconds=1,
    ),
    CandidateCase(
        8,
        "candidate profile can start the packaged-profile equivalent command",
        ("python3", "-c", "print('candidate-case-8')"),
    ),
    CandidateCase(
        10,
        "candidate profile can start the installed-package equivalent command",
        ("python3", "-c", "print('candidate-case-10')"),
    ),
)


def _container_user() -> str:
    uid = getattr(os, "getuid", lambda: 0)()
    gid = getattr(os, "getgid", lambda: 0)()
    return f"{uid}:{gid}" if uid > 0 and gid > 0 else "65532:65532"


def _build_docker_argv(
    *,
    image: str,
    candidate_path: Path,
    workspace: Path,
    out: Path,
    container_name: str,
    command: tuple[str, ...],
) -> list[str]:
    return [
        "docker",
        "run",
        "--rm",
        "--name",
        container_name,
        "--pull=never",
        "--network",
        "none",
        "--workdir",
        "/workspace",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--security-opt",
        f"seccomp={candidate_path}",
        "--memory",
        "1g",
        "--cpus",
        "1.0",
        "--pids-limit",
        "256",
        "--user",
        _container_user(),
        "--env",
        "HOME=/tmp",
        "--env",
        "PYTHONDONTWRITEBYTECODE=1",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=64m",
        "--mount",
        f"type=bind,src={workspace},dst=/workspace",
        "--mount",
        f"type=bind,src={out},dst=/out",
        image,
        *command,
    ]


def _capture(argv: list[str], *, timeout_seconds: int = 10) -> tuple[int | None, str, bool]:
    try:
        completed = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout_seconds,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        return None, "", True
    except (FileNotFoundError, OSError):
        return None, "", False
    return completed.returncode, completed.stdout.strip(), False


def _safe_environment_value(
    argv: list[str],
    *,
    failure_code: str,
) -> tuple[str, str | None]:
    returncode, value, timed_out = _capture(argv)
    if returncode != 0 or timed_out or not SAFE_METADATA.fullmatch(value):
        return "unknown", failure_code
    return value, None


def _resolve_local_image(selected_image: str) -> tuple[dict[str, str], str | None]:
    image_id_code, image_id, image_id_timed_out = _capture(
        ["docker", "image", "inspect", selected_image, "--format", "{{.Id}}"]
    )
    if image_id_code != 0 or image_id_timed_out or not LOCAL_IMAGE_ID.fullmatch(image_id):
        return {}, "local_image_unavailable"

    digests_code, digests_text, digests_timed_out = _capture(
        ["docker", "image", "inspect", selected_image, "--format", "{{json .RepoDigests}}"]
    )
    if digests_code != 0 or digests_timed_out:
        return {}, "local_image_digest_unresolved"
    try:
        repo_digests = json.loads(digests_text)
    except json.JSONDecodeError:
        return {}, "local_image_digest_unresolved"
    if not isinstance(repo_digests, list) or any(not isinstance(item, str) for item in repo_digests):
        return {}, "local_image_digest_unresolved"

    digest_references = sorted(
        item
        for item in repo_digests
        if "@" in item and CONTENT_DIGEST.fullmatch(item.rsplit("@", maxsplit=1)[1])
    )
    if not digest_references:
        return {}, "local_image_digest_unresolved"
    runtime_reference = (
        selected_image
        if "@" in selected_image
        and CONTENT_DIGEST.fullmatch(selected_image.rsplit("@", maxsplit=1)[1])
        else digest_references[0]
    )
    runtime_digest = runtime_reference.rsplit("@", maxsplit=1)[1]
    return {
        "runtime_reference": runtime_reference,
        "image_digest": runtime_digest,
        "local_image_id": image_id,
    }, None


def _container_exists(container_name: str) -> bool | None:
    returncode, _, timed_out = _capture(
        ["docker", "container", "inspect", container_name],
        timeout_seconds=5,
    )
    if timed_out or returncode is None:
        return None
    return returncode == 0


def _cleanup_container(container_name: str) -> list[str]:
    exists = _container_exists(container_name)
    if exists is False:
        return []
    if exists is None:
        return ["container_cleanup_state_unknown"]
    remove_code, _, remove_timed_out = _capture(
        ["docker", "rm", "--force", container_name],
        timeout_seconds=10,
    )
    if remove_code != 0 or remove_timed_out:
        return ["container_cleanup_failed"]
    if _container_exists(container_name) is not False:
        return ["container_cleanup_failed"]
    return []


def _run_case(case: CandidateCase, *, image: str) -> dict[str, object]:
    failure_codes: list[str] = []
    timed_out = False
    exit_code: int | None = None
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix=f"rhd-candidate-case-{case.case_id}-") as temporary:
        root = Path(temporary)
        workspace = root / "workspace"
        out = root / "out"
        workspace.mkdir()
        out.mkdir()
        workspace.chmod(0o777)
        out.chmod(0o777)
        (workspace / "README.md").write_text("synthetic candidate regression fixture\n", encoding="utf-8")
        container_name = f"rhd-candidate-review-{case.case_id}-{uuid.uuid4().hex[:12]}"
        argv = _build_docker_argv(
            image=image,
            candidate_path=CANDIDATE_PATH,
            workspace=workspace,
            out=out,
            container_name=container_name,
            command=case.command,
        )
        try:
            completed = subprocess.run(
                argv,
                check=False,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=case.timeout_seconds,
                stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired:
            timed_out = True
        except (FileNotFoundError, OSError):
            failure_codes.append("docker_invocation_failed")
        else:
            exit_code = completed.returncode

        if case.expected_outcome == "timed_out":
            if not timed_out:
                failure_codes.append("expected_timeout_not_observed")
        elif timed_out:
            failure_codes.append("unexpected_timeout")
        elif exit_code is None:
            if "docker_invocation_failed" not in failure_codes:
                failure_codes.append("docker_invocation_failed")
        elif exit_code != 0:
            failure_codes.append(f"docker_exit_code_{exit_code}")

        if case.case_id == 1 and not failure_codes and not (out / "case-1.txt").is_file():
            failure_codes.append("expected_out_change_missing")
        failure_codes.extend(_cleanup_container(container_name))

    return {
        "case_id": case.case_id,
        "description": case.description,
        "expected_outcome": case.expected_outcome,
        "status": "pass" if not failure_codes else "fail",
        "exit_code": exit_code,
        "timed_out": timed_out,
        "duration_ms": int((time.monotonic() - started) * 1000),
        "failure_codes": list(dict.fromkeys(failure_codes)),
    }


def _not_run_case(case: CandidateCase) -> dict[str, object]:
    return {
        "case_id": case.case_id,
        "description": case.description,
        "expected_outcome": case.expected_outcome,
        "status": "not_run",
        "exit_code": None,
        "timed_out": False,
        "duration_ms": 0,
        "failure_codes": ["preflight_blocked"],
    }


def _render_markdown(record: dict[str, object]) -> str:
    environment = record["environment"]
    assert isinstance(environment, dict)
    cases = record["cases"]
    assert isinstance(cases, list)
    failures = record["failures"]
    assert isinstance(failures, list)
    lines = [
        MARKDOWN_START,
        "## F030 candidate専用local real Docker regression",
        "",
        f"観測日時は`{record['observed_at']}`、実行状態は`{record['execution_state']}`である。",
        f"candidate bytesのSHA-256は`{record['profile_sha256']}`である。",
        "このtest pathはreview専用であり、candidateをpackage data、schema、CLI、",
        "Docker argvの製品選択肢またはdefaultへ接続しない。Human判断は引き続きpendingである。",
        "",
        "環境:",
        "",
        f"- Docker server: `{environment['docker_server_version']}`",
        f"- Docker OS / architecture: `{environment['docker_os']}` / `{environment['docker_architecture']}`",
        f"- Kernel: `{environment['kernel_version']}`",
        f"- Rootless / userns-remap: `{environment['rootless']}` / `{environment['userns_remap']}`",
        f"- Existing local image digest: `{environment['image_digest']}`",
        f"- Existing local image ID: `{environment['local_image_id']}`",
        f"- Image selection source: `{environment['image_selection_source']}`",
        "",
        "case別結果:",
        "",
        "| case | status | expected | exit code | timeout | failure codes |",
        "|---:|---|---|---:|---|---|",
    ]
    for result in cases:
        assert isinstance(result, dict)
        failure_text = ", ".join(result["failure_codes"]) or "none"
        exit_text = "null" if result["exit_code"] is None else str(result["exit_code"])
        lines.append(
            f"| {result['case_id']} | `{result['status']}` | `{result['expected_outcome']}` | "
            f"{exit_text} | `{str(result['timed_out']).lower()}` | `{failure_text}` |"
        )
    lines.extend(["", "全failure:", ""])
    if not failures:
        lines.append("- なし。")
    else:
        for failure in failures:
            assert isinstance(failure, dict)
            case_label = "preflight" if failure["case_id"] is None else f"case {failure['case_id']}"
            lines.append(f"- {case_label}: `{failure['failure_code']}`")
    lines.extend(
        [
            "",
            "結果は記録されたlocal Docker環境とimage digestにだけ限定され、一般的な互換性、",
            "安全性、完全な隔離、Human approvalを示さない。raw stdout/stderr、host path、",
            "container名はpacketへ保存していない。",
            MARKDOWN_END,
        ]
    )
    return "\n".join(lines)


def _replace_markdown_section(markdown: str, section: str) -> str:
    if MARKDOWN_START not in markdown and MARKDOWN_END not in markdown:
        return f"{markdown.rstrip()}\n\n{section}\n"
    if markdown.count(MARKDOWN_START) != 1 or markdown.count(MARKDOWN_END) != 1:
        raise ValueError("candidate regression markdown markers are invalid")
    before, remainder = markdown.split(MARKDOWN_START, maxsplit=1)
    _, after = remainder.split(MARKDOWN_END, maxsplit=1)
    return f"{before.rstrip()}\n\n{section}\n{after.lstrip()}"


def run_candidate_review(*, selected_image: str, image_selection_source: str) -> dict[str, object]:
    candidate_bytes = CANDIDATE_PATH.read_bytes()
    profile_sha256 = hashlib.sha256(candidate_bytes).hexdigest()
    packet = json.loads(PACKET_PATH.read_text(encoding="utf-8"))
    markdown = MARKDOWN_PATH.read_text(encoding="utf-8")

    environment_failure_codes: list[str] = []
    docker_server_version, failure = _safe_environment_value(
        ["docker", "version", "--format", "{{.Server.Version}}"],
        failure_code="docker_daemon_unavailable",
    )
    if failure:
        environment_failure_codes.append(failure)
    docker_os, failure = _safe_environment_value(
        ["docker", "info", "--format", "{{.OperatingSystem}}"],
        failure_code="docker_os_unavailable",
    )
    if failure:
        environment_failure_codes.append(failure)
    docker_architecture, failure = _safe_environment_value(
        ["docker", "info", "--format", "{{.Architecture}}"],
        failure_code="docker_architecture_unavailable",
    )
    if failure:
        environment_failure_codes.append(failure)
    kernel_version, failure = _safe_environment_value(
        ["docker", "info", "--format", "{{.KernelVersion}}"],
        failure_code="docker_kernel_unavailable",
    )
    if failure:
        environment_failure_codes.append(failure)

    security_code, security_text, security_timed_out = _capture(
        ["docker", "info", "--format", "{{json .SecurityOptions}}"]
    )
    rootless = "unknown"
    userns_remap = "unknown"
    if security_code == 0 and not security_timed_out:
        try:
            security_options = json.loads(security_text)
        except json.JSONDecodeError:
            security_options = None
        if isinstance(security_options, list) and all(isinstance(item, str) for item in security_options):
            normalized = tuple(item.lower() for item in security_options)
            rootless = "true" if any("rootless" in item for item in normalized) else "false"
            userns_remap = "true" if any("userns" in item for item in normalized) else "false"
        else:
            environment_failure_codes.append("docker_security_options_unavailable")
    else:
        environment_failure_codes.append("docker_security_options_unavailable")

    image_details, image_failure = _resolve_local_image(selected_image)
    blocking_failure_codes: list[str] = []
    if docker_server_version == "unknown":
        blocking_failure_codes.append("docker_daemon_unavailable")
    if image_failure:
        blocking_failure_codes.append(image_failure)

    if blocking_failure_codes:
        case_results = [_not_run_case(case) for case in CASES]
    else:
        case_results = [
            _run_case(case, image=image_details["runtime_reference"])
            for case in CASES
        ]

    failures = [
        {"scope": "environment", "case_id": None, "failure_code": code}
        for code in dict.fromkeys(environment_failure_codes + blocking_failure_codes)
    ]
    failures.extend(
        {
            "scope": "case",
            "case_id": result["case_id"],
            "failure_code": code,
        }
        for result in case_results
        for code in result["failure_codes"]
    )
    passed_count = sum(result["status"] == "pass" for result in case_results)
    failed_count = sum(result["status"] == "fail" for result in case_results)
    not_run_count = sum(result["status"] == "not_run" for result in case_results)
    if blocking_failure_codes:
        execution_state = "preflight_failed"
    elif failures:
        execution_state = "completed_with_failures"
    else:
        execution_state = "completed"

    record: dict[str, object] = {
        "recorded_by_feature_id": "F030",
        "observed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "execution_state": execution_state,
        "profile": "rhd-locked-down-v1",
        "profile_sha256": profile_sha256,
        "approval_state": "human_unapproved",
        "product_connection_state": "disconnected",
        "pull_policy": "never",
        "network_mode": "none",
        "environment": {
            "docker_server_version": docker_server_version,
            "docker_os": docker_os,
            "docker_architecture": docker_architecture,
            "kernel_version": kernel_version,
            "rootless": rootless,
            "userns_remap": userns_remap,
            "image_selection_source": image_selection_source,
            "image_digest": image_details.get("image_digest", "unknown"),
            "local_image_id": image_details.get("local_image_id", "unknown"),
        },
        "required_case_ids": [case.case_id for case in CASES],
        "attempted_case_count": len(CASES) - not_run_count,
        "passed_case_count": passed_count,
        "failed_case_count": failed_count,
        "not_run_case_count": not_run_count,
        "all_required_cases_recorded": len(case_results) == len(CASES),
        "cases": case_results,
        "failures": failures,
        "raw_process_output_recorded": False,
        "limitations": [
            "result_scope_is_recorded_local_environment_only",
            "successful_cases_do_not_establish_general_compatibility_or_safety",
            "human_decision_remains_pending",
            "candidate_remains_disconnected_from_product_and_default_paths",
        ],
    }
    packet["candidate_local_regression"] = record
    PACKET_PATH.write_text(
        json.dumps(packet, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    MARKDOWN_PATH.write_text(
        _replace_markdown_section(markdown, _render_markdown(record)),
        encoding="utf-8",
    )
    return record


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the Human-unapproved candidate against an existing local Docker image."
    )
    parser.add_argument(
        "--image",
        default=os.environ.get("RHD_REAL_DOCKER_IMAGE", "").strip() or DEFAULT_LOCAL_IMAGE,
        help="Existing local image reference. The script never pulls an image.",
    )
    args = parser.parse_args()
    source = "environment" if os.environ.get("RHD_REAL_DOCKER_IMAGE", "").strip() else "default_local_tag"
    record = run_candidate_review(selected_image=args.image, image_selection_source=source)
    print(
        "candidate regression recorded: "
        f"state={record['execution_state']} "
        f"passed={record['passed_case_count']} "
        f"failed={record['failed_case_count']} "
        f"not_run={record['not_run_case_count']}"
    )
    return 0 if record["execution_state"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
