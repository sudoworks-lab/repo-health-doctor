from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys

from repo_health_doctor.sandbox.approval import build_demo_sandbox_run_approval
from repo_health_doctor.sandbox.profiles import get_sandbox_profile
from repo_health_doctor.sandbox.run_workspace import fingerprint_target


ROOT = Path(__file__).resolve().parents[1]
COMMAND = ["python3", "-c", "print('hello from sandbox')"]
IMAGE = "python:3.12-slim"


def _repo(path: Path) -> Path:
    path.mkdir()
    (path / "README.md").write_text("demo\n", encoding="utf-8")
    return path


def _approval(repo: Path, profile_name: str = "no-network-default") -> dict[str, object]:
    profile = get_sandbox_profile(profile_name)
    return build_demo_sandbox_run_approval(
        target_path=repo,
        target_inventory=fingerprint_target(repo),
        command_argv=COMMAND,
        image=IMAGE,
        profile=profile,
        expires_at="2099-01-01T00:00:00Z",
    )


def _write_approval(path: Path, approval: dict[str, object]) -> Path:
    path.write_text(json.dumps(approval, indent=2) + "\n", encoding="utf-8")
    return path


def _run_cli(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    return subprocess.run(
        [sys.executable, "-m", "repo_health_doctor", "sandbox-run", str(repo), "--format", "json", *args],
        cwd=ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )


def _base_args(approval_path: Path, runner: str = "fake") -> list[str]:
    return [
        "--approval",
        str(approval_path),
        "--image",
        IMAGE,
        "--profile",
        "no-network-default",
        "--runner",
        runner,
        "--",
        *COMMAND,
    ]


def test_cli_refuses_missing_approval(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "repo")
    result = _run_cli(repo, "--image", IMAGE, "--profile", "no-network-default", "--runner", "fake", "--", *COMMAND)
    report = json.loads(result.stdout)

    assert result.returncode == 1
    assert report["result"]["status"] == "blocked"
    assert "approval_missing" in report["approval"]["refusal_reasons"]


def test_cli_refuses_invalid_approval(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "repo")
    approval_path = tmp_path / "approval.json"
    approval_path.write_text("{not json", encoding="utf-8")
    result = _run_cli(repo, *_base_args(approval_path))
    report = json.loads(result.stdout)

    assert result.returncode == 1
    assert "approval_invalid_json" in report["approval"]["refusal_reasons"]


def test_cli_refuses_approval_binding_mismatches(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "repo")
    cases: list[tuple[str, dict[str, object], list[str], str, str]] = []

    approval = deepcopy(_approval(repo))
    approval["command"] = {"argv": ["python3", "-c", "print('other')"], "shell": False}
    cases.append(("command", approval, _base_args(tmp_path / "command.json"), "command_argv_mismatch", "command.json"))

    approval = deepcopy(_approval(repo))
    approval["image"] = {"reference": "python:3.11-slim", "pull_policy": "never"}
    cases.append(("image", approval, _base_args(tmp_path / "image.json"), "image_reference_mismatch", "image.json"))

    approval = deepcopy(_approval(repo))
    approval["sandbox_profile"] = {"name": "no-network-readonly", "network": "none"}
    cases.append(("profile", approval, _base_args(tmp_path / "profile.json"), "sandbox_profile_mismatch", "profile.json"))

    approval = deepcopy(_approval(repo))
    approval["network"] = "bridge"
    cases.append(("network", approval, _base_args(tmp_path / "network.json"), "network_mismatch", "network.json"))

    approval = deepcopy(_approval(repo))
    approval["timeout_seconds"] = 1
    timeout_args = [
        "--approval",
        str(tmp_path / "timeout.json"),
        "--image",
        IMAGE,
        "--profile",
        "no-network-default",
        "--runner",
        "fake",
        "--timeout-seconds",
        "2",
        "--",
        *COMMAND,
    ]
    cases.append(("timeout", approval, timeout_args, "timeout_exceeds_approval", "timeout.json"))

    for _label, approval_doc, args, expected, filename in cases:
        approval_path = _write_approval(tmp_path / filename, approval_doc)
        args = [str(approval_path) if arg.endswith(filename) else arg for arg in args]
        result = _run_cli(repo, *args)
        report = json.loads(result.stdout)
        assert result.returncode == 1
        assert expected in report["approval"]["refusal_reasons"]


def test_cli_refuses_docker_unavailable_and_local_image_unavailable(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "repo")
    approval_path = _write_approval(tmp_path / "approval.json", _approval(repo))

    docker_unavailable = _run_cli(repo, *_base_args(approval_path, runner="fake-docker-unavailable"))
    image_unavailable = _run_cli(repo, *_base_args(approval_path, runner="fake-image-unavailable"))

    docker_report = json.loads(docker_unavailable.stdout)
    image_report = json.loads(image_unavailable.stdout)
    assert docker_unavailable.returncode == 1
    assert image_unavailable.returncode == 1
    assert "docker_unavailable" in docker_report["approval"]["refusal_reasons"]
    assert "image_unavailable_local_only_policy" in image_report["approval"]["refusal_reasons"]


def test_cli_fake_runner_successful_synthetic_run(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "repo")
    approval_path = _write_approval(tmp_path / "approval.json", _approval(repo))
    output_path = tmp_path / "sandbox-run.json"
    result = _run_cli(
        repo,
        "--approval",
        str(approval_path),
        "--image",
        IMAGE,
        "--profile",
        "no-network-default",
        "--runner",
        "fake",
        "--output",
        str(output_path),
        "--",
        *COMMAND,
    )
    report = json.loads(result.stdout)

    assert result.returncode == 0
    assert output_path.is_file()
    assert report["result"]["status"] == "completed"
    assert report["approval"]["matched"] is True
    assert report["docker"]["docker_invoked"] is False
    assert report["output_summary"]["raw_stdout_stderr_persisted"] is False
    assert "not proof that the repository is safe" in report["safety_statement"]
