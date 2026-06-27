from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from repo_health_doctor.sandbox.approval import build_demo_sandbox_run_approval
from repo_health_doctor.sandbox.docker_runner import FakeDockerRunner
from repo_health_doctor.sandbox.profiles import get_sandbox_profile
from repo_health_doctor.sandbox.run import run_sandbox_run
from repo_health_doctor.sandbox.run_workspace import fingerprint_target


ROOT = Path(__file__).resolve().parents[1]
COMMAND = ["python3", "-c", "print('hello from sandbox')"]
IMAGE = "python:3.12-slim"


def _repo(path: Path) -> Path:
    path.mkdir()
    (path / "README.md").write_text("demo\n", encoding="utf-8")
    return path


def _approval_file(repo: Path, path: Path) -> Path:
    profile = get_sandbox_profile("no-network-default")
    approval = build_demo_sandbox_run_approval(
        target_path=repo,
        target_inventory=fingerprint_target(repo),
        command_argv=COMMAND,
        image=IMAGE,
        profile=profile,
        expires_at="2099-01-01T00:00:00Z",
    )
    path.write_text(json.dumps(approval, indent=2) + "\n", encoding="utf-8")
    return path


def _assert_sandbox_run_schema_valid(report: dict[str, object]) -> None:
    schema = json.loads((ROOT / "schemas" / "sandbox-run.schema.json").read_text(encoding="utf-8"))
    try:
        from jsonschema import Draft202012Validator
    except ModuleNotFoundError:
        assert set(schema["required"]).issubset(report)
        assert report["result"]["status"] in schema["properties"]["result"]["properties"]["status"]["enum"]  # type: ignore[index]
    else:
        Draft202012Validator(schema).validate(report)


def test_completed_report_includes_safety_statement_and_no_authorization_claim(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "repo")
    approval_path = _approval_file(repo, tmp_path / "approval.json")
    secret_like = "token" + "=abcdefghijklmnopqrstuvwxyz"
    private_path = "/" + "home/alice/.ssh/id_rsa"
    runner = FakeDockerRunner(stdout=f"hello {secret_like} {private_path}\n")

    report = run_sandbox_run(
        repo,
        approval_path=approval_path,
        image=IMAGE,
        profile_name="no-network-default",
        command_argv=COMMAND,
        runner=runner,
        output_preview_chars=40,
    )

    assert report["result"]["status"] == "completed"
    assert report["approval"]["matched"] is True
    assert "not proof that the repository is safe" in report["safety_statement"]
    assert "not unrestricted execution authorization" in report["safety_statement"]
    assert "Docker isolation has limitations" in report["safety_statement"]
    assert "execution_authorized" not in report
    assert report["output_summary"]["stdout_truncated"] is True
    rendered = json.dumps(report)
    assert "abcdefghijklmnopqrstuvwxyz" not in rendered
    assert "/" + "home/alice" not in rendered
    assert report["output_summary"]["raw_stdout_stderr_persisted"] is False


def test_completed_report_matches_sandbox_run_schema_required_shape(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "repo")
    approval_path = _approval_file(repo, tmp_path / "approval.json")
    report = run_sandbox_run(
        repo,
        approval_path=approval_path,
        image=IMAGE,
        profile_name="no-network-default",
        command_argv=COMMAND,
        runner=FakeDockerRunner(),
    )

    _assert_sandbox_run_schema_valid(report)
    assert report["schema_version"] == "0.1-draft"
    assert report["report_kind"] == "sandbox_run"
    assert report["experimental"] is True


def test_docker_exit_125_infrastructure_failure_has_redacted_diagnostic(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "repo")
    approval_path = _approval_file(repo, tmp_path / "approval.json")
    runner = FakeDockerRunner(
        mode="failure",
        exit_code=125,
        stderr='invalid argument "type=bind,src=' + "/" + 'home/alice/private,dst=/workspace,rw" for "--mount" flag\n',
        docker_invoked=True,
    )

    report = run_sandbox_run(
        repo,
        approval_path=approval_path,
        image=IMAGE,
        profile_name="no-network-default",
        command_argv=COMMAND,
        runner=runner,
    )

    _assert_sandbox_run_schema_valid(report)
    assert report["result"]["status"] == "failed"
    assert report["result"]["exit_code"] == 125
    assert report["approval"]["matched"] is True
    assert report["approval"]["refusal_reasons"] == []
    assert report["docker"]["invoked"] is True
    assert report["docker"]["docker_invoked"] is True
    assert report["docker"]["exit_code"] == 125
    assert report["docker"]["failure_class"] == "docker_infrastructure_failure"
    assert "before the approved command could be confirmed as executed" in report["docker"]["diagnostic_redacted"]
    assert "<host-private-path>" in report["docker"]["stderr_preview_redacted"]
    assert "/" + "home/alice" not in json.dumps(report)
    assert any("Docker infrastructure failed" in item for item in report["limitations"])
    assert any("not as command completion" in item for item in report["next_actions"])


def test_cleanup_failure_becomes_cleanup_uncertain(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "repo")
    approval_path = _approval_file(repo, tmp_path / "approval.json")

    with patch("repo_health_doctor.sandbox.run_workspace.shutil.rmtree", side_effect=OSError("cleanup failed")):
        report = run_sandbox_run(
            repo,
            approval_path=approval_path,
            image=IMAGE,
            profile_name="no-network-default",
            command_argv=COMMAND,
            runner=FakeDockerRunner(),
        )

    assert report["result"]["status"] == "cleanup_uncertain"
    assert report["disposable_workspace"]["cleanup"] == "failed"
    assert any("cleanup failed" in item for item in report["limitations"])


def test_network_explicit_profile_fails_closed(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "repo")
    report = run_sandbox_run(
        repo,
        approval_path=None,
        image=IMAGE,
        profile_name="network-explicit",
        command_argv=COMMAND,
        runner=FakeDockerRunner(),
    )

    assert report["result"]["status"] == "blocked"
    assert "profile_not_implemented" in report["approval"]["refusal_reasons"]


def test_timeout_result_is_reported_as_timed_out(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "repo")
    approval_path = _approval_file(repo, tmp_path / "approval.json")

    report = run_sandbox_run(
        repo,
        approval_path=approval_path,
        image=IMAGE,
        profile_name="no-network-default",
        command_argv=COMMAND,
        runner=FakeDockerRunner(mode="timeout"),
    )

    assert report["result"]["status"] == "timed_out"
    assert report["result"]["timed_out"] is True
    assert any("timeout" in item.lower() for item in report["next_actions"])
