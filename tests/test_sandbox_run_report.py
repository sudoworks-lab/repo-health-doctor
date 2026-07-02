from __future__ import annotations

import json
from pathlib import Path
import unittest
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
    assert report["authorization"]["execution_authorized"] is False
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
    assert report["experimental"] is False


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

    assert report["result"]["status"] == "failed"
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


class SandboxRunReportContractTests(unittest.TestCase):
    def test_v1_report_distinguishes_command_exit_2_from_policy_block(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp) / "repo")
            approval_path = _approval_file(repo, Path(tmp) / "approval.json")
            command_exit = run_sandbox_run(
                repo,
                approval_path=approval_path,
                image=IMAGE,
                profile_name="no-network-default",
                command_argv=COMMAND,
                runner=FakeDockerRunner(mode="failure", exit_code=2, docker_invoked=True),
            )
            policy_block = run_sandbox_run(
                repo,
                image=IMAGE,
                profile_name="locked-down",
                command_argv=COMMAND,
                runner=FakeDockerRunner(),
                gate_decision={"verdict": "quarantine", "decision_kind": "repo_health_gate_decision", "schema_version": "0.1-draft"},
                fail_on_gate="quarantine",
            )

        self.assertFalse(command_exit["policy_blocked"])
        self.assertTrue(command_exit["command_started"])
        self.assertEqual(command_exit["command_exit_code"], 2)
        self.assertEqual(command_exit["sandbox_exit_code"], 2)
        self.assertTrue(policy_block["policy_blocked"])
        self.assertFalse(policy_block["command_started"])
        self.assertIsNone(policy_block["command_exit_code"])
        self.assertEqual(policy_block["sandbox_exit_code"], 2)
        self.assertEqual(policy_block["block_reason"], "gate_verdict_quarantine")

    def test_v1_report_contains_core_contract_and_env_policy(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp) / "repo")
            report = run_sandbox_run(
                repo,
                image=IMAGE,
                profile_name="locked-down",
                command_argv=COMMAND,
                runner=FakeDockerRunner(),
                dry_run=True,
            )

        _assert_sandbox_run_schema_valid(report)
        self.assertFalse(report["experimental"])
        self.assertEqual(report["contract"]["stage"], "sandbox-run-v1-core")
        self.assertFalse(report["contract"]["safety_proof_claimed"])
        self.assertFalse(report["env_policy"]["host_environment_inherited"])
        self.assertFalse(report["command"]["shell_wrapped_by_runner"])
        self.assertEqual(report["result"]["status"], "dry_run")

    def test_explicit_shell_is_reported_but_not_runner_wrapped(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            repo = _repo(Path(tmp) / "repo")
            report = run_sandbox_run(
                repo,
                image=IMAGE,
                profile_name="locked-down",
                command_argv=["sh", "-c", "echo explicit"],
                runner=FakeDockerRunner(),
                dry_run=True,
            )

        self.assertTrue(report["command"]["shell"])
        self.assertFalse(report["command"]["shell_wrapped_by_runner"])
        self.assertEqual(report["command"]["argv_redacted"], ["sh", "-c", "echo explicit"])
