from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "validate_final_security_gates.py"
SCHEMA_PATH = ROOT / "docs" / "human-review" / "final-security-gates.schema.json"
CANDIDATE_PATH = ROOT / "docs" / "human-review" / "rhd-locked-down-v1.candidate.json"


def _load_validator():
    spec = importlib.util.spec_from_file_location("validate_final_security_gates", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


VALIDATOR = _load_validator()


def _head_sha() -> str:
    return subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _valid_evidence() -> dict[str, object]:
    return {
        "schema_version": "0.1-draft",
        "evidence_kind": "final_security_gates",
        "hosted_workflow": {
            "provider": "github_actions",
            "runner_environment": "github_hosted",
            "workflow_path": ".github/workflows/real-docker-verification.yml",
            "event": "workflow_dispatch",
            "conclusion": "success",
            "run_id": 123456,
            "head_sha": _head_sha(),
            "docker_server_version": "28.3.3",
            "runner_os": "Linux",
            "runner_architecture": "X64",
        },
        "seccomp_approval": {
            "approval_kind": "human",
            "decision": "approved",
            "syscall_reduction_approved": True,
            "profile_name": "rhd-locked-down-v1",
            "approved_profile_sha256": hashlib.sha256(CANDIDATE_PATH.read_bytes()).hexdigest(),
            "approved_by": "maintainer-reviewer",
            "approved_at": "2026-07-17T09:00:00+09:00",
        },
    }


class FinalSecurityGatesTests(unittest.TestCase):
    def _validate(self, evidence: dict[str, object]) -> tuple[bool, list[str]]:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "evidence.json"
            path.write_text(json.dumps(evidence), encoding="utf-8")
            return VALIDATOR.validate_final_security_gates(path)

    def test_schema_is_closed_and_requires_all_human_gate_sections(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

        self.assertEqual("object", schema["type"])
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            {
                "schema_version",
                "evidence_kind",
                "hosted_workflow",
                "seccomp_approval",
            },
            set(schema["required"]),
        )
        self.assertFalse(schema["properties"]["hosted_workflow"]["additionalProperties"])
        self.assertFalse(schema["properties"]["seccomp_approval"]["additionalProperties"])

    def test_valid_green_hosted_run_and_human_approval_are_accepted(self) -> None:
        valid, reasons = self._validate(_valid_evidence())

        self.assertTrue(valid)
        self.assertEqual([], reasons)

    def test_green_run_url_can_supply_the_required_run_reference(self) -> None:
        evidence = _valid_evidence()
        workflow = evidence["hosted_workflow"]
        assert isinstance(workflow, dict)
        workflow.pop("run_id")
        workflow["run_url"] = "https://github.com/example/project/actions/runs/123456"

        valid, reasons = self._validate(evidence)

        self.assertTrue(valid)
        self.assertEqual([], reasons)

    def test_hosted_workflow_fields_and_reachable_commit_fail_closed(self) -> None:
        evidence = _valid_evidence()
        workflow = evidence["hosted_workflow"]
        assert isinstance(workflow, dict)
        workflow["runner_environment"] = "self_hosted"
        workflow["event"] = "push"
        workflow["conclusion"] = "failure"
        workflow["head_sha"] = "f" * 40
        workflow["docker_server_version"] = ""
        workflow["runner_os"] = ""
        workflow["runner_architecture"] = ""

        valid, reasons = self._validate(evidence)

        self.assertFalse(valid)
        self.assertIn("hosted_runner_environment_invalid", reasons)
        self.assertIn("hosted_event_invalid", reasons)
        self.assertIn("hosted_conclusion_invalid", reasons)
        self.assertIn("hosted_target_commit_unreachable", reasons)
        self.assertIn("hosted_docker_version_invalid", reasons)
        self.assertIn("hosted_os_invalid", reasons)
        self.assertIn("hosted_architecture_invalid", reasons)

    def test_seccomp_human_approval_and_candidate_hash_fail_closed(self) -> None:
        evidence = _valid_evidence()
        approval = evidence["seccomp_approval"]
        assert isinstance(approval, dict)
        approval["approval_kind"] = "automation"
        approval["decision"] = "pending"
        approval["syscall_reduction_approved"] = False
        approval["approved_profile_sha256"] = "0" * 64
        approval["approved_by"] = ""
        approval["approved_at"] = "not-a-date"

        valid, reasons = self._validate(evidence)

        self.assertFalse(valid)
        self.assertIn("seccomp_human_approval_invalid", reasons)
        self.assertIn("seccomp_decision_invalid", reasons)
        self.assertIn("seccomp_reduction_approval_invalid", reasons)
        self.assertIn("approved_profile_hash_mismatch", reasons)
        self.assertIn("seccomp_approver_invalid", reasons)
        self.assertIn("seccomp_approval_time_invalid", reasons)

    def test_missing_and_extra_evidence_are_rejected_without_path_echo(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            missing = Path(temp_dir) / "private-location" / "evidence.json"
            completed = subprocess.run(
                ["python3", str(SCRIPT_PATH), str(missing)],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertEqual(1, completed.returncode)
        result = json.loads(completed.stdout)
        self.assertFalse(result["valid"])
        self.assertEqual(["evidence_missing"], result["reason_codes"])
        self.assertNotIn(str(missing), completed.stdout + completed.stderr)

        evidence = _valid_evidence()
        evidence["unexpected"] = "not-emitted"
        valid, reasons = self._validate(evidence)
        self.assertFalse(valid)
        self.assertIn("evidence_unexpected_fields", reasons)


if __name__ == "__main__":
    unittest.main()
