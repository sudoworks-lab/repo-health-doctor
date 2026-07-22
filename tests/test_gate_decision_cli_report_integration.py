from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from repo_health_doctor.cli import _bind_gate_decision_subject
from repo_health_doctor.gate import build_execution_authorization_draft, validate_gate_decision
from repo_health_doctor.sandbox.run_workspace import inspect_git_worktree


ROOT = Path(__file__).resolve().parents[1]
DEMO_REPO = ROOT / "tests" / "fixtures" / "demo-repo"
SYNTHETIC_SUPPLY_CHAIN = ROOT / "examples" / "demo-synthetic-supply-chain"
FORBIDDEN_PATTERNS = (
    "/home/",
    "/Users/",
    "C:\\Users\\",
    ".ssh",
    ".aws",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "AKIA",
    "ghp_",
    "github_pat_",
    "xoxb-",
    "sk-",
    "-----BEGIN",
    "password=",
    "token=",
)


class GateDecisionCliReportIntegrationTests(unittest.TestCase):
    def _cli_env(self) -> dict[str, str]:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        return env

    def _initialize_clean_git_repo(self, target: Path) -> None:
        tracked_files = sorted(
            str(path.relative_to(target))
            for path in target.rglob("*")
            if path.is_file()
        )
        for args in (
            ["git", "-C", str(target), "init", "-q"],
            ["git", "-C", str(target), "config", "user.email", "probe@example.invalid"],
            ["git", "-C", str(target), "config", "user.name", "synthetic"],
            ["git", "-C", str(target), "add", "--", *tracked_files],
            ["git", "-C", str(target), "commit", "-qm", "synthetic fixture"],
        ):
            subprocess.run(args, check=True, capture_output=True)

    def test_gate_decision_sidecar_does_not_change_default_json_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "report.json"
            gate_path = Path(tmp) / "gate-decision.json"
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "repo_health_doctor.cli",
                    str(DEMO_REPO),
                    "--public-safety",
                    "--format",
                    "json",
                    "--output",
                    str(report_path),
                    "--gate-decision-output",
                    str(gate_path),
                ],
                check=True,
                capture_output=True,
                text=True,
                env=self._cli_env(),
            )
            stdout_report = json.loads(result.stdout)
            written_report = json.loads(report_path.read_text(encoding="utf-8"))
            gate_decision = json.loads(gate_path.read_text(encoding="utf-8"))

        self.assertEqual(stdout_report, written_report)
        self.assertEqual(written_report["schema_version"], "1.1")
        self.assertNotIn("gate_decision", written_report)
        self.assertNotIn("execution_authorized", written_report)
        self.assertFalse(gate_decision["execution_authorized"])
        self.assertTrue(gate_decision["limitations"])
        self.assertIn("explanation", gate_decision)
        self.assertTrue(gate_decision["explanation"]["summary"])
        self.assertTrue(validate_gate_decision(gate_decision).valid)

    def test_default_cli_does_not_emit_gate_sidecar_without_opt_in(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "report.json"
            gate_path = Path(tmp) / "gate-decision.json"
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "repo_health_doctor.cli",
                    str(DEMO_REPO),
                    "--public-safety",
                    "--format",
                    "json",
                    "--output",
                    str(report_path),
                ],
                check=True,
                capture_output=True,
                text=True,
                env=self._cli_env(),
            )
            self.assertTrue(report_path.is_file())
            self.assertFalse(gate_path.exists())

    def test_fail_on_gate_quarantine_exits_2_and_writes_redacted_stderr(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor.cli",
                str(SYNTHETIC_SUPPLY_CHAIN),
                "--public-safety",
                "--fail-on-gate",
                "quarantine",
            ],
            check=False,
            capture_output=True,
            text=True,
            env=self._cli_env(),
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("Repo Health Doctor gate blocked execution.", result.stderr)
        self.assertIn("Gate decision: QUARANTINE", result.stderr)
        self.assertIn("Key reasons:", result.stderr)
        self.assertIn("Next actions:", result.stderr)
        for pattern in FORBIDDEN_PATTERNS:
            with self.subTest(pattern=pattern):
                self.assertNotIn(pattern, result.stderr)

    def test_gate_check_without_authorization_blocks_with_exit_2(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor.cli",
                "gate-check",
                str(DEMO_REPO),
                "--format",
                "json",
            ],
            check=False,
            capture_output=True,
            text=True,
            env=self._cli_env(),
        )

        self.assertEqual(result.returncode, 2)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "blocked")
        self.assertFalse(payload["execution_authorized"])
        self.assertIn("authorization_missing", payload["blocking_reasons"])
        self.assertIn("authorization_missing", result.stderr)

    def test_gate_check_with_matching_authorization_can_exit_0_when_gate_threshold_allows_warn(self) -> None:
        argv = ["python3", "-m", "pytest", "tests"]
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            target = tmp_path / "demo-repo"
            shutil.copytree(DEMO_REPO, target)
            self._initialize_clean_git_repo(target)
            gate_path = tmp_path / "gate.json"
            auth_path = tmp_path / "authorization.json"
            argv_path = tmp_path / "argv.json"
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "repo_health_doctor.cli",
                    str(target),
                    "--public-safety",
                    "--gate-decision-output",
                    str(gate_path),
                    "--output",
                    str(tmp_path / "report.txt"),
                ],
                check=True,
                capture_output=True,
                text=True,
                env=self._cli_env(),
            )
            gate = json.loads(gate_path.read_text(encoding="utf-8"))
            observed = inspect_git_worktree(target)
            self.assertEqual(gate["verdict"], "warn")
            self.assertEqual(gate["subject"]["commit"], observed["commit"])
            self.assertEqual(gate["subject"]["tree_hash"], observed["tree_hash"])
            self.assertEqual(gate["subject"]["binding_kind"], "commit_bound")
            authorization = dict(
                build_execution_authorization_draft(
                    gate,
                    argv,
                    expires_at="2099-01-01T00:00:00Z",
                )
            )
            authorization["approved"] = True
            authorization["approved_by"] = "redacted@example.test"
            authorization["approved_at"] = "2026-01-01T00:00:00Z"
            auth_path.write_text(json.dumps(authorization, indent=2) + "\n", encoding="utf-8")
            argv_path.write_text(json.dumps(argv, indent=2) + "\n", encoding="utf-8")

            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "repo_health_doctor.cli",
                    "gate-check",
                    str(target),
                    "--fail-on-gate",
                    "quarantine",
                    "--authorization",
                    str(auth_path),
                    "--argv-json",
                    str(argv_path),
                    "--format",
                    "json",
                ],
                check=False,
                capture_output=True,
                text=True,
                env=self._cli_env(),
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "authorized")
        self.assertTrue(payload["execution_authorized"])
        self.assertEqual(payload["gate_decision"]["verdict"], "warn")
        self.assertEqual(payload["gate_decision"]["subject"], gate["subject"])

    def test_gate_subject_binding_requires_clean_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "repo"
            target.mkdir()
            readme = target / "README.md"
            readme.write_text("clean\n", encoding="utf-8")
            self._initialize_clean_git_repo(target)
            gate = {
                "subject": {
                    "repo": "<repo>",
                    "commit": None,
                    "tree_hash": None,
                    "binding_kind": "path_bound",
                },
                "verdict": "warn",
            }

            clean = _bind_gate_decision_subject(gate, target)
            readme.write_text("dirty\n", encoding="utf-8")
            dirty = _bind_gate_decision_subject(gate, target)

        self.assertEqual(clean["subject"]["binding_kind"], "commit_bound")
        self.assertIsNotNone(clean["subject"]["commit"])
        self.assertIsNotNone(clean["subject"]["tree_hash"])
        self.assertEqual(dirty, gate)


if __name__ == "__main__":
    unittest.main()
