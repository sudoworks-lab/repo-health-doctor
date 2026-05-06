from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest

from repo_health_doctor.doctor import determine_exit_code, diagnose_repo, format_text


class RepoHealthDoctorBehaviorTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmp_dir.name)

    def tearDown(self) -> None:
        self._tmp_dir.cleanup()

    def test_diagnose_repo_detects_expected_checks(self) -> None:
        (self.tmp_path / "README.md").write_text("# Demo\n", encoding="utf-8")
        (self.tmp_path / "LICENSE").write_text("MIT\n", encoding="utf-8")
        (self.tmp_path / ".gitignore").write_text("__pycache__/\n", encoding="utf-8")
        (self.tmp_path / "tests").mkdir()
        (self.tmp_path / "docs").mkdir()
        (self.tmp_path / "scripts").mkdir()

        report = diagnose_repo(self.tmp_path)
        checks = {check["name"]: check for check in report["checks"]}

        self.assertEqual(report["overall_status"], "pass")
        self.assertEqual(checks["readme"]["status"], "pass")
        self.assertEqual(checks["license"]["status"], "pass")
        self.assertEqual(checks["gitignore"]["status"], "pass")
        self.assertEqual(checks["tests"]["status"], "pass")
        self.assertEqual(checks["docs"]["status"], "pass")
        self.assertEqual(checks["scripts"]["status"], "pass")
        self.assertEqual(checks["secrets_scan"]["status"], "pass")
        self.assertEqual(checks["large_files"]["status"], "pass")
        self.assertIn("Repo Health Doctor: PASS", format_text(report))

    def test_cli_outputs_json(self) -> None:
        (self.tmp_path / "README.md").write_text("# Demo\n", encoding="utf-8")

        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor.cli",
                str(self.tmp_path),
                "--format",
                "json",
            ],
            check=True,
            capture_output=True,
            text=True,
            env=env,
        )

        payload = json.loads(result.stdout)
        self.assertEqual(payload["tool"], "repo-health-doctor")
        self.assertEqual(payload["repo_path"], str(self.tmp_path.resolve()))

    def test_fail_exit_code_when_secret_detected(self) -> None:
        (self.tmp_path / "README.md").write_text("# Demo\n", encoding="utf-8")
        secret_line = 'to' + 'ken = "' + ("a" * 20) + '"\n'
        (self.tmp_path / "config.py").write_text(secret_line, encoding="utf-8")

        report = diagnose_repo(self.tmp_path)
        self.assertEqual(report["overall_status"], "fail")
        self.assertEqual(determine_exit_code(report), 1)

    def test_warn_only_exit_code_without_strict_is_zero(self) -> None:
        (self.tmp_path / "README.md").write_text("# Demo\n", encoding="utf-8")

        report = diagnose_repo(self.tmp_path)
        self.assertEqual(report["overall_status"], "warn")
        self.assertEqual(determine_exit_code(report, strict=False), 0)

    def test_warn_only_exit_code_with_strict_is_one(self) -> None:
        (self.tmp_path / "README.md").write_text("# Demo\n", encoding="utf-8")

        report = diagnose_repo(self.tmp_path)
        self.assertEqual(report["overall_status"], "warn")
        self.assertEqual(determine_exit_code(report, strict=True), 1)

    def test_large_file_threshold_option_changes_result(self) -> None:
        (self.tmp_path / "README.md").write_text("# Demo\n", encoding="utf-8")
        (self.tmp_path / "LICENSE").write_text("MIT\n", encoding="utf-8")
        (self.tmp_path / ".gitignore").write_text("__pycache__/\n", encoding="utf-8")
        (self.tmp_path / "tests").mkdir()
        (self.tmp_path / "docs").mkdir()
        (self.tmp_path / "scripts").mkdir()
        (self.tmp_path / "large.bin").write_bytes(b"x" * (2 * 1024 * 1024))

        default_report = diagnose_repo(self.tmp_path)
        strict_report = diagnose_repo(self.tmp_path, large_file_threshold_mb=1)
        checks = {check["name"]: check for check in strict_report["checks"]}

        self.assertEqual(default_report["overall_status"], "pass")
        self.assertEqual(strict_report["overall_status"], "warn")
        self.assertEqual(checks["large_files"]["status"], "warn")
        self.assertEqual(checks["large_files"]["details"]["threshold_mb"], 1)

    def test_json_output_file_is_created(self) -> None:
        (self.tmp_path / "README.md").write_text("# Demo\n", encoding="utf-8")
        output_path = self.tmp_path / "report.json"

        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor.cli",
                str(self.tmp_path),
                "--format",
                "json",
                "--output",
                str(output_path),
            ],
            check=True,
            capture_output=True,
            text=True,
            env=env,
        )

        self.assertTrue(output_path.exists())
        self.assertEqual(result.stdout, output_path.read_text(encoding="utf-8"))
        payload = json.loads(output_path.read_text(encoding="utf-8"))
        self.assertEqual(payload["tool"], "repo-health-doctor")

    def test_text_output_file_is_created(self) -> None:
        (self.tmp_path / "README.md").write_text("# Demo\n", encoding="utf-8")
        output_path = self.tmp_path / "report.txt"

        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor.cli",
                str(self.tmp_path),
                "--output",
                str(output_path),
            ],
            check=True,
            capture_output=True,
            text=True,
            env=env,
        )

        self.assertTrue(output_path.exists())
        self.assertEqual(result.stdout, output_path.read_text(encoding="utf-8"))
        self.assertIn("Repo Health Doctor:", output_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
