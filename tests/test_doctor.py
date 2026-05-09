from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest

from repo_health_doctor.doctor import determine_exit_code, diagnose_repo, format_json, format_text


SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "public-safety-report.schema.json"


def _assert_matches_schema(testcase: unittest.TestCase, value: object, schema: dict, path: str = "$") -> None:
    expected_type = schema.get("type")
    if expected_type == "object":
        testcase.assertIsInstance(value, dict, f"{path} should be an object")
        assert isinstance(value, dict)
        for key in schema.get("required", []):
            testcase.assertIn(key, value, f"{path} missing required key: {key}")
        properties = schema.get("properties", {})
        for key, child_schema in properties.items():
            if key in value:
                _assert_matches_schema(testcase, value[key], child_schema, f"{path}.{key}")
        if schema.get("additionalProperties") is False:
            extra_keys = sorted(set(value) - set(properties))
            testcase.assertEqual(extra_keys, [], f"{path} has unexpected keys")
    elif expected_type == "array":
        testcase.assertIsInstance(value, list, f"{path} should be an array")
        assert isinstance(value, list)
        item_schema = schema.get("items")
        if item_schema:
            for index, item in enumerate(value):
                _assert_matches_schema(testcase, item, item_schema, f"{path}[{index}]")
    elif expected_type == "string":
        testcase.assertIsInstance(value, str, f"{path} should be a string")
    elif expected_type == "integer":
        testcase.assertIsInstance(value, int, f"{path} should be an integer")
        testcase.assertNotIsInstance(value, bool, f"{path} should be an integer, not boolean")
    elif expected_type == "boolean":
        testcase.assertIsInstance(value, bool, f"{path} should be a boolean")

    if "enum" in schema:
        testcase.assertIn(value, schema["enum"], f"{path} has invalid enum value")
    if "minimum" in schema:
        testcase.assertGreaterEqual(value, schema["minimum"], f"{path} is below minimum")


class RepoHealthDoctorBehaviorTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmp_dir.name)

    def tearDown(self) -> None:
        self._tmp_dir.cleanup()

    def _init_git_repo(self) -> None:
        subprocess.run(
            ["git", "init"],
            cwd=self.tmp_path,
            check=True,
            capture_output=True,
            text=True,
        )

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
        self.assertEqual(payload["schema_version"], "1.0")
        self.assertFalse(Path(payload["repo_path"]).is_absolute())

    def test_block_exit_code_when_secret_detected(self) -> None:
        (self.tmp_path / "README.md").write_text("# Demo\n", encoding="utf-8")
        secret_line = 'to' + 'ken = "' + ("a" * 20) + '"\n'
        (self.tmp_path / "config.py").write_text(secret_line, encoding="utf-8")

        report = diagnose_repo(self.tmp_path)
        self.assertEqual(report["overall_status"], "block")
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

    def test_default_ignored_directory_is_not_scanned_for_secrets(self) -> None:
        (self.tmp_path / "README.md").write_text("# Demo\n", encoding="utf-8")
        (self.tmp_path / ".pytest_cache").mkdir()
        secret_line = 'to' + 'ken = "' + ("a" * 20) + '"\n'
        (self.tmp_path / ".pytest_cache" / "cache.py").write_text(secret_line, encoding="utf-8")

        report = diagnose_repo(self.tmp_path)
        checks = {check["name"]: check for check in report["checks"]}

        self.assertEqual(checks["secrets_scan"]["status"], "pass")

    def test_normal_file_secret_is_detected(self) -> None:
        (self.tmp_path / "README.md").write_text("# Demo\n", encoding="utf-8")
        secret_line = 'to' + 'ken = "' + ("a" * 20) + '"\n'
        (self.tmp_path / "app.py").write_text(secret_line, encoding="utf-8")

        report = diagnose_repo(self.tmp_path)
        checks = {check["name"]: check for check in report["checks"]}

        self.assertEqual(checks["secrets_scan"]["status"], "block")
        self.assertEqual(checks["secrets_scan"]["details"]["findings"][0]["file"], "app.py")
        self.assertEqual(
            checks["secrets_scan"]["details"]["findings"][0]["rule_id"],
            "rhd.secret.generic_api_key",
        )
        self.assertEqual(checks["secrets_scan"]["details"]["findings"][0]["severity"], "block")
        self.assertNotIn("excerpt", checks["secrets_scan"]["details"]["findings"][0])

    def test_secret_findings_are_redacted_in_json_and_text(self) -> None:
        (self.tmp_path / "README.md").write_text("# Demo\n", encoding="utf-8")
        secret_value = "s" * 24
        secret_line = 'api_' + 'key = "' + secret_value + '"\n'
        (self.tmp_path / "app.py").write_text(secret_line, encoding="utf-8")

        report = diagnose_repo(self.tmp_path)
        rendered_json = format_json(report)
        rendered_text = format_text(report)

        self.assertEqual(report["overall_status"], "block")
        self.assertNotIn(secret_value, rendered_json)
        self.assertNotIn(secret_line.strip(), rendered_json)
        self.assertNotIn(secret_value, rendered_text)
        self.assertNotIn(secret_line.strip(), rendered_text)
        self.assertNotIn("excerpt", rendered_json)

    def test_cli_secrets_ignore_skips_matching_path(self) -> None:
        (self.tmp_path / "README.md").write_text("# Demo\n", encoding="utf-8")
        (self.tmp_path / "artifacts").mkdir()
        secret_line = 'to' + 'ken = "' + ("a" * 20) + '"\n'
        (self.tmp_path / "artifacts" / "sample.py").write_text(secret_line, encoding="utf-8")

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
                "--secrets-ignore",
                "artifacts/",
            ],
            check=True,
            capture_output=True,
            text=True,
            env=env,
        )

        payload = json.loads(result.stdout)
        checks = {check["name"]: check for check in payload["checks"]}

        self.assertEqual(checks["secrets_scan"]["status"], "pass")

    def test_binary_file_is_skipped_by_secrets_scan(self) -> None:
        (self.tmp_path / "README.md").write_text("# Demo\n", encoding="utf-8")
        binary_secret = b"\x00\x01\x02" + b"to" + b"ken=" + (b"a" * 20)
        (self.tmp_path / "blob.bin").write_bytes(binary_secret)

        report = diagnose_repo(self.tmp_path)
        checks = {check["name"]: check for check in report["checks"]}

        self.assertEqual(checks["secrets_scan"]["status"], "pass")
        self.assertEqual(checks["secrets_scan"]["details"]["scanned_files"], 1)

    def test_public_safety_is_opt_in(self) -> None:
        (self.tmp_path / "README.md").write_text("# Demo\n", encoding="utf-8")

        report = diagnose_repo(self.tmp_path)
        check_names = {check["name"] for check in report["checks"]}

        self.assertNotIn("public_text_safety", check_names)
        self.assertNotIn("tracked_artifacts", check_names)

    def test_public_safety_detects_restricted_term(self) -> None:
        self._init_git_repo()
        (self.tmp_path / "README.md").write_text("# Demo\n", encoding="utf-8")
        restricted_text = "public note: " + "Fi" + "nd" + "y" + "\n"
        (self.tmp_path / "notes.txt").write_text(restricted_text, encoding="utf-8")
        subprocess.run(
            ["git", "add", "README.md", "notes.txt"],
            cwd=self.tmp_path,
            check=True,
            capture_output=True,
            text=True,
        )

        report = diagnose_repo(self.tmp_path, public_safety=True)
        checks = {check["name"]: check for check in report["checks"]}

        self.assertEqual(checks["public_text_safety"]["status"], "block")
        self.assertEqual(checks["public_text_safety"]["details"]["findings"][0]["pattern"], "restricted_term")
        self.assertEqual(
            checks["public_text_safety"]["details"]["findings"][0]["rule_id"],
            "rhd.public_text.restricted_term",
        )
        self.assertEqual(checks["public_text_safety"]["details"]["findings"][0]["severity"], "block")
        self.assertEqual(checks["public_text_safety"]["details"]["scan_scope"], "tracked")

    def test_public_safety_detects_private_path(self) -> None:
        self._init_git_repo()
        (self.tmp_path / "README.md").write_text("# Demo\n", encoding="utf-8")
        private_path = "/" + "ho" + "me" + "/" + "user" + "/" + "work" + "\n"
        (self.tmp_path / "notes.txt").write_text(private_path, encoding="utf-8")
        subprocess.run(
            ["git", "add", "README.md", "notes.txt"],
            cwd=self.tmp_path,
            check=True,
            capture_output=True,
            text=True,
        )

        report = diagnose_repo(self.tmp_path, public_safety=True)
        checks = {check["name"]: check for check in report["checks"]}

        self.assertEqual(checks["public_text_safety"]["status"], "block")
        self.assertEqual(checks["public_text_safety"]["details"]["findings"][0]["pattern"], "private_path")
        self.assertEqual(
            checks["public_text_safety"]["details"]["findings"][0]["rule_id"],
            "rhd.public_text.private_path",
        )
        self.assertNotIn(private_path.strip(), format_json(report))
        self.assertNotIn(private_path.strip(), format_text(report))

    def test_public_safety_detects_local_ip_without_leaking_value(self) -> None:
        self._init_git_repo()
        (self.tmp_path / "README.md").write_text("# Demo\n", encoding="utf-8")
        local_ip = ".".join(("19" + "2", "16" + "8", "1", "25"))
        (self.tmp_path / "notes.txt").write_text(f"endpoint={local_ip}\n", encoding="utf-8")
        subprocess.run(
            ["git", "add", "README.md", "notes.txt"],
            cwd=self.tmp_path,
            check=True,
            capture_output=True,
            text=True,
        )

        report = diagnose_repo(self.tmp_path, public_safety=True)
        checks = {check["name"]: check for check in report["checks"]}
        rendered_json = format_json(report)
        rendered_text = format_text(report)

        self.assertEqual(checks["public_text_safety"]["status"], "block")
        self.assertEqual(checks["public_text_safety"]["details"]["findings"][0]["pattern"], "local_ip")
        self.assertEqual(
            checks["public_text_safety"]["details"]["findings"][0]["rule_id"],
            "rhd.public_text.local_ip",
        )
        self.assertEqual(checks["public_text_safety"]["details"]["findings"][0]["severity"], "block")
        self.assertNotIn(local_ip, rendered_json)
        self.assertNotIn(local_ip, rendered_text)

    def test_public_safety_detects_tracked_artifact_candidate(self) -> None:
        self._init_git_repo()
        (self.tmp_path / "README.md").write_text("# Demo\n", encoding="utf-8")
        (self.tmp_path / "artifacts").mkdir()
        (self.tmp_path / "artifacts" / "build.log").write_text("log\n", encoding="utf-8")
        subprocess.run(
            ["git", "add", "README.md", "artifacts/build.log"],
            cwd=self.tmp_path,
            check=True,
            capture_output=True,
            text=True,
        )

        report = diagnose_repo(self.tmp_path, public_safety=True)
        checks = {check["name"]: check for check in report["checks"]}

        self.assertEqual(checks["tracked_artifacts"]["status"], "block")
        self.assertEqual(checks["tracked_artifacts"]["details"]["findings"][0]["pattern"], "generated_dir")
        self.assertEqual(
            checks["tracked_artifacts"]["details"]["findings"][0]["rule_id"],
            "rhd.tracked_artifact.generated_dir",
        )
        self.assertEqual(checks["tracked_artifacts"]["details"]["findings"][0]["severity"], "block")

    def test_public_safety_allows_env_template(self) -> None:
        self._init_git_repo()
        (self.tmp_path / "README.md").write_text("# Demo\n", encoding="utf-8")
        (self.tmp_path / ".env.example").write_text("NAME=value\n", encoding="utf-8")
        subprocess.run(
            ["git", "add", "README.md", ".env.example"],
            cwd=self.tmp_path,
            check=True,
            capture_output=True,
            text=True,
        )

        report = diagnose_repo(self.tmp_path, public_safety=True)
        checks = {check["name"]: check for check in report["checks"]}

        self.assertEqual(checks["tracked_artifacts"]["status"], "pass")

    def test_large_file_finding_has_rule_id_and_warn_severity(self) -> None:
        (self.tmp_path / "README.md").write_text("# Demo\n", encoding="utf-8")
        (self.tmp_path / "large.bin").write_bytes(b"x" * (2 * 1024 * 1024))

        report = diagnose_repo(self.tmp_path, large_file_threshold_mb=1)
        checks = {check["name"]: check for check in report["checks"]}
        finding = checks["large_files"]["details"]["findings"][0]

        self.assertEqual(checks["large_files"]["status"], "warn")
        self.assertEqual(finding["rule_id"], "rhd.repository.large_file")
        self.assertEqual(finding["severity"], "warn")
        self.assertEqual(finding["pattern"], "large_file")
        self.assertFalse(finding["redacted"])

    def test_public_safety_report_matches_json_schema(self) -> None:
        self._init_git_repo()
        (self.tmp_path / "README.md").write_text("# Demo\n", encoding="utf-8")
        secret_line = 'api_' + 'key = "' + ("a" * 24) + '"\n'
        (self.tmp_path / "config.py").write_text(secret_line, encoding="utf-8")
        (self.tmp_path / "large.bin").write_bytes(b"x" * (2 * 1024 * 1024))
        (self.tmp_path / "artifacts").mkdir()
        (self.tmp_path / "artifacts" / "build.log").write_text("log\n", encoding="utf-8")
        subprocess.run(
            ["git", "add", "README.md", "artifacts/build.log"],
            cwd=self.tmp_path,
            check=True,
            capture_output=True,
            text=True,
        )

        report = diagnose_repo(self.tmp_path, large_file_threshold_mb=1, public_safety=True)
        payload = json.loads(format_json(report))
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

        _assert_matches_schema(self, payload, schema)

    def test_findings_share_stable_public_contract(self) -> None:
        (self.tmp_path / "README.md").write_text("# Demo\n", encoding="utf-8")
        secret_line = 'api_' + 'key = "' + ("a" * 24) + '"\n'
        (self.tmp_path / "app.py").write_text(secret_line, encoding="utf-8")
        (self.tmp_path / "large.bin").write_bytes(b"x" * (2 * 1024 * 1024))

        report = diagnose_repo(self.tmp_path, large_file_threshold_mb=1)
        findings = [
            finding
            for check in report["checks"]
            for finding in check["details"].get("findings", [])
        ]

        self.assertGreaterEqual(len(findings), 2)
        for finding in findings:
            self.assertTrue(finding["rule_id"].startswith("rhd."))
            self.assertIn(finding["severity"], {"warn", "block"})
            self.assertFalse(Path(finding["file"]).is_absolute())
            self.assertIn("pattern", finding)
            self.assertIsInstance(finding["redacted"], bool)

    def test_package_module_help_runs(self) -> None:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor",
                "--help",
            ],
            check=True,
            capture_output=True,
            text=True,
            env=env,
        )

        self.assertIn("repo-health-doctor", result.stdout)


if __name__ == "__main__":
    unittest.main()
