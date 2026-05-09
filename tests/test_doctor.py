from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest

from repo_health_doctor.doctor import (
    TOOL_VERSION,
    determine_exit_code,
    diagnose_repo,
    format_json,
    format_text,
    validate_policy,
)


SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "public-safety-report.schema.json"
POLICY_SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "policy-config.schema.json"
FIXTURES_PATH = Path(__file__).resolve().parent / "fixtures"
POLICY_FIXTURES_PATH = FIXTURES_PATH / "policies"
VALID_POLICY_REPO_PATH = FIXTURES_PATH / "policy-valid-repo"
GOLDEN_POLICY_REPORT_PATH = FIXTURES_PATH / "golden" / "valid-policy-report.json"


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

    def _write_complete_repo_baseline(self) -> None:
        (self.tmp_path / "README.md").write_text("# Demo\n", encoding="utf-8")
        (self.tmp_path / "LICENSE").write_text("MIT\n", encoding="utf-8")
        (self.tmp_path / ".gitignore").write_text("__pycache__/\n", encoding="utf-8")
        (self.tmp_path / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
        (self.tmp_path / ".github" / "workflows" / "ci.yml").write_text("name: CI\n", encoding="utf-8")
        (self.tmp_path / "tests").mkdir(exist_ok=True)
        (self.tmp_path / "docs").mkdir(exist_ok=True)
        (self.tmp_path / "scripts").mkdir(exist_ok=True)

    def test_diagnose_repo_detects_expected_checks(self) -> None:
        (self.tmp_path / "README.md").write_text("# Demo\n", encoding="utf-8")
        (self.tmp_path / "LICENSE").write_text("MIT\n", encoding="utf-8")
        (self.tmp_path / ".gitignore").write_text("__pycache__/\n", encoding="utf-8")
        (self.tmp_path / ".github" / "workflows").mkdir(parents=True)
        (self.tmp_path / ".github" / "workflows" / "ci.yml").write_text("name: CI\n", encoding="utf-8")
        (self.tmp_path / "tests").mkdir()
        (self.tmp_path / "docs").mkdir()
        (self.tmp_path / "scripts").mkdir()

        report = diagnose_repo(self.tmp_path)
        checks = {check["name"]: check for check in report["checks"]}

        self.assertEqual(report["overall_status"], "pass")
        self.assertEqual(checks["readme"]["status"], "pass")
        self.assertEqual(checks["license"]["status"], "pass")
        self.assertEqual(checks["gitignore"]["status"], "pass")
        self.assertEqual(checks["ci"]["status"], "pass")
        self.assertEqual(checks["tests"]["status"], "pass")
        self.assertEqual(checks["docs"]["status"], "pass")
        self.assertEqual(checks["scripts"]["status"], "pass")
        self.assertEqual(checks["secrets_scan"]["status"], "pass")
        self.assertEqual(checks["large_files"]["status"], "pass")
        self.assertIn("Repo Health Doctor: PASS", format_text(report))

    def test_missing_readme_emits_warn_finding(self) -> None:
        report = diagnose_repo(self.tmp_path)
        rendered_text = format_text(report)
        checks = {check["name"]: check for check in report["checks"]}

        self.assertEqual(checks["readme"]["status"], "warn")
        self.assertEqual(checks["readme"]["details"]["findings"][0]["rule_id"], "rhd.repository.missing_readme")
        self.assertIn("rule=rhd.repository.missing_readme", rendered_text)

    def test_missing_license_emits_warn_finding(self) -> None:
        (self.tmp_path / "README.md").write_text("# Demo\n", encoding="utf-8")

        report = diagnose_repo(self.tmp_path)
        checks = {check["name"]: check for check in report["checks"]}

        self.assertEqual(checks["license"]["status"], "warn")
        self.assertEqual(checks["license"]["details"]["findings"][0]["rule_id"], "rhd.repository.missing_license")

    def test_missing_ci_emits_warn_finding(self) -> None:
        self._write_complete_repo_baseline()
        (self.tmp_path / ".github" / "workflows" / "ci.yml").unlink()

        report = diagnose_repo(self.tmp_path)
        checks = {check["name"]: check for check in report["checks"]}

        self.assertEqual(checks["ci"]["status"], "warn")
        self.assertEqual(checks["ci"]["details"]["findings"][0]["rule_id"], "rhd.repository.missing_ci")

    def test_missing_tests_emits_warn_finding(self) -> None:
        self._write_complete_repo_baseline()
        (self.tmp_path / "tests").rmdir()

        report = diagnose_repo(self.tmp_path)
        checks = {check["name"]: check for check in report["checks"]}

        self.assertEqual(checks["tests"]["status"], "warn")
        self.assertEqual(checks["tests"]["details"]["findings"][0]["rule_id"], "rhd.repository.missing_tests")

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
        self.assertEqual(payload["schema_version"], "1.1")
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

    def test_warn_only_exit_code_with_fail_on_warn_is_one(self) -> None:
        (self.tmp_path / "README.md").write_text("# Demo\n", encoding="utf-8")

        report = diagnose_repo(self.tmp_path)
        self.assertEqual(report["overall_status"], "warn")
        self.assertEqual(determine_exit_code(report, fail_on="warn"), 1)

    def test_large_file_threshold_option_changes_result(self) -> None:
        (self.tmp_path / "README.md").write_text("# Demo\n", encoding="utf-8")
        (self.tmp_path / "LICENSE").write_text("MIT\n", encoding="utf-8")
        (self.tmp_path / ".gitignore").write_text("__pycache__/\n", encoding="utf-8")
        (self.tmp_path / ".github" / "workflows").mkdir(parents=True)
        (self.tmp_path / ".github" / "workflows" / "ci.yml").write_text("name: CI\n", encoding="utf-8")
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

    def test_text_output_includes_cli_ux_context_without_raw_secret(self) -> None:
        (self.tmp_path / "README.md").write_text("# Demo\n", encoding="utf-8")
        secret_value = "s" * 24
        (self.tmp_path / "app.py").write_text('api_' + 'key = "' + secret_value + '"\n', encoding="utf-8")

        report = diagnose_repo(self.tmp_path)
        rendered_text = format_text(report)

        self.assertIn("Schema: 1.1", rendered_text)
        self.assertIn("Status: PASS ok, WARN review, BLOCK release blocker", rendered_text)
        self.assertIn("rule=rhd.secret.generic_api_key", rendered_text)
        self.assertNotIn(secret_value, rendered_text)

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

    def test_public_safety_detects_build_and_generated_tracked_artifacts(self) -> None:
        self._init_git_repo()
        (self.tmp_path / "README.md").write_text("# Demo\n", encoding="utf-8")
        for directory in ("build", "generated"):
            target_dir = self.tmp_path / directory
            target_dir.mkdir()
            (target_dir / "output.txt").write_text("artifact\n", encoding="utf-8")
        subprocess.run(
            ["git", "add", "README.md", "build/output.txt", "generated/output.txt"],
            cwd=self.tmp_path,
            check=True,
            capture_output=True,
            text=True,
        )

        report = diagnose_repo(self.tmp_path, public_safety=True)
        checks = {check["name"]: check for check in report["checks"]}
        findings = checks["tracked_artifacts"]["details"]["findings"]
        files = {finding["file"] for finding in findings}

        self.assertEqual(checks["tracked_artifacts"]["status"], "block")
        self.assertIn("build/output.txt", files)
        self.assertIn("generated/output.txt", files)
        self.assertTrue(all(finding["rule_id"] == "rhd.tracked_artifact.generated_dir" for finding in findings))

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

    def test_policy_ignore_paths_only_exclude_non_security_checks(self) -> None:
        self._init_git_repo()
        self._write_complete_repo_baseline()
        (self.tmp_path / "artifacts").mkdir()
        secret_line = 'to' + 'ken = "' + ("a" * 20) + '"\n'
        (self.tmp_path / "artifacts" / "sample.py").write_text(secret_line, encoding="utf-8")
        (self.tmp_path / "artifacts" / "build.log").write_text("log\n", encoding="utf-8")
        (self.tmp_path / "artifacts" / "large.bin").write_bytes(b"x" * (2 * 1024 * 1024))
        (self.tmp_path / "repo-health-doctor.yml").write_text(
            "ignore_paths:\n"
            "  - artifacts/\n",
            encoding="utf-8",
        )
        subprocess.run(
            ["git", "add", "README.md", "artifacts/build.log"],
            cwd=self.tmp_path,
            check=True,
            capture_output=True,
            text=True,
        )

        report = diagnose_repo(self.tmp_path, public_safety=True, large_file_threshold_mb=1)
        checks = {check["name"]: check for check in report["checks"]}

        self.assertEqual(checks["secrets_scan"]["status"], "block")
        self.assertEqual(checks["tracked_artifacts"]["status"], "block")
        self.assertEqual(checks["large_files"]["status"], "pass")
        self.assertEqual(checks["policy"]["status"], "pass")
        self.assertEqual(checks["policy"]["details"]["ignore_path_count"], 1)

    def test_policy_ignore_paths_wildcard_does_not_hide_secret_finding(self) -> None:
        self._write_complete_repo_baseline()
        secret_value = "s" * 24
        (self.tmp_path / "app.py").write_text('api_' + 'key = "' + secret_value + '"\n', encoding="utf-8")
        (self.tmp_path / "repo-health-doctor.yml").write_text(
            "ignore_paths:\n"
            "  - '*'\n",
            encoding="utf-8",
        )

        report = diagnose_repo(self.tmp_path)
        checks = {check["name"]: check for check in report["checks"]}

        self.assertEqual(checks["secrets_scan"]["status"], "block")
        self.assertEqual(
            checks["secrets_scan"]["details"]["findings"][0]["rule_id"],
            "rhd.secret.generic_api_key",
        )

    def test_policy_ignore_paths_wildcard_does_not_hide_public_text_findings(self) -> None:
        self._init_git_repo()
        self._write_complete_repo_baseline()
        private_path = "/ho" + "me/" + "demo/private/project"
        local_ip = "192." + "168.1.20"
        (self.tmp_path / "docs" / "public.md").write_text(
            f"path={private_path}\nip={local_ip}\n",
            encoding="utf-8",
        )
        (self.tmp_path / "repo-health-doctor.yml").write_text(
            "ignore_paths:\n"
            "  - '*'\n",
            encoding="utf-8",
        )
        subprocess.run(
            ["git", "add", "README.md", "docs/public.md"],
            cwd=self.tmp_path,
            check=True,
            capture_output=True,
            text=True,
        )

        report = diagnose_repo(self.tmp_path, public_safety=True)
        checks = {check["name"]: check for check in report["checks"]}
        rule_ids = {finding["rule_id"] for finding in checks["public_text_safety"]["details"]["findings"]}

        self.assertEqual(checks["public_text_safety"]["status"], "block")
        self.assertIn("rhd.public_text.private_path", rule_ids)
        self.assertIn("rhd.public_text.local_ip", rule_ids)

    def test_policy_ignore_paths_wildcard_does_not_hide_tracked_artifact_finding(self) -> None:
        self._init_git_repo()
        self._write_complete_repo_baseline()
        (self.tmp_path / "artifacts").mkdir()
        (self.tmp_path / "artifacts" / "build.log").write_text("log\n", encoding="utf-8")
        (self.tmp_path / "repo-health-doctor.yml").write_text(
            "ignore_paths:\n"
            "  - '*'\n",
            encoding="utf-8",
        )
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
        self.assertEqual(
            checks["tracked_artifacts"]["details"]["findings"][0]["rule_id"],
            "rhd.tracked_artifact.generated_dir",
        )

    def test_policy_ignore_paths_wildcard_cannot_disable_security_checks_in_reports(self) -> None:
        self._init_git_repo()
        self._write_complete_repo_baseline()
        secret_value = "s" * 24
        private_path = "/ho" + "me/" + "demo/private/project"
        local_ip = "192." + "168.1.20"
        (self.tmp_path / "app.py").write_text('api_' + 'key = "' + secret_value + '"\n', encoding="utf-8")
        (self.tmp_path / "docs" / "public.md").write_text(
            f"path={private_path}\nip={local_ip}\n",
            encoding="utf-8",
        )
        (self.tmp_path / "repo-health-doctor.yml").write_text(
            "ignore_paths:\n"
            "  - '*'\n",
            encoding="utf-8",
        )
        subprocess.run(
            ["git", "add", "README.md", "app.py", "docs/public.md"],
            cwd=self.tmp_path,
            check=True,
            capture_output=True,
            text=True,
        )

        report = diagnose_repo(self.tmp_path, public_safety=True)
        rendered_json = format_json(report)
        rendered_text = format_text(report)

        self.assertIn("rhd.secret.generic_api_key", rendered_json)
        self.assertIn("rhd.public_text.private_path", rendered_json)
        self.assertIn("rhd.public_text.local_ip", rendered_json)
        self.assertIn("rhd.secret.generic_api_key", rendered_text)
        self.assertIn("rhd.public_text.private_path", rendered_text)
        self.assertIn("rhd.public_text.local_ip", rendered_text)
        self.assertNotIn(secret_value, rendered_json)
        self.assertNotIn(secret_value, rendered_text)
        self.assertNotIn(private_path, rendered_json)
        self.assertNotIn(private_path, rendered_text)
        self.assertNotIn(local_ip, rendered_json)
        self.assertNotIn(local_ip, rendered_text)

    def test_policy_allows_matching_large_file_finding(self) -> None:
        self._write_complete_repo_baseline()
        (self.tmp_path / "large.bin").write_bytes(b"x" * (2 * 1024 * 1024))
        (self.tmp_path / "repo-health-doctor.yml").write_text(
            "allow_findings:\n"
            "  - rule_id: rhd.repository.large_file\n"
            "    path: large.bin\n"
            "    reason: reviewed category\n"
            "    owner: release-team\n"
            "    expires: 2999-01-01\n",
            encoding="utf-8",
        )

        report = diagnose_repo(self.tmp_path, large_file_threshold_mb=1)
        checks = {check["name"]: check for check in report["checks"]}
        finding = checks["large_files"]["details"]["findings"][0]

        self.assertEqual(report["overall_status"], "pass")
        self.assertEqual(checks["large_files"]["status"], "pass")
        self.assertTrue(finding["allowed"])
        self.assertEqual(finding["matched_policy_id"], "repo:allow:1")
        self.assertEqual(finding["policy_source"], "repo")

    def test_policy_allow_requires_reason_owner_and_expires(self) -> None:
        self._write_complete_repo_baseline()
        (self.tmp_path / "repo-health-doctor.yml").write_text(
            "allow_findings:\n"
            "  - rule_id: rhd.repository.large_file\n"
            "    path: large.bin\n",
            encoding="utf-8",
        )

        report = diagnose_repo(self.tmp_path)
        checks = {check["name"]: check for check in report["checks"]}
        finding = checks["policy"]["details"]["findings"][0]

        self.assertEqual(checks["policy"]["status"], "block")
        self.assertEqual(finding["rule_id"], "rhd.policy.invalid_allow")
        self.assertEqual(finding["matched_policy_id"], "repo:allow:1")

    def test_expired_policy_allow_blocks(self) -> None:
        self._write_complete_repo_baseline()
        (self.tmp_path / "repo-health-doctor.yml").write_text(
            "allow_findings:\n"
            "  - rule_id: rhd.repository.large_file\n"
            "    path: large.bin\n"
            "    reason: reviewed category\n"
            "    owner: release-team\n"
            "    expires: 2000-01-01\n",
            encoding="utf-8",
        )

        report = diagnose_repo(self.tmp_path)
        checks = {check["name"]: check for check in report["checks"]}
        finding = checks["policy"]["details"]["findings"][0]

        self.assertEqual(report["overall_status"], "block")
        self.assertEqual(finding["rule_id"], "rhd.policy.expired_allow")

    def test_unknown_policy_rule_id_blocks_without_echoing_value(self) -> None:
        self._write_complete_repo_baseline()
        unknown_rule_id = "rhd.example.unknown"
        (self.tmp_path / "repo-health-doctor.yml").write_text(
            "allow_findings:\n"
            f"  - rule_id: {unknown_rule_id}\n"
            "    path: docs/generated.bin\n"
            "    reason: reviewed category\n"
            "    owner: release-team\n"
            "    expires: 2999-01-01\n",
            encoding="utf-8",
        )

        report = diagnose_repo(self.tmp_path)
        rendered_json = format_json(report)
        rendered_text = format_text(report)
        checks = {check["name"]: check for check in report["checks"]}

        self.assertEqual(checks["policy"]["status"], "block")
        self.assertEqual(checks["policy"]["details"]["findings"][0]["rule_id"], "rhd.policy.unknown_rule_id")
        self.assertNotIn(unknown_rule_id, rendered_json)
        self.assertNotIn(unknown_rule_id, rendered_text)

    def test_secret_policy_allow_is_restricted_outside_fixtures(self) -> None:
        self._write_complete_repo_baseline()
        secret_value = "s" * 24
        (self.tmp_path / "app.py").write_text('api_' + 'key = "' + secret_value + '"\n', encoding="utf-8")
        (self.tmp_path / "repo-health-doctor.yml").write_text(
            "allow_findings:\n"
            "  - rule_id: rhd.secret.generic_api_key\n"
            "    path: app.py\n"
            "    reason: reviewed category\n"
            "    owner: release-team\n"
            "    expires: 2999-01-01\n",
            encoding="utf-8",
        )

        report = diagnose_repo(self.tmp_path)
        rendered_json = format_json(report)
        checks = {check["name"]: check for check in report["checks"]}

        self.assertEqual(checks["policy"]["status"], "block")
        self.assertEqual(
            checks["policy"]["details"]["findings"][0]["rule_id"],
            "rhd.policy.restricted_secret_allow",
        )
        self.assertEqual(checks["secrets_scan"]["status"], "block")
        self.assertNotIn(secret_value, rendered_json)

    def test_secret_policy_allow_can_match_fixture_path(self) -> None:
        self._write_complete_repo_baseline()
        fixture_dir = self.tmp_path / "tests" / "fixtures"
        fixture_dir.mkdir()
        secret_value = "s" * 24
        (fixture_dir / "app.py").write_text('api_' + 'key = "' + secret_value + '"\n', encoding="utf-8")
        (self.tmp_path / "repo-health-doctor.yml").write_text(
            "allow_findings:\n"
            "  - rule_id: rhd.secret.generic_api_key\n"
            "    path: tests/fixtures/app.py\n"
            "    reason: reviewed test fixture\n"
            "    owner: release-team\n"
            "    expires: 2999-01-01\n",
            encoding="utf-8",
        )

        report = diagnose_repo(self.tmp_path)
        rendered_json = format_json(report)
        checks = {check["name"]: check for check in report["checks"]}
        finding = checks["secrets_scan"]["details"]["findings"][0]

        self.assertEqual(report["overall_status"], "pass")
        self.assertEqual(checks["secrets_scan"]["status"], "pass")
        self.assertTrue(finding["allowed"])
        self.assertEqual(finding["matched_policy_id"], "repo:allow:1")
        self.assertNotIn(secret_value, rendered_json)

    def test_local_config_values_are_not_rendered(self) -> None:
        self._write_complete_repo_baseline()
        marker = "DO_NOT_LEAK_LOCAL_POLICY_VALUE"
        private_dir = self.tmp_path / "private-policy-area"
        private_dir.mkdir()
        (private_dir / "large.bin").write_bytes(b"x" * (2 * 1024 * 1024))
        local_config = self.tmp_path / ".repo-health-doctor.local.yml"
        local_config.write_text(
            "ignore_paths:\n"
            "  - private-policy-area/\n"
            "allow_findings:\n"
            "  - rule_id: rhd.repository.large_file\n"
            "    path: private-policy-area/large.bin\n"
            f"    reason: {marker}\n"
            f"    owner: {marker}\n"
            "    expires: 2999-01-01\n",
            encoding="utf-8",
        )

        report = diagnose_repo(self.tmp_path, large_file_threshold_mb=1)
        rendered_json = format_json(report)
        rendered_text = format_text(report)

        self.assertNotIn(marker, rendered_json)
        self.assertNotIn(marker, rendered_text)
        self.assertNotIn("private-policy-area", rendered_json)
        self.assertNotIn("private-policy-area", rendered_text)
        self.assertIn('"policy_sources"', rendered_json)
        self.assertIn('"local"', rendered_json)

    def test_no_local_config_skips_local_policy(self) -> None:
        self._write_complete_repo_baseline()
        (self.tmp_path / ".repo-health-doctor.local.yml").write_text(
            "allow_findings:\n"
            "  - rule_id: rhd.repository.large_file\n"
            "    path: large.bin\n",
            encoding="utf-8",
        )

        report = diagnose_repo(self.tmp_path, load_local_config=False)
        check_names = {check["name"] for check in report["checks"]}

        self.assertEqual(report["overall_status"], "pass")
        self.assertNotIn("policy", check_names)

    def test_policy_config_schema_matches_valid_fixture(self) -> None:
        schema = json.loads(POLICY_SCHEMA_PATH.read_text(encoding="utf-8"))
        payload = json.loads((POLICY_FIXTURES_PATH / "valid-policy.json").read_text(encoding="utf-8"))

        _assert_matches_schema(self, payload, schema)

    def test_validate_policy_valid_policy_passes_without_scanning(self) -> None:
        report = validate_policy(self.tmp_path, config_path=POLICY_FIXTURES_PATH / "valid-policy.yml")
        checks = {check["name"]: check for check in report["checks"]}

        self.assertEqual(report["overall_status"], "pass")
        self.assertEqual(list(checks), ["policy"])
        self.assertEqual(checks["policy"]["details"]["policy_sources"], ["repo"])
        self.assertEqual(checks["policy"]["details"]["ignore_path_count"], 1)
        self.assertEqual(checks["policy"]["details"]["allow_finding_count"], 1)

    def test_validate_policy_blocks_missing_required_field(self) -> None:
        report = validate_policy(self.tmp_path, config_path=POLICY_FIXTURES_PATH / "missing-required.yml")
        checks = {check["name"]: check for check in report["checks"]}
        finding = checks["policy"]["details"]["findings"][0]

        self.assertEqual(report["overall_status"], "block")
        self.assertEqual(finding["rule_id"], "rhd.policy.invalid_allow")
        self.assertEqual(finding["matched_policy_id"], "repo:allow:1")

    def test_validate_policy_blocks_invalid_ignore_paths(self) -> None:
        report = validate_policy(self.tmp_path, config_path=POLICY_FIXTURES_PATH / "invalid-ignore.json")
        checks = {check["name"]: check for check in report["checks"]}
        finding = checks["policy"]["details"]["findings"][0]

        self.assertEqual(report["overall_status"], "block")
        self.assertEqual(finding["rule_id"], "rhd.policy.invalid_ignore")
        self.assertEqual(finding["matched_policy_id"], "repo:ignore:1")

    def test_validate_policy_blocks_invalid_expiration_date(self) -> None:
        report = validate_policy(self.tmp_path, config_path=POLICY_FIXTURES_PATH / "invalid-date.yml")
        checks = {check["name"]: check for check in report["checks"]}
        finding = checks["policy"]["details"]["findings"][0]

        self.assertEqual(report["overall_status"], "block")
        self.assertEqual(finding["rule_id"], "rhd.policy.invalid_allow")
        self.assertEqual(finding["matched_policy_id"], "repo:allow:1")

    def test_validate_policy_blocks_expired_allow(self) -> None:
        report = validate_policy(self.tmp_path, config_path=POLICY_FIXTURES_PATH / "expired-allow.yml")
        checks = {check["name"]: check for check in report["checks"]}

        self.assertEqual(report["overall_status"], "block")
        self.assertEqual(
            checks["policy"]["details"]["findings"][0]["rule_id"],
            "rhd.policy.expired_allow",
        )

    def test_validate_policy_blocks_unknown_rule_id_without_echoing_value(self) -> None:
        unknown_rule_id = "rhd.example.unknown"
        report = validate_policy(self.tmp_path, config_path=POLICY_FIXTURES_PATH / "unknown-rule-id.yml")
        rendered_json = format_json(report)
        rendered_text = format_text(report)
        checks = {check["name"]: check for check in report["checks"]}

        self.assertEqual(report["overall_status"], "block")
        self.assertEqual(
            checks["policy"]["details"]["findings"][0]["rule_id"],
            "rhd.policy.unknown_rule_id",
        )
        self.assertNotIn(unknown_rule_id, rendered_json)
        self.assertNotIn(unknown_rule_id, rendered_text)

    def test_validate_policy_restricts_secret_rule_outside_fixture(self) -> None:
        report = validate_policy(self.tmp_path, config_path=POLICY_FIXTURES_PATH / "secret-outside-fixture.yml")
        checks = {check["name"]: check for check in report["checks"]}

        self.assertEqual(report["overall_status"], "block")
        self.assertEqual(
            checks["policy"]["details"]["findings"][0]["rule_id"],
            "rhd.policy.restricted_secret_allow",
        )

    def test_validate_policy_blocks_unknown_top_level_key_without_echoing_value(self) -> None:
        unknown_key = "ignore_pathz"
        raw_value = "private-policy-area/"
        (self.tmp_path / "repo-health-doctor.yml").write_text(
            f"{unknown_key}:\n"
            f"  - {raw_value}\n",
            encoding="utf-8",
        )

        report = validate_policy(self.tmp_path)
        rendered_json = format_json(report)
        rendered_text = format_text(report)
        checks = {check["name"]: check for check in report["checks"]}

        self.assertEqual(report["overall_status"], "block")
        self.assertEqual(
            checks["policy"]["details"]["findings"][0]["rule_id"],
            "rhd.policy.unknown_top_level_key",
        )
        self.assertNotIn(unknown_key, rendered_json)
        self.assertNotIn(unknown_key, rendered_text)
        self.assertNotIn(raw_value, rendered_json)
        self.assertNotIn(raw_value, rendered_text)

    def test_validate_policy_no_local_config_skips_local_policy(self) -> None:
        local_policy = (POLICY_FIXTURES_PATH / "local-invalid.yml").read_text(encoding="utf-8")
        (self.tmp_path / ".repo-health-doctor.local.yml").write_text(local_policy, encoding="utf-8")

        default_report = validate_policy(self.tmp_path)
        no_local_report = validate_policy(self.tmp_path, load_local_config=False)

        self.assertEqual(default_report["overall_status"], "block")
        self.assertEqual(no_local_report["overall_status"], "pass")
        self.assertEqual(no_local_report["checks"][0]["details"]["policy_sources"], [])

    def test_validate_policy_json_redacts_policy_values(self) -> None:
        marker = "POLICY_MARKER_VALUE"
        raw_path = "private-policy-area/generated.bin"
        unknown_rule_id = "rhd.example.unknown"
        (self.tmp_path / "repo-health-doctor.yml").write_text(
            "allow_findings:\n"
            f"  - rule_id: {unknown_rule_id}\n"
            f"    path: {raw_path}\n"
            f"    reason: {marker}\n"
            f"    owner: {marker}\n"
            "    expires: 2999-01-01\n",
            encoding="utf-8",
        )

        report = validate_policy(self.tmp_path)
        rendered_json = format_json(report)
        rendered_text = format_text(report)

        self.assertEqual(report["overall_status"], "block")
        self.assertNotIn(marker, rendered_json)
        self.assertNotIn(marker, rendered_text)
        self.assertNotIn(raw_path, rendered_json)
        self.assertNotIn(raw_path, rendered_text)
        self.assertNotIn(unknown_rule_id, rendered_json)
        self.assertNotIn(unknown_rule_id, rendered_text)

    def test_validate_policy_report_matches_public_report_schema(self) -> None:
        report = validate_policy(self.tmp_path, config_path=POLICY_FIXTURES_PATH / "missing-required.yml")
        payload = json.loads(format_json(report))
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

        _assert_matches_schema(self, payload, schema)

    def test_validate_policy_golden_json_fixture_is_stable(self) -> None:
        report = validate_policy(VALID_POLICY_REPO_PATH)
        payload = json.loads(format_json(report))
        payload["repo_path"] = "<repo>"
        golden = json.loads(GOLDEN_POLICY_REPORT_PATH.read_text(encoding="utf-8"))

        self.assertEqual(payload, golden)

    def test_rules_document_lists_phase3b_rule_ids(self) -> None:
        rules_doc = (Path(__file__).resolve().parents[1] / "docs" / "rules.md").read_text(encoding="utf-8")

        for rule_id in (
            "rhd.repository.missing_readme",
            "rhd.repository.missing_license",
            "rhd.repository.missing_ci",
            "rhd.repository.missing_tests",
        ):
            self.assertIn(rule_id, rules_doc)

    def test_validate_policy_cli_outputs_json(self) -> None:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor",
                "validate-policy",
                str(self.tmp_path),
                "--format",
                "json",
                "--config",
                str(POLICY_FIXTURES_PATH / "valid-policy.yml"),
            ],
            check=True,
            capture_output=True,
            text=True,
            env=env,
        )

        payload = json.loads(result.stdout)
        self.assertEqual(payload["overall_status"], "pass")
        self.assertEqual([check["name"] for check in payload["checks"]], ["policy"])

    def test_scan_cli_fail_on_controls_warn_exit_code(self) -> None:
        (self.tmp_path / "README.md").write_text("# Demo\n", encoding="utf-8")
        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")

        block_result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor",
                str(self.tmp_path),
                "--fail-on",
                "block",
            ],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
        warn_result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor",
                str(self.tmp_path),
                "--fail-on",
                "warn",
            ],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )

        self.assertEqual(block_result.returncode, 0)
        self.assertEqual(warn_result.returncode, 1)

    def test_validate_policy_help_is_policy_focused(self) -> None:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor",
                "validate-policy",
                "--help",
            ],
            check=True,
            capture_output=True,
            text=True,
            env=env,
        )

        self.assertIn("validate-policy", result.stdout)
        self.assertIn("--no-local-config", result.stdout)
        self.assertNotIn("--public-safety", result.stdout)
        self.assertNotIn("--fail-on", result.stdout)

    def test_validate_policy_cli_blocks_invalid_policy_without_scanning(self) -> None:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor",
                "validate-policy",
                str(self.tmp_path),
                "--format",
                "json",
                "--config",
                str(POLICY_FIXTURES_PATH / "missing-required.yml"),
            ],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )

        payload = json.loads(result.stdout)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(payload["overall_status"], "block")
        self.assertEqual([check["name"] for check in payload["checks"]], ["policy"])

    def test_validate_policy_cli_no_local_config_skips_local_policy(self) -> None:
        local_policy = (POLICY_FIXTURES_PATH / "local-invalid.yml").read_text(encoding="utf-8")
        (self.tmp_path / ".repo-health-doctor.local.yml").write_text(local_policy, encoding="utf-8")
        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor",
                "validate-policy",
                str(self.tmp_path),
                "--format",
                "json",
                "--no-local-config",
            ],
            check=True,
            capture_output=True,
            text=True,
            env=env,
        )

        payload = json.loads(result.stdout)
        self.assertEqual(payload["overall_status"], "pass")
        self.assertEqual(payload["checks"][0]["details"]["policy_sources"], [])

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

    def test_package_module_version_runs(self) -> None:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor",
                "--version",
            ],
            check=True,
            capture_output=True,
            text=True,
            env=env,
        )

        self.assertEqual(result.stdout.strip(), f"repo-health-doctor {TOOL_VERSION}")


if __name__ == "__main__":
    unittest.main()
