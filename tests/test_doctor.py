from __future__ import annotations

from datetime import date, timedelta
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest

from repo_health_doctor.doctor import (
    DOCUMENTED_RESERVED_RULE_IDS,
    REPORT_SCHEMA_VERSION,
    RULE_REGISTRY,
    RUNTIME_FINDING_SEVERITY_VALUES,
    RUNTIME_STATUS_VALUES,
    TOOL_VERSION,
    determine_exit_code,
    diagnose_repo,
    diff_reports,
    format_json,
    format_markdown,
    format_text,
    list_policy_allows,
    release_check,
    validate_policy,
)


SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "public-safety-report.schema.json"
DIFF_SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "report-diff.schema.json"
POLICY_SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "policy-config.schema.json"
RELEASE_CHECK_SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "release-check-report.schema.json"
FIXTURES_PATH = Path(__file__).resolve().parent / "fixtures"
POLICY_FIXTURES_PATH = FIXTURES_PATH / "policies"
VALID_POLICY_REPO_PATH = FIXTURES_PATH / "policy-valid-repo"
DEMO_FIXTURE_PATH = FIXTURES_PATH / "demo-repo"
MISSING_METADATA_FIXTURE_PATH = FIXTURES_PATH / "missing-metadata-repo"
SECRET_LIKE_FIXTURE_PATH = FIXTURES_PATH / "secret-like-repo"
PUBLIC_SAFETY_FIXTURE_PATH = FIXTURES_PATH / "public-safety-repo"
TRACKED_ARTIFACT_FIXTURE_PATH = FIXTURES_PATH / "tracked-artifact-repo"
GOLDEN_POLICY_REPORT_PATH = FIXTURES_PATH / "golden" / "valid-policy-report.json"
GOLDEN_DEMO_PUBLIC_JSON_PATH = FIXTURES_PATH / "golden" / "public-safety-demo.json"
GOLDEN_DEMO_POLICY_JSON_PATH = FIXTURES_PATH / "golden" / "policy-demo.json"
GOLDEN_DEMO_PUBLIC_TEXT_PATH = FIXTURES_PATH / "golden" / "public-safety-demo.txt"
GOLDEN_DEMO_PUBLIC_MARKDOWN_PATH = FIXTURES_PATH / "golden" / "public-safety-demo.md"
GOLDEN_DIFF_REPORT_PATH = FIXTURES_PATH / "golden" / "report-diff-demo.json"
GOLDEN_RELEASE_CHECK_REPORT_PATH = FIXTURES_PATH / "golden" / "release-check-demo.json"


def _assert_matches_schema(
    testcase: unittest.TestCase,
    value: object,
    schema: dict,
    path: str = "$",
    root_schema: dict | None = None,
) -> None:
    if root_schema is None:
        root_schema = schema
    if "$ref" in schema:
        ref = schema["$ref"]
        testcase.assertTrue(ref.startswith("#/"), f"{path} uses unsupported ref: {ref}")
        resolved_schema = root_schema
        for part in ref[2:].split("/"):
            resolved_schema = resolved_schema[part]
        schema = {**resolved_schema, **{key: value for key, value in schema.items() if key != "$ref"}}

    expected_type = schema.get("type")
    if expected_type == "object":
        testcase.assertIsInstance(value, dict, f"{path} should be an object")
        assert isinstance(value, dict)
        for key in schema.get("required", []):
            testcase.assertIn(key, value, f"{path} missing required key: {key}")
        properties = schema.get("properties", {})
        for key, child_schema in properties.items():
            if key in value:
                _assert_matches_schema(testcase, value[key], child_schema, f"{path}.{key}", root_schema)
        if schema.get("additionalProperties") is False:
            extra_keys = sorted(set(value) - set(properties))
            testcase.assertEqual(extra_keys, [], f"{path} has unexpected keys")
    elif expected_type == "array":
        testcase.assertIsInstance(value, list, f"{path} should be an array")
        assert isinstance(value, list)
        item_schema = schema.get("items")
        if item_schema:
            for index, item in enumerate(value):
                _assert_matches_schema(testcase, item, item_schema, f"{path}[{index}]", root_schema)
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


def _parse_documented_rules() -> dict[str, str]:
    rules_doc = (Path(__file__).resolve().parents[1] / "docs" / "rules.md").read_text(encoding="utf-8")
    matches = re.findall(r"^\|\s*`(rhd\.[^`]+)`\s*\|.*\|\s*`(warn|block)`\s*\|", rules_doc, flags=re.MULTILINE)
    return {rule_id: severity for rule_id, severity in matches}


def _extract_fenced_block(content: str, language: str, occurrence: int = 0) -> str:
    pattern = rf"```{re.escape(language)}\n(.*?)\n```"
    matches = re.findall(pattern, content, flags=re.DOTALL)
    return matches[occurrence]


def _iter_relative_markdown_links(content: str) -> list[str]:
    links: list[str] = []
    for raw_target in re.findall(r"\[[^\]]+\]\(([^)]+)\)", content):
        target = raw_target.strip()
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        if target.startswith("<") and target.endswith(">"):
            target = target[1:-1]
        target = target.split("#", 1)[0].strip()
        if not target:
            continue
        links.append(target)
    return links


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

    def _cli_env(self) -> dict[str, str]:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        return env

    def _make_report_check(
        self,
        *,
        name: str,
        status: str,
        findings: list[dict] | None = None,
        details: dict | None = None,
    ) -> dict:
        payload = {"findings": list(findings or [])}
        if details:
            payload.update(details)
        return {
            "name": name,
            "status": status,
            "summary": f"{name} status is {status}.",
            "details": payload,
        }

    def _make_report_payload(self, *, repo_path: str, checks: list[dict]) -> dict:
        summary = {
            "pass": sum(1 for check in checks if check["status"] == "pass"),
            "warn": sum(1 for check in checks if check["status"] == "warn"),
            "block": sum(1 for check in checks if check["status"] == "block"),
        }
        overall_status = "block" if summary["block"] else "warn" if summary["warn"] else "pass"
        return {
            "tool": "repo-health-doctor",
            "version": TOOL_VERSION,
            "schema_version": REPORT_SCHEMA_VERSION,
            "repo_path": repo_path,
            "overall_status": overall_status,
            "summary": summary,
            "checks": checks,
        }

    def _write_report_json(self, name: str, report: dict) -> Path:
        report_path = self.tmp_path / name
        report_path.write_text(format_json(report), encoding="utf-8")
        return report_path

    def _make_diff_fixture_report(self) -> dict:
        before_report = self._make_report_payload(
            repo_path="<before-repo>",
            checks=[
                self._make_report_check(
                    name="readme",
                    status="warn",
                    findings=[
                        {
                            "rule_id": "rhd.repository.missing_readme",
                            "severity": "warn",
                            "file": ".",
                            "pattern": "missing_readme",
                            "redacted": False,
                        }
                    ],
                ),
                self._make_report_check(
                    name="public_text_safety",
                    status="block",
                    findings=[
                        {
                            "rule_id": "rhd.public_text.private_path",
                            "severity": "block",
                            "file": "docs/public.md",
                            "pattern": "private_path",
                            "redacted": True,
                        }
                    ],
                ),
                self._make_report_check(
                    name="large_files",
                    status="warn",
                    findings=[
                        {
                            "rule_id": "rhd.repository.large_file",
                            "severity": "warn",
                            "file": "dist/bundle.bin",
                            "pattern": "large_file",
                            "redacted": False,
                        }
                    ],
                ),
                self._make_report_check(name="secrets_scan", status="pass"),
            ],
        )
        after_report = self._make_report_payload(
            repo_path="<after-repo>",
            checks=[
                self._make_report_check(
                    name="readme",
                    status="block",
                    findings=[
                        {
                            "rule_id": "rhd.repository.missing_readme",
                            "severity": "block",
                            "file": ".",
                            "pattern": "missing_readme",
                            "redacted": False,
                        }
                    ],
                ),
                self._make_report_check(
                    name="public_text_safety",
                    status="block",
                    findings=[
                        {
                            "rule_id": "rhd.public_text.private_path",
                            "severity": "block",
                            "file": "docs/public.md",
                            "pattern": "private_path",
                            "redacted": True,
                        }
                    ],
                ),
                self._make_report_check(name="large_files", status="pass"),
                self._make_report_check(
                    name="secrets_scan",
                    status="block",
                    findings=[
                        {
                            "rule_id": "rhd.secret.generic_api_key",
                            "severity": "block",
                            "file": "app.py",
                            "pattern": "generic_api_key",
                            "redacted": True,
                        }
                    ],
                ),
            ],
        )
        return diff_reports(
            self._write_report_json("before-golden.json", before_report),
            self._write_report_json("after-golden.json", after_report),
        )

    def _write_allow_inventory_policy(self, entries: list[dict[str, str]]) -> None:
        lines = ["allow_findings:"]
        for entry in entries:
            lines.extend(
                [
                    f"  - rule_id: {entry['rule_id']}",
                    f"    path: {entry['path']}",
                    f"    reason: {entry['reason']}",
                    f"    owner: {entry['owner']}",
                    f"    expires: {entry['expires']}",
                ]
            )
        (self.tmp_path / "repo-health-doctor.yml").write_text("\n".join(lines) + "\n", encoding="utf-8")

    def _materialize_fixture_repo(self, fixture_path: Path, target_name: str, git_init: bool = False) -> Path:
        repo_path = self.tmp_path / target_name
        shutil.copytree(fixture_path, repo_path)
        if git_init:
            subprocess.run(
                ["git", "-C", str(repo_path), "init"],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                ["git", "-C", str(repo_path), "add", "."],
                check=True,
                capture_output=True,
                text=True,
            )
        return repo_path

    def _materialize_demo_repo(self) -> Path:
        return self._materialize_fixture_repo(DEMO_FIXTURE_PATH, "demo-repo", git_init=True)

    def _normalized_demo_reports(self) -> tuple[dict, dict, str, str]:
        public_report = diagnose_repo(self._materialize_demo_repo(), public_safety=True)
        policy_report = validate_policy(self.tmp_path / "demo-repo")
        public_report["repo_path"] = "<demo-repo>"
        policy_report["repo_path"] = "<demo-repo>"
        return public_report, policy_report, format_text(public_report), format_markdown(public_report)

    def _normalized_demo_release_check_report(self) -> dict:
        report = release_check(self._materialize_demo_repo())
        report["repo_path"] = "<demo-repo>"
        return report

    def test_definition_of_done_docs_and_templates_exist(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]

        required_paths = (
            repo_root / "AGENTS.md",
            repo_root / "CONTRIBUTING.md",
            repo_root / "SECURITY.md",
            repo_root / "CODE_OF_CONDUCT.md",
            repo_root / ".github" / "ISSUE_TEMPLATE" / "bug_report.yml",
            repo_root / ".github" / "ISSUE_TEMPLATE" / "rule_request.yml",
            repo_root / ".github" / "ISSUE_TEMPLATE" / "false_positive.yml",
            repo_root / ".github" / "ISSUE_TEMPLATE" / "docs_improvement.yml",
            repo_root / ".github" / "pull_request_template.md",
            repo_root / "docs" / "requirements.md",
            repo_root / "docs" / "maintainer-guide.md",
            repo_root / "docs" / "agent-guide.md",
            repo_root / "docs" / "security-model.md",
            repo_root / "docs" / "evaluation-model.md",
            repo_root / "docs" / "ci-integration.md",
            repo_root / "docs" / "project-pitch.md",
            repo_root / "docs" / "roadmap.md",
        )

        for path in required_paths:
            self.assertTrue(path.is_file(), f"missing required file: {path}")

    def test_agents_file_stays_within_short_contract_limit(self) -> None:
        agents_path = Path(__file__).resolve().parents[1] / "AGENTS.md"
        content = agents_path.read_text(encoding="utf-8")

        self.assertLessEqual(len(content.splitlines()), 200)
        for required_text in (
            "Do not add network calls.",
            "Do not weaken redaction",
            "Do not change `schema_version`",
            "Update tests, fixtures, and docs together",
            "Re-check golden outputs",
            "publish",
        ):
            self.assertIn(required_text, content)

    def test_markdown_links_resolve_for_readme_and_docs(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        markdown_paths = [repo_root / "README.md", *sorted((repo_root / "docs").glob("*.md"))]

        for markdown_path in markdown_paths:
            content = markdown_path.read_text(encoding="utf-8")
            for target in _iter_relative_markdown_links(content):
                resolved = (markdown_path.parent / target).resolve()
                self.assertTrue(resolved.exists(), f"broken link in {markdown_path}: {target}")

    def test_ci_permissions_and_pyproject_metadata_match_requirements(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        workflow = (repo_root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        pyproject = (repo_root / "pyproject.toml").read_text(encoding="utf-8")

        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertIn('{name = "repo-health-doctor contributors"}', pyproject)
        for keyword in ("maintainer", "public-safety", "repository-health"):
            self.assertIn(f'"{keyword}"', pyproject)

    def test_minimum_fixture_set_is_present(self) -> None:
        for path in (
            DEMO_FIXTURE_PATH,
            MISSING_METADATA_FIXTURE_PATH,
            SECRET_LIKE_FIXTURE_PATH,
            PUBLIC_SAFETY_FIXTURE_PATH,
            TRACKED_ARTIFACT_FIXTURE_PATH,
            VALID_POLICY_REPO_PATH,
            POLICY_FIXTURES_PATH,
        ):
            self.assertTrue(path.exists(), f"missing fixture path: {path}")

    def test_missing_metadata_fixture_triggers_repository_warning(self) -> None:
        repo_path = self._materialize_fixture_repo(MISSING_METADATA_FIXTURE_PATH, "missing-metadata-repo")
        report = diagnose_repo(repo_path)
        checks = {check["name"]: check for check in report["checks"]}

        self.assertEqual(checks["readme"]["status"], "warn")
        self.assertEqual(checks["readme"]["details"]["findings"][0]["rule_id"], "rhd.repository.missing_readme")

    def test_secret_like_fixture_triggers_redacted_secret_block(self) -> None:
        repo_path = self._materialize_fixture_repo(SECRET_LIKE_FIXTURE_PATH, "secret-like-repo")
        report = diagnose_repo(repo_path)
        checks = {check["name"]: check for check in report["checks"]}
        rendered_json = format_json(report)

        self.assertEqual(checks["secrets_scan"]["status"], "block")
        self.assertEqual(checks["secrets_scan"]["details"]["findings"][0]["rule_id"], "rhd.secret.generic_api_key")
        self.assertNotIn("aaaaaaaaaaaaaaaaaaaaaaaa", rendered_json)

    def test_public_safety_fixture_triggers_expected_categories(self) -> None:
        repo_path = self._materialize_fixture_repo(PUBLIC_SAFETY_FIXTURE_PATH, "public-safety-repo", git_init=True)
        report = diagnose_repo(repo_path, public_safety=True)
        checks = {check["name"]: check for check in report["checks"]}
        patterns = {finding["pattern"] for finding in checks["public_text_safety"]["details"]["findings"]}

        self.assertEqual(checks["public_text_safety"]["status"], "block")
        self.assertTrue({"restricted_term", "private_path", "local_ip"}.issubset(patterns))

    def test_tracked_artifact_fixture_triggers_block(self) -> None:
        repo_path = self._materialize_fixture_repo(TRACKED_ARTIFACT_FIXTURE_PATH, "tracked-artifact-repo", git_init=True)
        report = diagnose_repo(repo_path, public_safety=True)
        checks = {check["name"]: check for check in report["checks"]}
        findings = checks["tracked_artifacts"]["details"]["findings"]

        self.assertEqual(report["overall_status"], "block")
        self.assertEqual(checks["tracked_artifacts"]["status"], "block")
        self.assertEqual(checks["tracked_artifacts"]["details"]["scan_scope"], "tracked")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "rhd.tracked_artifact.generated_dir")
        self.assertEqual(findings[0]["file"], "artifacts/build.log")
        self.assertEqual(findings[0]["pattern"], "generated_dir")
        self.assertTrue(findings[0]["redacted"])

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

    def test_cli_outputs_markdown(self) -> None:
        self._write_complete_repo_baseline()

        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor.cli",
                str(self.tmp_path),
                "--format",
                "markdown",
            ],
            check=True,
            capture_output=True,
            text=True,
            env=env,
        )

        self.assertIn("# Repo Health Doctor Report", result.stdout)
        self.assertIn("Overall Status: `PASS`", result.stdout)
        self.assertIn("| Status | Check | Summary |", result.stdout)

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

    def test_markdown_output_file_is_created(self) -> None:
        self._write_complete_repo_baseline()
        output_path = self.tmp_path / "report.md"

        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor.cli",
                str(self.tmp_path),
                "--format",
                "md",
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
        self.assertIn("# Repo Health Doctor Report", output_path.read_text(encoding="utf-8"))

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

    def test_markdown_output_includes_overall_status_and_redacts_raw_values(self) -> None:
        self._write_complete_repo_baseline()
        secret_value = "s" * 24
        private_path = "/" + "home" + "/example/private"
        local_ip = ".".join(("192", "168", "1", "25"))
        (self.tmp_path / "app.py").write_text('api_' + 'key = "' + secret_value + '"\n', encoding="utf-8")
        (self.tmp_path / "docs" / "public.md").write_text(
            f"path: {private_path}\nip: {local_ip}\n",
            encoding="utf-8",
        )
        self._init_git_repo()
        subprocess.run(
            ["git", "add", "README.md", "LICENSE", ".gitignore", ".github/workflows/ci.yml", "app.py", "docs/public.md"],
            cwd=self.tmp_path,
            check=True,
            capture_output=True,
            text=True,
        )

        report = diagnose_repo(self.tmp_path, public_safety=True)
        rendered_markdown = format_markdown(report)

        self.assertIn("Overall Status: `BLOCK`", rendered_markdown)
        self.assertIn("| Rule ID | Severity | File | Pattern | Redacted | Notes |", rendered_markdown)
        self.assertIn("`rhd.secret.generic_api_key`", rendered_markdown)
        self.assertIn("`rhd.public_text.private_path`", rendered_markdown)
        self.assertIn("`rhd.public_text.local_ip`", rendered_markdown)
        self.assertNotIn(secret_value, rendered_markdown)
        self.assertNotIn(private_path, rendered_markdown)
        self.assertNotIn(local_ip, rendered_markdown)

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

    def test_runtime_rule_registry_is_documented(self) -> None:
        documented_rules = _parse_documented_rules()
        undocumented_rules = sorted(set(RULE_REGISTRY) - set(documented_rules))

        self.assertEqual(undocumented_rules, [])

    def test_documented_rules_are_runtime_or_reserved(self) -> None:
        documented_rules = _parse_documented_rules()
        unknown_documented_rules = sorted(set(documented_rules) - set(RULE_REGISTRY) - set(DOCUMENTED_RESERVED_RULE_IDS))

        self.assertEqual(unknown_documented_rules, [])

    def test_documented_rule_severities_match_runtime_registry(self) -> None:
        documented_rules = _parse_documented_rules()

        for rule_id, severity in documented_rules.items():
            if rule_id in RULE_REGISTRY:
                self.assertEqual(RULE_REGISTRY[rule_id]["severity"], severity)

    def test_schema_contract_matches_runtime_constants(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        checks_schema = schema["properties"]["checks"]["items"]["properties"]
        finding_schema = checks_schema["details"]["properties"]["findings"]["items"]["properties"]

        self.assertEqual(schema["properties"]["schema_version"]["enum"], [REPORT_SCHEMA_VERSION])
        self.assertEqual(tuple(schema["properties"]["overall_status"]["enum"]), RUNTIME_STATUS_VALUES)
        self.assertEqual(tuple(checks_schema["status"]["enum"]), RUNTIME_STATUS_VALUES)
        self.assertEqual(tuple(finding_schema["severity"]["enum"]), RUNTIME_FINDING_SEVERITY_VALUES)

    def test_diff_report_schema_contract_matches_runtime_constants(self) -> None:
        schema = json.loads(DIFF_SCHEMA_PATH.read_text(encoding="utf-8"))
        finding_schema = schema["$defs"]["finding"]["properties"]
        severity_change_schema = schema["$defs"]["severity_change_finding"]["properties"]

        self.assertEqual(schema["properties"]["schema_version"]["enum"], [REPORT_SCHEMA_VERSION])
        self.assertEqual(schema["properties"]["report_kind"]["enum"], ["report_diff"])
        self.assertEqual(tuple(schema["$defs"]["runtime_status"]["enum"]), RUNTIME_STATUS_VALUES)
        self.assertEqual(tuple(finding_schema["severity"]["enum"]), RUNTIME_FINDING_SEVERITY_VALUES)
        self.assertEqual(tuple(severity_change_schema["before_severity"]["enum"]), RUNTIME_FINDING_SEVERITY_VALUES)
        self.assertEqual(tuple(severity_change_schema["after_severity"]["enum"]), RUNTIME_FINDING_SEVERITY_VALUES)

    def test_release_check_schema_contract_matches_runtime_constants(self) -> None:
        schema = json.loads(RELEASE_CHECK_SCHEMA_PATH.read_text(encoding="utf-8"))

        self.assertEqual(schema["properties"]["schema_version"]["enum"], [REPORT_SCHEMA_VERSION])
        self.assertEqual(schema["properties"]["report_kind"]["enum"], ["release_check"])
        self.assertEqual(tuple(schema["$defs"]["runtime_status"]["enum"]), RUNTIME_STATUS_VALUES)

    def test_runtime_and_policy_findings_follow_common_contract(self) -> None:
        policy_marker = "ignore_pathz"
        (self.tmp_path / "app.py").write_text('api_' + 'key = "' + ("a" * 24) + '"\n', encoding="utf-8")
        (self.tmp_path / "repo-health-doctor.yml").write_text(
            f"{policy_marker}:\n"
            "  - private-area/\n",
            encoding="utf-8",
        )

        report = diagnose_repo(self.tmp_path)
        findings = [
            finding
            for check in report["checks"]
            for finding in check["details"].get("findings", [])
        ]

        self.assertGreaterEqual(len(findings), 3)
        for finding in findings:
            self.assertEqual(
                {"rule_id", "severity", "file", "pattern", "redacted"} - set(finding),
                set(),
            )
            self.assertIn(finding["rule_id"], RULE_REGISTRY)
            self.assertIn(finding["severity"], RUNTIME_FINDING_SEVERITY_VALUES)
            self.assertFalse(Path(finding["file"]).is_absolute())
            self.assertIsInstance(finding["pattern"], str)
            self.assertIsInstance(finding["redacted"], bool)

    def test_policy_issue_findings_preserve_redaction_contract(self) -> None:
        raw_value = "private-policy-area/"
        (self.tmp_path / "repo-health-doctor.yml").write_text(
            "ignore_pathz:\n"
            f"  - {raw_value}\n",
            encoding="utf-8",
        )

        report = validate_policy(self.tmp_path)
        rendered_json = format_json(report)
        rendered_text = format_text(report)
        findings = report["checks"][0]["details"]["findings"]

        self.assertGreaterEqual(len(findings), 1)
        for finding in findings:
            self.assertEqual(
                {"rule_id", "severity", "file", "pattern", "redacted"} - set(finding),
                set(),
            )
            self.assertEqual(finding["file"], "<policy>")
            self.assertTrue(finding["redacted"])
            self.assertEqual(finding["severity"], "block")
        self.assertNotIn(raw_value, rendered_json)
        self.assertNotIn(raw_value, rendered_text)

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

    def test_list_policy_allows_reports_active_allow(self) -> None:
        report = list_policy_allows(self.tmp_path, config_path=POLICY_FIXTURES_PATH / "valid-policy.yml")
        checks = {check["name"]: check for check in report["checks"]}
        inventory = checks["policy_allow_inventory"]
        allow = inventory["details"]["allows"][0]

        self.assertEqual(report["overall_status"], "pass")
        self.assertEqual(inventory["status"], "pass")
        self.assertEqual(allow["policy_source"], "repo")
        self.assertEqual(allow["policy_id"], "repo:allow:1")
        self.assertEqual(allow["rule_id"], "rhd.repository.large_file")
        self.assertEqual(allow["path_scope"], "exact_path")
        self.assertEqual(allow["expires"], "2999-01-01")
        self.assertEqual(allow["status"], "active")
        self.assertTrue(allow["redacted"])

    def test_list_policy_allows_reports_expiring_soon_allow(self) -> None:
        soon_date = (date.today() + timedelta(days=15)).isoformat()
        (self.tmp_path / "repo-health-doctor.yml").write_text(
            "allow_findings:\n"
            "  - rule_id: rhd.repository.large_file\n"
            "    path: docs/*.bin\n"
            "    reason: reviewed category\n"
            "    owner: release-team\n"
            f"    expires: {soon_date}\n",
            encoding="utf-8",
        )

        report = list_policy_allows(self.tmp_path)
        checks = {check["name"]: check for check in report["checks"]}
        inventory = checks["policy_allow_inventory"]
        allow = inventory["details"]["allows"][0]

        self.assertEqual(report["overall_status"], "warn")
        self.assertEqual(inventory["status"], "warn")
        self.assertEqual(inventory["details"]["expiring_soon_count"], 1)
        self.assertEqual(allow["path_scope"], "wildcard_pattern")
        self.assertEqual(allow["status"], "expiring-soon")

    def test_list_policy_allows_reports_expired_allow_without_raw_path(self) -> None:
        expired_date = (date.today() - timedelta(days=1)).isoformat()
        raw_path = "private-allow-scope/generated.bin"
        (self.tmp_path / "repo-health-doctor.yml").write_text(
            "allow_findings:\n"
            "  - rule_id: rhd.repository.large_file\n"
            f"    path: {raw_path}\n"
            "    reason: reviewed category\n"
            "    owner: release-team\n"
            f"    expires: {expired_date}\n",
            encoding="utf-8",
        )

        report = list_policy_allows(self.tmp_path)
        rendered_json = format_json(report)
        rendered_text = format_text(report)
        rendered_markdown = format_markdown(report)
        checks = {check["name"]: check for check in report["checks"]}
        inventory = checks["policy_allow_inventory"]
        allow = inventory["details"]["allows"][0]

        self.assertEqual(report["overall_status"], "block")
        self.assertEqual(checks["policy"]["status"], "block")
        self.assertEqual(inventory["status"], "block")
        self.assertEqual(inventory["details"]["expired_count"], 1)
        self.assertEqual(allow["status"], "expired")
        self.assertEqual(allow["path_scope"], "exact_path")
        self.assertNotIn(raw_path, rendered_json)
        self.assertNotIn(raw_path, rendered_text)
        self.assertNotIn(raw_path, rendered_markdown)

    def test_list_policy_allows_filters_active_status(self) -> None:
        self._write_allow_inventory_policy(
            [
                {
                    "rule_id": "rhd.repository.large_file",
                    "path": "docs/active.bin",
                    "reason": "reviewed",
                    "owner": "team-a",
                    "expires": "2999-01-01",
                },
                {
                    "rule_id": "rhd.repository.large_file",
                    "path": "docs/soon.bin",
                    "reason": "reviewed",
                    "owner": "team-a",
                    "expires": (date.today() + timedelta(days=10)).isoformat(),
                },
                {
                    "rule_id": "rhd.repository.large_file",
                    "path": "docs/expired.bin",
                    "reason": "reviewed",
                    "owner": "team-a",
                    "expires": (date.today() - timedelta(days=1)).isoformat(),
                },
            ]
        )

        report = list_policy_allows(self.tmp_path, status_filter="active")
        inventory = {check["name"]: check for check in report["checks"]}["policy_allow_inventory"]["details"]

        self.assertEqual(inventory["filter"], "active")
        self.assertEqual(inventory["displayed_allow_count"], 1)
        self.assertEqual(inventory["active_count"], 1)
        self.assertEqual(inventory["expiring_soon_count"], 1)
        self.assertEqual(inventory["expired_count"], 1)
        self.assertEqual([allow["status"] for allow in inventory["allows"]], ["active"])

    def test_list_policy_allows_filters_expiring_soon_status(self) -> None:
        self._write_allow_inventory_policy(
            [
                {
                    "rule_id": "rhd.repository.large_file",
                    "path": "docs/active.bin",
                    "reason": "reviewed",
                    "owner": "team-a",
                    "expires": "2999-01-01",
                },
                {
                    "rule_id": "rhd.repository.large_file",
                    "path": "docs/soon.bin",
                    "reason": "reviewed",
                    "owner": "team-a",
                    "expires": (date.today() + timedelta(days=10)).isoformat(),
                },
                {
                    "rule_id": "rhd.repository.large_file",
                    "path": "docs/expired.bin",
                    "reason": "reviewed",
                    "owner": "team-a",
                    "expires": (date.today() - timedelta(days=1)).isoformat(),
                },
            ]
        )

        report = list_policy_allows(self.tmp_path, status_filter="expiring-soon")
        inventory = {check["name"]: check for check in report["checks"]}["policy_allow_inventory"]["details"]

        self.assertEqual(inventory["filter"], "expiring-soon")
        self.assertEqual(inventory["displayed_allow_count"], 1)
        self.assertEqual([allow["status"] for allow in inventory["allows"]], ["expiring-soon"])

    def test_list_policy_allows_filters_expired_status(self) -> None:
        self._write_allow_inventory_policy(
            [
                {
                    "rule_id": "rhd.repository.large_file",
                    "path": "docs/active.bin",
                    "reason": "reviewed",
                    "owner": "team-a",
                    "expires": "2999-01-01",
                },
                {
                    "rule_id": "rhd.repository.large_file",
                    "path": "docs/soon.bin",
                    "reason": "reviewed",
                    "owner": "team-a",
                    "expires": (date.today() + timedelta(days=10)).isoformat(),
                },
                {
                    "rule_id": "rhd.repository.large_file",
                    "path": "docs/expired.bin",
                    "reason": "reviewed",
                    "owner": "team-a",
                    "expires": (date.today() - timedelta(days=1)).isoformat(),
                },
            ]
        )

        report = list_policy_allows(self.tmp_path, status_filter="expired")
        inventory = {check["name"]: check for check in report["checks"]}["policy_allow_inventory"]["details"]

        self.assertEqual(inventory["filter"], "expired")
        self.assertEqual(inventory["displayed_allow_count"], 1)
        self.assertEqual([allow["status"] for allow in inventory["allows"]], ["expired"])

    def test_list_policy_allows_filtered_report_redacts_raw_policy_values(self) -> None:
        marker = "POLICY_MARKER_VALUE"
        raw_path = "private-policy-area/generated.bin"
        self._write_allow_inventory_policy(
            [
                {
                    "rule_id": "rhd.repository.large_file",
                    "path": raw_path,
                    "reason": marker,
                    "owner": marker,
                    "expires": "2999-01-01",
                }
            ]
        )

        report = list_policy_allows(self.tmp_path, status_filter="active", fail_on="expiring-soon")
        rendered_json = format_json(report)
        rendered_text = format_text(report)
        rendered_markdown = format_markdown(report)
        inventory = {check["name"]: check for check in report["checks"]}["policy_allow_inventory"]["details"]

        self.assertEqual(inventory["filter"], "active")
        self.assertEqual(inventory["fail_on"], "expiring-soon")
        self.assertNotIn(marker, rendered_json)
        self.assertNotIn(marker, rendered_text)
        self.assertNotIn(marker, rendered_markdown)
        self.assertNotIn(raw_path, rendered_json)
        self.assertNotIn(raw_path, rendered_text)
        self.assertNotIn(raw_path, rendered_markdown)

    def test_list_policy_allows_filter_without_matches_reports_empty_subset(self) -> None:
        self._write_allow_inventory_policy(
            [
                {
                    "rule_id": "rhd.repository.large_file",
                    "path": "docs/active.bin",
                    "reason": "reviewed",
                    "owner": "team-a",
                    "expires": "2999-01-01",
                }
            ]
        )

        report = list_policy_allows(self.tmp_path, status_filter="expiring-soon")
        inventory = {check["name"]: check for check in report["checks"]}["policy_allow_inventory"]

        self.assertEqual(inventory["status"], "pass")
        self.assertEqual(inventory["summary"], "No allow entries matched filter.")
        self.assertEqual(inventory["details"]["displayed_allow_count"], 0)
        self.assertEqual(inventory["details"]["allows"], [])

    def test_list_policy_allows_default_behavior_is_unfiltered(self) -> None:
        self._write_allow_inventory_policy(
            [
                {
                    "rule_id": "rhd.repository.large_file",
                    "path": "docs/active.bin",
                    "reason": "reviewed",
                    "owner": "team-a",
                    "expires": "2999-01-01",
                },
                {
                    "rule_id": "rhd.repository.large_file",
                    "path": "docs/soon.bin",
                    "reason": "reviewed",
                    "owner": "team-a",
                    "expires": (date.today() + timedelta(days=10)).isoformat(),
                },
            ]
        )

        report = list_policy_allows(self.tmp_path)
        inventory = {check["name"]: check for check in report["checks"]}["policy_allow_inventory"]["details"]

        self.assertNotIn("filter", inventory)
        self.assertNotIn("fail_on", inventory)
        self.assertEqual(inventory["displayed_allow_count"], 2)
        self.assertEqual(len(inventory["allows"]), 2)

    def test_list_policy_allows_report_matches_public_report_schema(self) -> None:
        report = list_policy_allows(self.tmp_path, config_path=POLICY_FIXTURES_PATH / "valid-policy.yml")
        payload = json.loads(format_json(report))
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

        _assert_matches_schema(self, payload, schema)

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

    def test_demo_fixture_supports_documented_commands(self) -> None:
        demo_repo = self._materialize_demo_repo()
        repo_root = Path(__file__).resolve().parents[1]
        env = os.environ.copy()
        env["PYTHONPATH"] = str(repo_root / "src")

        public_result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor",
                str(demo_repo),
                "--public-safety",
            ],
            check=True,
            capture_output=True,
            text=True,
            cwd=repo_root,
            env=env,
        )
        policy_result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor",
                "validate-policy",
                str(demo_repo),
            ],
            check=True,
            capture_output=True,
            text=True,
            cwd=repo_root,
            env=env,
        )
        public_json_path = self.tmp_path / "demo-public-safety.json"
        policy_json_path = self.tmp_path / "demo-policy.json"
        subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor",
                str(demo_repo),
                "--public-safety",
                "--format",
                "json",
                "--output",
                str(public_json_path),
            ],
            check=True,
            capture_output=True,
            text=True,
            cwd=repo_root,
            env=env,
        )
        subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor",
                "validate-policy",
                str(demo_repo),
                "--format",
                "json",
                "--output",
                str(policy_json_path),
            ],
            check=True,
            capture_output=True,
            text=True,
            cwd=repo_root,
            env=env,
        )

        self.assertIn("Repo Health Doctor: PASS", public_result.stdout)
        self.assertIn("Repo Health Doctor: PASS", policy_result.stdout)
        self.assertEqual(json.loads(public_json_path.read_text(encoding="utf-8"))["overall_status"], "pass")
        self.assertEqual(json.loads(policy_json_path.read_text(encoding="utf-8"))["overall_status"], "pass")

    def test_demo_public_safety_json_golden_fixture_is_stable(self) -> None:
        public_report, _, _, _ = self._normalized_demo_reports()
        golden = json.loads(GOLDEN_DEMO_PUBLIC_JSON_PATH.read_text(encoding="utf-8"))

        self.assertEqual(public_report, golden)

    def test_demo_policy_json_golden_fixture_is_stable(self) -> None:
        _, policy_report, _, _ = self._normalized_demo_reports()
        golden = json.loads(GOLDEN_DEMO_POLICY_JSON_PATH.read_text(encoding="utf-8"))

        self.assertEqual(policy_report, golden)

    def test_demo_public_safety_text_golden_fixture_is_stable(self) -> None:
        _, _, public_text, _ = self._normalized_demo_reports()
        golden = GOLDEN_DEMO_PUBLIC_TEXT_PATH.read_text(encoding="utf-8")

        self.assertEqual(public_text, golden)

    def test_demo_public_safety_markdown_golden_fixture_is_stable(self) -> None:
        _, _, _, public_markdown = self._normalized_demo_reports()
        golden = GOLDEN_DEMO_PUBLIC_MARKDOWN_PATH.read_text(encoding="utf-8")

        self.assertEqual(public_markdown, golden)

    def test_golden_demo_outputs_do_not_contain_absolute_paths(self) -> None:
        for path in (
            GOLDEN_DEMO_PUBLIC_JSON_PATH,
            GOLDEN_DEMO_POLICY_JSON_PATH,
            GOLDEN_DEMO_PUBLIC_TEXT_PATH,
            GOLDEN_DEMO_PUBLIC_MARKDOWN_PATH,
            GOLDEN_DIFF_REPORT_PATH,
        ):
            content = path.read_text(encoding="utf-8")
            self.assertNotIn(str(self.tmp_path), content)
            self.assertNotIn("/tmp/", content)
            self.assertNotIn("\\\\", content)

    def test_readme_sample_output_matches_demo_golden_fixtures(self) -> None:
        readme = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
        json_block = _extract_fenced_block(readme, "json", occurrence=0)
        text_block = _extract_fenced_block(readme, "text", occurrence=0)

        self.assertEqual(json_block + "\n", GOLDEN_DEMO_POLICY_JSON_PATH.read_text(encoding="utf-8"))
        self.assertEqual(text_block + "\n", GOLDEN_DEMO_PUBLIC_TEXT_PATH.read_text(encoding="utf-8"))

    def test_documented_command_references_cover_quickstart_demo_and_release(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        readme = (repo_root / "README.md").read_text(encoding="utf-8")
        demo_doc = (repo_root / "docs" / "demo.md").read_text(encoding="utf-8")
        ci_doc = (repo_root / "docs" / "ci-integration.md").read_text(encoding="utf-8")
        policy_doc = (repo_root / "docs" / "policy.md").read_text(encoding="utf-8")
        release_checklist = (repo_root / "docs" / "release-checklist.md").read_text(encoding="utf-8")

        for command in (
            "repo-health-doctor --version",
            "repo-health-doctor validate-policy .",
            "repo-health-doctor . --fail-on block --public-safety",
            "repo-health-doctor list-allows .",
            "repo-health-doctor list-allows . --fail-on expiring-soon",
            "repo-health-doctor diff-reports before.json after.json",
            "repo-health-doctor release-check .",
        ):
            self.assertIn(command, readme)
        for command in (
            "PYTHONPATH=src python3 -m repo_health_doctor /tmp/repo-health-doctor-demo --public-safety",
            "PYTHONPATH=src python3 -m repo_health_doctor validate-policy /tmp/repo-health-doctor-demo",
        ):
            self.assertIn(command, demo_doc)
        for command in (
            "repo-health-doctor --help",
            "repo-health-doctor --version",
            "PYTHONPATH=src python3 -m repo_health_doctor . --fail-on warn --public-safety",
            "PYTHONPATH=src python3 -m repo_health_doctor validate-policy .",
            "PYTHONPATH=src python3 -m repo_health_doctor release-check . --format markdown --output /tmp/release-check.md",
        ):
            self.assertIn(command, release_checklist)
        for command in (
            "repo-health-doctor . --strict --public-safety --format json --output /tmp/repo-health-doctor-result.json",
            "repo-health-doctor . --strict --public-safety --format markdown --output /tmp/repo-health-doctor-summary.md",
            "repo-health-doctor list-allows . --fail-on expiring-soon --format json --output /tmp/repo-health-doctor-allows.json",
            'cat /tmp/repo-health-doctor-summary.md >> "$GITHUB_STEP_SUMMARY"',
        ):
            self.assertIn(command, ci_doc)
        for command in (
            "repo-health-doctor validate-policy .",
            "repo-health-doctor list-allows .",
            "repo-health-doctor list-allows . --format json",
            "repo-health-doctor list-allows . --fail-on expiring-soon",
        ):
            self.assertIn(command, policy_doc)

    def test_readme_and_release_checklist_describe_offline_and_packaging_verify(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        readme = (repo_root / "README.md").read_text(encoding="utf-8")
        release_checklist = (repo_root / "docs" / "release-checklist.md").read_text(encoding="utf-8")

        self.assertIn("offline local verify", readme)
        self.assertIn("packaging verify", readme)
        self.assertIn("CI または build dependency 解決済み環境", readme)
        self.assertIn("## Offline Local Verify", release_checklist)
        self.assertIn("## Packaging Verify", release_checklist)

    def test_rules_document_has_no_duplicate_rule_ids(self) -> None:
        rules_doc = (Path(__file__).resolve().parents[1] / "docs" / "rules.md").read_text(encoding="utf-8")
        documented_rule_ids = re.findall(r"`(rhd\.[^`]+)`", rules_doc)

        self.assertEqual(len(documented_rule_ids), len(set(documented_rule_ids)))

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

    def test_list_allows_cli_outputs_json(self) -> None:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor",
                "list-allows",
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
        self.assertEqual([check["name"] for check in payload["checks"]], ["policy", "policy_allow_inventory"])

    def test_validate_policy_cli_outputs_markdown(self) -> None:
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
                "markdown",
                "--config",
                str(POLICY_FIXTURES_PATH / "valid-policy.yml"),
            ],
            check=True,
            capture_output=True,
            text=True,
            env=env,
        )

        self.assertIn("# Repo Health Doctor Report", result.stdout)
        self.assertIn("Overall Status: `PASS`", result.stdout)
        self.assertIn("### `policy`", result.stdout)

    def test_list_allows_cli_outputs_markdown(self) -> None:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor",
                "list-allows",
                str(self.tmp_path),
                "--format",
                "markdown",
                "--config",
                str(POLICY_FIXTURES_PATH / "valid-policy.yml"),
            ],
            check=True,
            capture_output=True,
            text=True,
            env=env,
        )

        self.assertIn("# Repo Health Doctor Report", result.stdout)
        self.assertIn("### `policy_allow_inventory`", result.stdout)
        self.assertIn("| Policy Source | Policy ID | Rule ID | Path Scope | Expires | Status | Redacted |", result.stdout)

    def test_diff_reports_detects_added_finding(self) -> None:
        before_report = self._make_report_payload(
            repo_path="<before-repo>",
            checks=[self._make_report_check(name="secrets_scan", status="pass")],
        )
        after_report = self._make_report_payload(
            repo_path="<after-repo>",
            checks=[
                self._make_report_check(
                    name="secrets_scan",
                    status="block",
                    findings=[
                        {
                            "rule_id": "rhd.secret.generic_api_key",
                            "severity": "block",
                            "file": "app.py",
                            "pattern": "generic_api_key",
                            "redacted": True,
                        }
                    ],
                )
            ],
        )

        report = diff_reports(
            self._write_report_json("before-added.json", before_report),
            self._write_report_json("after-added.json", after_report),
        )

        self.assertEqual(report["overall_status"]["before"], "pass")
        self.assertEqual(report["overall_status"]["after"], "block")
        self.assertEqual(report["summary"]["added_findings"], 1)
        self.assertEqual(report["summary"]["resolved_findings"], 0)
        self.assertEqual(report["findings"]["added"][0]["rule_id"], "rhd.secret.generic_api_key")

    def test_diff_reports_detects_resolved_finding(self) -> None:
        before_report = self._make_report_payload(
            repo_path="<before-repo>",
            checks=[
                self._make_report_check(
                    name="large_files",
                    status="warn",
                    findings=[
                        {
                            "rule_id": "rhd.repository.large_file",
                            "severity": "warn",
                            "file": "dist/bundle.bin",
                            "pattern": "large_file",
                            "redacted": False,
                        }
                    ],
                )
            ],
        )
        after_report = self._make_report_payload(
            repo_path="<after-repo>",
            checks=[self._make_report_check(name="large_files", status="pass")],
        )

        report = diff_reports(
            self._write_report_json("before-resolved.json", before_report),
            self._write_report_json("after-resolved.json", after_report),
        )

        self.assertEqual(report["summary"]["added_findings"], 0)
        self.assertEqual(report["summary"]["resolved_findings"], 1)
        self.assertEqual(report["findings"]["resolved"][0]["rule_id"], "rhd.repository.large_file")

    def test_diff_reports_tracks_unchanged_finding_count(self) -> None:
        finding = {
            "rule_id": "rhd.public_text.private_path",
            "severity": "block",
            "file": "docs/public.md",
            "pattern": "private_path",
            "redacted": True,
        }
        before_report = self._make_report_payload(
            repo_path="<before-repo>",
            checks=[self._make_report_check(name="public_text_safety", status="block", findings=[finding])],
        )
        after_report = self._make_report_payload(
            repo_path="<after-repo>",
            checks=[self._make_report_check(name="public_text_safety", status="block", findings=[finding])],
        )

        report = diff_reports(
            self._write_report_json("before-unchanged.json", before_report),
            self._write_report_json("after-unchanged.json", after_report),
        )

        self.assertEqual(report["summary"]["unchanged_findings"], 1)
        self.assertEqual(report["findings"]["unchanged_count"], 1)
        self.assertEqual(report["summary"]["added_findings"], 0)
        self.assertEqual(report["summary"]["resolved_findings"], 0)

    def test_diff_reports_detects_check_status_and_severity_changes(self) -> None:
        before_report = self._make_report_payload(
            repo_path="<before-repo>",
            checks=[
                self._make_report_check(
                    name="readme",
                    status="warn",
                    findings=[
                        {
                            "rule_id": "rhd.repository.missing_readme",
                            "severity": "warn",
                            "file": ".",
                            "pattern": "missing_readme",
                            "redacted": False,
                        }
                    ],
                )
            ],
        )
        after_report = self._make_report_payload(
            repo_path="<after-repo>",
            checks=[
                self._make_report_check(
                    name="readme",
                    status="block",
                    findings=[
                        {
                            "rule_id": "rhd.repository.missing_readme",
                            "severity": "block",
                            "file": ".",
                            "pattern": "missing_readme",
                            "redacted": False,
                        }
                    ],
                )
            ],
        )

        report = diff_reports(
            self._write_report_json("before-status.json", before_report),
            self._write_report_json("after-status.json", after_report),
        )

        self.assertTrue(report["overall_status"]["changed"])
        self.assertEqual(report["summary"]["status_changes"], 1)
        self.assertEqual(report["status_changes"][0]["check"], "readme")
        self.assertEqual(report["status_changes"][0]["before_status"], "warn")
        self.assertEqual(report["status_changes"][0]["after_status"], "block")
        self.assertEqual(report["summary"]["severity_changes"], 1)
        self.assertEqual(report["findings"]["severity_changes"][0]["before_severity"], "warn")
        self.assertEqual(report["findings"]["severity_changes"][0]["after_severity"], "block")

    def test_diff_reports_cli_outputs_markdown(self) -> None:
        before_report = self._make_report_payload(
            repo_path="<before-repo>",
            checks=[self._make_report_check(name="public_text_safety", status="pass")],
        )
        after_report = self._make_report_payload(
            repo_path="<after-repo>",
            checks=[
                self._make_report_check(
                    name="public_text_safety",
                    status="block",
                    findings=[
                        {
                            "rule_id": "rhd.public_text.local_ip",
                            "severity": "block",
                            "file": "docs/public.md",
                            "pattern": "local_ip",
                            "redacted": True,
                        }
                    ],
                )
            ],
        )
        before_path = self._write_report_json("before-markdown.json", before_report)
        after_path = self._write_report_json("after-markdown.json", after_report)

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor",
                "diff-reports",
                str(before_path),
                str(after_path),
                "--format",
                "markdown",
            ],
            check=True,
            capture_output=True,
            text=True,
            env=self._cli_env(),
        )

        self.assertIn("# Repo Health Doctor Report Diff", result.stdout)
        self.assertIn("## Added Findings", result.stdout)
        self.assertIn("| Rule ID | Severity | File | Pattern | Redacted | Notes |", result.stdout)
        self.assertIn("`rhd.public_text.local_ip`", result.stdout)

    def test_diff_reports_cli_outputs_parseable_json(self) -> None:
        before_report = self._make_report_payload(
            repo_path="<before-repo>",
            checks=[self._make_report_check(name="secrets_scan", status="pass")],
        )
        after_report = self._make_report_payload(
            repo_path="<after-repo>",
            checks=[self._make_report_check(name="secrets_scan", status="pass")],
        )
        before_path = self._write_report_json("before-json.json", before_report)
        after_path = self._write_report_json("after-json.json", after_report)

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor",
                "diff-reports",
                str(before_path),
                str(after_path),
                "--format",
                "json",
            ],
            check=True,
            capture_output=True,
            text=True,
            env=self._cli_env(),
        )

        payload = json.loads(result.stdout)
        self.assertEqual(payload["report_kind"], "report_diff")
        self.assertEqual(payload["summary"]["unchanged_findings"], 0)
        self.assertEqual(payload["status_changes"], [])

    def test_diff_report_matches_json_schema(self) -> None:
        payload = self._make_diff_fixture_report()
        schema = json.loads(DIFF_SCHEMA_PATH.read_text(encoding="utf-8"))

        _assert_matches_schema(self, payload, schema)

    def test_diff_report_golden_json_fixture_is_stable(self) -> None:
        payload = self._make_diff_fixture_report()
        golden = json.loads(GOLDEN_DIFF_REPORT_PATH.read_text(encoding="utf-8"))

        self.assertEqual(payload, golden)

    def test_diff_reports_output_does_not_leak_raw_values_or_report_paths(self) -> None:
        repo_path = self._materialize_demo_repo()
        secret_value = "s" * 24
        private_path = "/" + "home" + "/" + "example" + "/private"
        local_ip = ".".join(("192", "168", "1", "25"))

        before_report = diagnose_repo(repo_path, public_safety=True)
        (repo_path / "app.py").write_text('api_' + 'key = "' + secret_value + '"\n', encoding="utf-8")
        (repo_path / "docs" / "public.md").write_text(
            f"path: {private_path}\nip: {local_ip}\n",
            encoding="utf-8",
        )
        subprocess.run(
            ["git", "-C", str(repo_path), "add", "app.py", "docs/public.md"],
            check=True,
            capture_output=True,
            text=True,
        )
        after_report = diagnose_repo(repo_path, public_safety=True)

        before_path = self._write_report_json("before-redaction.json", before_report)
        after_path = self._write_report_json("after-redaction.json", after_report)

        json_result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor",
                "diff-reports",
                str(before_path),
                str(after_path),
                "--format",
                "json",
            ],
            check=True,
            capture_output=True,
            text=True,
            env=self._cli_env(),
        )
        text_result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor",
                "diff-reports",
                str(before_path),
                str(after_path),
            ],
            check=True,
            capture_output=True,
            text=True,
            env=self._cli_env(),
        )
        markdown_result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor",
                "diff-reports",
                str(before_path),
                str(after_path),
                "--format",
                "markdown",
            ],
            check=True,
            capture_output=True,
            text=True,
            env=self._cli_env(),
        )

        for content in (json_result.stdout, text_result.stdout, markdown_result.stdout):
            self.assertNotIn(secret_value, content)
            self.assertNotIn(private_path, content)
            self.assertNotIn(local_ip, content)
            self.assertNotIn(str(before_path), content)
            self.assertNotIn(str(after_path), content)

    def test_release_check_report_matches_json_schema(self) -> None:
        payload = release_check(self._materialize_demo_repo())
        schema = json.loads(RELEASE_CHECK_SCHEMA_PATH.read_text(encoding="utf-8"))

        _assert_matches_schema(self, payload, schema)

    def test_release_check_cli_json_output_matches_json_schema(self) -> None:
        demo_repo = self._materialize_demo_repo()
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor",
                "release-check",
                str(demo_repo),
                "--format",
                "json",
            ],
            check=True,
            capture_output=True,
            text=True,
            env=self._cli_env(),
        )

        payload = json.loads(result.stdout)
        schema = json.loads(RELEASE_CHECK_SCHEMA_PATH.read_text(encoding="utf-8"))

        _assert_matches_schema(self, payload, schema)

    def test_release_check_cli_outputs_text(self) -> None:
        demo_repo = self._materialize_demo_repo()
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor",
                "release-check",
                str(demo_repo),
            ],
            check=True,
            capture_output=True,
            text=True,
            env=self._cli_env(),
        )

        self.assertIn("Repo Health Doctor Release Check: PASS", result.stdout)
        self.assertIn("Recommended Next Action:", result.stdout)
        self.assertIn("comparison_available: false", result.stdout)

    def test_release_check_cli_outputs_json(self) -> None:
        demo_repo = self._materialize_demo_repo()
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor",
                "release-check",
                str(demo_repo),
                "--format",
                "json",
            ],
            check=True,
            capture_output=True,
            text=True,
            env=self._cli_env(),
        )

        payload = json.loads(result.stdout)
        self.assertEqual(payload["report_kind"], "release_check")
        self.assertEqual(payload["overall_status"], "pass")
        self.assertEqual(payload["release_readiness"]["status"], "pass")
        self.assertEqual(
            [check["name"] for check in payload["checks"]],
            ["repo_scan", "policy_validation", "allow_inventory", "report_diff"],
        )

    def test_release_check_cli_outputs_markdown(self) -> None:
        demo_repo = self._materialize_demo_repo()
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor",
                "release-check",
                str(demo_repo),
                "--format",
                "markdown",
            ],
            check=True,
            capture_output=True,
            text=True,
            env=self._cli_env(),
        )

        self.assertIn("# Repo Health Doctor Release Check", result.stdout)
        self.assertIn("Overall Release Readiness: `PASS`", result.stdout)
        self.assertIn("### `allow_inventory`", result.stdout)

    def test_release_check_markdown_smoke_writes_step_summary_sections(self) -> None:
        demo_repo = self._materialize_demo_repo()
        output_path = self.tmp_path / "release-check.md"
        subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor",
                "release-check",
                str(demo_repo),
                "--format",
                "markdown",
                "--output",
                str(output_path),
            ],
            check=True,
            capture_output=True,
            text=True,
            env=self._cli_env(),
        )

        rendered = output_path.read_text(encoding="utf-8")

        self.assertTrue(output_path.stat().st_size > 0)
        self.assertIn("# Repo Health Doctor Release Check", rendered)
        self.assertIn("## Summary Counts", rendered)
        self.assertIn("## Checks", rendered)
        self.assertIn("| `PASS` | `repo_scan` | Repository scan passed release checks. |", rendered)
        self.assertIn("### `report_diff`", rendered)
        self.assertIn("- Comparison Available: `false`", rendered)

    def test_release_check_policy_failure_sets_block_status(self) -> None:
        self._init_git_repo()
        self._write_complete_repo_baseline()
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor",
                "release-check",
                str(self.tmp_path),
                "--format",
                "json",
                "--config",
                str(POLICY_FIXTURES_PATH / "missing-required.yml"),
            ],
            check=False,
            capture_output=True,
            text=True,
            env=self._cli_env(),
        )

        payload = json.loads(result.stdout)
        checks = {check["name"]: check for check in payload["checks"]}
        self.assertEqual(result.returncode, 1)
        self.assertEqual(payload["overall_status"], "block")
        self.assertEqual(checks["policy_validation"]["status"], "block")
        self.assertGreater(checks["policy_validation"]["details"]["issue_count"], 0)

    def test_release_check_allow_inventory_summary_includes_status_counts(self) -> None:
        self._init_git_repo()
        self._write_complete_repo_baseline()
        self._write_allow_inventory_policy(
            [
                {
                    "rule_id": "rhd.repository.large_file",
                    "path": "docs/active.bin",
                    "reason": "reviewed",
                    "owner": "team-a",
                    "expires": "2999-01-01",
                },
                {
                    "rule_id": "rhd.repository.large_file",
                    "path": "docs/soon.bin",
                    "reason": "reviewed",
                    "owner": "team-a",
                    "expires": (date.today() + timedelta(days=10)).isoformat(),
                },
            ]
        )

        payload = release_check(self.tmp_path)
        inventory = {check["name"]: check for check in payload["checks"]}["allow_inventory"]["details"]

        self.assertEqual(payload["overall_status"], "warn")
        self.assertEqual(inventory["active_count"], 1)
        self.assertEqual(inventory["expiring_soon_count"], 1)
        self.assertEqual(inventory["expired_count"], 0)
        self.assertEqual(inventory["displayed_allow_count"], 2)

    def test_release_check_outputs_do_not_leak_raw_values(self) -> None:
        repo_path = self._materialize_demo_repo()
        secret_value = "s" * 24
        private_path = "/" + "home" + "/" + "example" + "/private"
        local_ip = ".".join(("192", "168", "1", "25"))
        raw_policy_path = "docs/raw-release-check.bin"
        raw_policy_owner = "owner@example.com"
        raw_policy_reason = "release ticket 123"

        (repo_path / "app.py").write_text('api_' + 'key = "' + secret_value + '"\n', encoding="utf-8")
        (repo_path / "docs" / "public.md").write_text(
            f"path: {private_path}\nip: {local_ip}\n",
            encoding="utf-8",
        )
        (repo_path / "repo-health-doctor.yml").write_text(
            "\n".join(
                [
                    "allow_findings:",
                    "  - rule_id: rhd.repository.large_file",
                    f"    path: {raw_policy_path}",
                    f"    reason: {raw_policy_reason}",
                    f"    owner: {raw_policy_owner}",
                    "    expires: 2999-01-01",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        subprocess.run(
            ["git", "-C", str(repo_path), "add", "app.py", "docs/public.md", "repo-health-doctor.yml"],
            check=True,
            capture_output=True,
            text=True,
        )

        report = release_check(repo_path)
        rendered_json = format_json(report)
        rendered_text = format_text(report)
        rendered_markdown = format_markdown(report)

        for content in (rendered_json, rendered_text, rendered_markdown):
            self.assertNotIn(secret_value, content)
            self.assertNotIn(private_path, content)
            self.assertNotIn(local_ip, content)
            self.assertNotIn(raw_policy_path, content)
            self.assertNotIn(raw_policy_owner, content)
            self.assertNotIn(raw_policy_reason, content)

    def test_release_check_with_baseline_outputs_do_not_leak_raw_values_or_report_paths(self) -> None:
        repo_path = self._materialize_demo_repo()
        baseline_report = diagnose_repo(repo_path, public_safety=True)
        baseline_path = self._write_report_json("baseline-release-check.json", baseline_report)
        secret_value = "s" * 24
        private_path = "/" + "home" + "/" + "example" + "/private"
        local_ip = ".".join(("192", "168", "1", "25"))
        raw_policy_path = "docs/raw-release-check.bin"
        raw_policy_owner = "owner@example.com"
        raw_policy_reason = "release ticket 123"

        (repo_path / "app.py").write_text('api_' + 'key = "' + secret_value + '"\n', encoding="utf-8")
        (repo_path / "docs" / "public.md").write_text(
            f"path: {private_path}\nip: {local_ip}\n",
            encoding="utf-8",
        )
        (repo_path / "repo-health-doctor.yml").write_text(
            "\n".join(
                [
                    "allow_findings:",
                    "  - rule_id: rhd.repository.large_file",
                    f"    path: {raw_policy_path}",
                    f"    reason: {raw_policy_reason}",
                    f"    owner: {raw_policy_owner}",
                    "    expires: 2999-01-01",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        subprocess.run(
            ["git", "-C", str(repo_path), "add", "app.py", "docs/public.md", "repo-health-doctor.yml"],
            check=True,
            capture_output=True,
            text=True,
        )

        outputs = []
        for extra_args in ([], ["--format", "json"], ["--format", "markdown"]):
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "repo_health_doctor",
                    "release-check",
                    str(repo_path),
                    "--baseline-report",
                    str(baseline_path),
                    *extra_args,
                ],
                check=False,
                capture_output=True,
                text=True,
                env=self._cli_env(),
            )
            self.assertNotEqual(result.stdout, "")
            outputs.append(result.stdout)

        for content in outputs:
            self.assertNotIn(secret_value, content)
            self.assertNotIn(private_path, content)
            self.assertNotIn(local_ip, content)
            self.assertNotIn(raw_policy_path, content)
            self.assertNotIn(raw_policy_owner, content)
            self.assertNotIn(raw_policy_reason, content)
            self.assertNotIn(str(baseline_path), content)

    def test_release_check_with_baseline_report_summarizes_diff(self) -> None:
        repo_path = self._materialize_demo_repo()
        baseline_report = diagnose_repo(repo_path, public_safety=True)
        baseline_path = self._write_report_json("baseline-scan.json", baseline_report)

        (repo_path / "docs" / "public.md").write_text(
            "ip: " + ".".join(("192", "168", "1", "25")) + "\n",
            encoding="utf-8",
        )
        subprocess.run(
            ["git", "-C", str(repo_path), "add", "docs/public.md"],
            check=True,
            capture_output=True,
            text=True,
        )

        payload = release_check(repo_path, baseline_report_path=baseline_path)
        diff_check = {check["name"]: check for check in payload["checks"]}["report_diff"]

        self.assertEqual(diff_check["status"], "warn")
        self.assertTrue(diff_check["details"]["comparison_available"])
        self.assertEqual(diff_check["details"]["added_findings"], 1)
        self.assertEqual(diff_check["details"]["resolved_findings"], 0)

    def test_release_check_golden_json_fixture_is_stable(self) -> None:
        payload = self._normalized_demo_release_check_report()
        golden = json.loads(GOLDEN_RELEASE_CHECK_REPORT_PATH.read_text(encoding="utf-8"))

        self.assertEqual(payload, golden)

    def test_list_allows_cli_filters_json_by_status(self) -> None:
        self._write_allow_inventory_policy(
            [
                {
                    "rule_id": "rhd.repository.large_file",
                    "path": "docs/active.bin",
                    "reason": "reviewed",
                    "owner": "team-a",
                    "expires": "2999-01-01",
                },
                {
                    "rule_id": "rhd.repository.large_file",
                    "path": "docs/soon.bin",
                    "reason": "reviewed",
                    "owner": "team-a",
                    "expires": (date.today() + timedelta(days=10)).isoformat(),
                },
            ]
        )
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor",
                "list-allows",
                str(self.tmp_path),
                "--format",
                "json",
                "--status",
                "expiring-soon",
                "--fail-on",
                "expiring-soon",
            ],
            check=False,
            capture_output=True,
            text=True,
            env=self._cli_env(),
        )

        payload = json.loads(result.stdout)
        inventory = {check["name"]: check for check in payload["checks"]}["policy_allow_inventory"]["details"]
        self.assertEqual(result.returncode, 1)
        self.assertEqual(inventory["filter"], "expiring-soon")
        self.assertEqual(inventory["fail_on"], "expiring-soon")
        self.assertEqual(inventory["displayed_allow_count"], 1)
        self.assertEqual([allow["status"] for allow in inventory["allows"]], ["expiring-soon"])

    def test_list_allows_cli_fail_on_expired(self) -> None:
        self._write_allow_inventory_policy(
            [
                {
                    "rule_id": "rhd.repository.large_file",
                    "path": "docs/expired.bin",
                    "reason": "reviewed",
                    "owner": "team-a",
                    "expires": (date.today() - timedelta(days=1)).isoformat(),
                }
            ]
        )
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor",
                "list-allows",
                str(self.tmp_path),
                "--fail-on",
                "expired",
            ],
            check=False,
            capture_output=True,
            text=True,
            env=self._cli_env(),
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("expired_count: 1", result.stdout)

    def test_list_allows_cli_fail_on_expiring_soon(self) -> None:
        self._write_allow_inventory_policy(
            [
                {
                    "rule_id": "rhd.repository.large_file",
                    "path": "docs/soon.bin",
                    "reason": "reviewed",
                    "owner": "team-a",
                    "expires": (date.today() + timedelta(days=10)).isoformat(),
                }
            ]
        )
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor",
                "list-allows",
                str(self.tmp_path),
                "--fail-on",
                "expiring-soon",
            ],
            check=False,
            capture_output=True,
            text=True,
            env=self._cli_env(),
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("expiring_soon_count: 1", result.stdout)

    def test_list_allows_cli_default_exit_code_does_not_fail_on_expiring_soon(self) -> None:
        self._write_allow_inventory_policy(
            [
                {
                    "rule_id": "rhd.repository.large_file",
                    "path": "docs/soon.bin",
                    "reason": "reviewed",
                    "owner": "team-a",
                    "expires": (date.today() + timedelta(days=10)).isoformat(),
                }
            ]
        )
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor",
                "list-allows",
                str(self.tmp_path),
            ],
            check=False,
            capture_output=True,
            text=True,
            env=self._cli_env(),
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("Repo Health Doctor: WARN", result.stdout)

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

    def test_list_allows_help_is_policy_focused(self) -> None:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor",
                "list-allows",
                "--help",
            ],
            check=True,
            capture_output=True,
            text=True,
            env=env,
        )

        self.assertIn("list-allows", result.stdout)
        self.assertIn("--no-local-config", result.stdout)
        self.assertIn("--status", result.stdout)
        self.assertIn("--fail-on", result.stdout)
        self.assertNotIn("--public-safety", result.stdout)

    def test_diff_reports_help_is_report_diff_focused(self) -> None:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor",
                "diff-reports",
                "--help",
            ],
            check=True,
            capture_output=True,
            text=True,
            env=env,
        )

        self.assertIn("diff-reports", result.stdout)
        self.assertIn("before_report", result.stdout)
        self.assertIn("after_report", result.stdout)
        self.assertNotIn("--public-safety", result.stdout)
        self.assertNotIn("--config", result.stdout)

    def test_release_check_help_is_release_focused(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor",
                "release-check",
                "--help",
            ],
            check=True,
            capture_output=True,
            text=True,
            env=self._cli_env(),
        )

        self.assertIn("release-check", result.stdout)
        self.assertIn("--baseline-report", result.stdout)
        self.assertIn("--fail-on", result.stdout)
        self.assertNotIn("--public-safety", result.stdout)

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
