from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import unittest

from repo_health_doctor.external_scanner import DockerCommandResult, run_zizmor_in_docker
from tests.external_scanner_fixture_helpers import (
    load_external_scanner_readiness_fixture,
    load_zizmor_docker_fixture,
)


LEAK_PATTERNS = (
    re.compile(r"/home/"),
    re.compile(r"/Users/"),
    re.compile(r"C:\\Users\\"),
    re.compile(r"\.ssh"),
    re.compile(r"\.aws"),
    re.compile(r"\.npmrc"),
    re.compile(r"\.pypirc"),
    re.compile(r"\.netrc"),
    re.compile(r"BEGIN OPENSSH PRIVATE KEY"),
    re.compile(r"BEGIN RSA PRIVATE KEY"),
    re.compile(r"AKIA[0-9A-Z]{4,}"),
    re.compile(r"ghp_[A-Za-z0-9_]{6,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{6,}"),
    re.compile(r"xoxb-[A-Za-z0-9-]{6,}"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{6,}\b"),
    re.compile(r"-----BEGIN"),
    re.compile(r"password="),
    re.compile(r"token="),
)


def _approval() -> dict[str, object]:
    return load_external_scanner_readiness_fixture("valid_plan_with_synthetic_approval.json")["approval"]  # type: ignore[return-value]


def _runner_for_fixture(fixture: str, returncode: int = 0):
    def runner(argv, timeout_seconds, max_output_bytes):
        del timeout_seconds, max_output_bytes
        rendered = " ".join(argv)
        assert "--network none" in rendered
        assert "/var/run/docker.sock" not in rendered
        assert "<host-home>" not in rendered
        output = load_zizmor_docker_fixture(fixture)
        if "synthetic_parse_failure_text" in output:
            return DockerCommandResult(returncode=returncode, stdout=str(output["synthetic_parse_failure_text"]), stderr="")
        return DockerCommandResult(returncode=returncode, stdout=json.dumps(output), stderr="")

    return runner


def _target_repo() -> Path:
    root = Path(tempfile.mkdtemp(prefix="rhd-zizmor-test-"))
    workflows = root / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text("name: synthetic\n", encoding="utf-8")
    return root


class ZizmorDockerExecutionTests(unittest.TestCase):
    def tearDown(self) -> None:
        pass

    def test_fake_runner_findings_output_connects_to_validator_mapper_and_imported_report(self) -> None:
        target = _target_repo()
        try:
            result = run_zizmor_in_docker(target, approval=_approval(), runner=_runner_for_fixture("synthetic_findings_output.json"))
        finally:
            shutil.rmtree(target)
        self.assertTrue(result.valid)
        self.assertTrue(result.scanner_executed)
        self.assertTrue(result.docker_invoked)
        self.assertTrue(result.raw_output_discarded)
        self.assertIsNotNone(result.validation_result)
        self.assertIsNotNone(result.risk_mapping_result)
        self.assertIsNotNone(result.imported_report_result)
        self.assertTrue(result.validation_result.valid)  # type: ignore[union-attr]
        self.assertIn("RISK011", [rule.rule_id for rule in result.risk_mapping_result.fired_rules])  # type: ignore[union-attr]
        self.assertFalse(result.imported_report_result.execution_authorized)  # type: ignore[union-attr]

    def test_fake_runner_no_findings_is_not_execution_authorization(self) -> None:
        target = _target_repo()
        try:
            result = run_zizmor_in_docker(target, approval=_approval(), runner=_runner_for_fixture("synthetic_no_findings_output.json"))
        finally:
            shutil.rmtree(target)
        self.assertTrue(result.valid)
        self.assertEqual(result.normalized_result["summary"]["outcome"], "no_findings_in_scope")  # type: ignore[index]
        self.assertFalse(result.normalized_result["execution_authorized"])  # type: ignore[index]
        self.assertTrue(result.risk_mapping_result.cannot_lower_risk)  # type: ignore[union-attr]

    def test_fake_runner_scanner_failure_is_not_pass(self) -> None:
        target = _target_repo()
        try:
            result = run_zizmor_in_docker(
                target,
                approval=_approval(),
                runner=_runner_for_fixture("synthetic_scanner_failure_output.json", returncode=2),
            )
        finally:
            shutil.rmtree(target)
        self.assertFalse(result.valid)
        self.assertIn("scanner_exit_nonzero_without_parseable_findings", result.blocking_errors)
        self.assertEqual(result.normalized_result["summary"]["outcome"], "unknown")  # type: ignore[index]

    def test_fake_runner_parse_failure_is_unknown_block(self) -> None:
        target = _target_repo()
        try:
            result = run_zizmor_in_docker(
                target,
                approval=_approval(),
                runner=_runner_for_fixture("synthetic_parse_failure_output.json"),
            )
        finally:
            shutil.rmtree(target)
        self.assertFalse(result.valid)
        self.assertIn("scanner_output_unknown", result.blocking_errors)
        self.assertEqual(result.normalized_result["summary"]["outcome"], "unknown")  # type: ignore[index]

    def test_cleanup_failure_is_not_pass(self) -> None:
        target = _target_repo()

        def cleanup_then_fail(path: Path) -> None:
            shutil.rmtree(path)
            raise OSError("synthetic cleanup failure")

        try:
            result = run_zizmor_in_docker(
                target,
                approval=_approval(),
                runner=_runner_for_fixture("synthetic_no_findings_output.json"),
                cleanup=cleanup_then_fail,
            )
        finally:
            shutil.rmtree(target)
        self.assertFalse(result.valid)
        self.assertFalse(result.cleanup_succeeded)
        self.assertIn("disposable_workspace_cleanup_failed", result.blocking_errors)

    def test_result_does_not_include_raw_output_or_obvious_leak_patterns(self) -> None:
        target = _target_repo()
        try:
            result = run_zizmor_in_docker(target, approval=_approval(), runner=_runner_for_fixture("synthetic_findings_output.json"))
        finally:
            shutil.rmtree(target)
        rendered = json.dumps(result.to_dict(), sort_keys=True)
        self.assertNotIn("synthetic_findings_output", rendered)
        self.assertNotIn("fixture_kind", rendered)
        self.assertNotIn("0.0.0-docker-fixture\", \"status\"", rendered)
        for pattern in LEAK_PATTERNS:
            self.assertIsNone(pattern.search(rendered), pattern.pattern)

    def test_missing_approval_does_not_invoke_docker(self) -> None:
        target = _target_repo()
        calls = []

        def runner(argv, timeout_seconds, max_output_bytes):
            calls.append(argv)
            return DockerCommandResult(returncode=0, stdout="{}", stderr="")

        try:
            result = run_zizmor_in_docker(target, approval={}, runner=runner)
        finally:
            shutil.rmtree(target)
        self.assertFalse(result.valid)
        self.assertFalse(result.scanner_executed)
        self.assertFalse(result.docker_invoked)
        self.assertEqual(calls, [])

    @unittest.skipUnless(os.environ.get("RHD_RUN_DOCKER_SCANNER_TESTS") == "1", "optional Docker scanner integration test")
    def test_optional_docker_integration_requires_explicit_environment(self) -> None:
        target = _target_repo()
        try:
            result = run_zizmor_in_docker(target, approval=_approval())
        finally:
            shutil.rmtree(target)
        self.assertTrue(result.readiness.ready)
        self.assertFalse(result.readiness.network_allowed)


if __name__ == "__main__":
    unittest.main()
