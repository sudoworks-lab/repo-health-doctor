from __future__ import annotations

import json
from pathlib import Path
import shutil
import tempfile
import unittest

from repo_health_doctor.external_scanner import (
    DockerCommandResult,
    build_zizmor_docker_execution_plan,
    run_zizmor_in_docker,
)
from tests.external_scanner_fixture_helpers import (
    load_external_scanner_readiness_fixture,
    load_zizmor_docker_fixture,
)


ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "docker-integration-ci.md"
FORBIDDEN = (
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


def _approval() -> dict[str, object]:
    return load_external_scanner_readiness_fixture("valid_plan_with_synthetic_approval.json")["approval"]  # type: ignore[return-value]


def _target_repo() -> Path:
    root = Path(tempfile.mkdtemp(prefix="rhd-docker-always-on-"))
    workflows = root / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text("name: synthetic\n", encoding="utf-8")
    return root


def _fake_runner(fixture_name: str):
    def runner(argv, timeout_seconds, max_output_bytes):
        del timeout_seconds, max_output_bytes
        rendered = " ".join(argv)
        assert "--network none" in rendered
        assert "/var/run/docker.sock" not in rendered
        assert "<host-home>" not in rendered
        assert "<credentials>" not in rendered
        output = load_zizmor_docker_fixture(fixture_name)
        return DockerCommandResult(returncode=0, stdout=json.dumps(output), stderr="")

    return runner


class DockerIntegrationAlwaysOnTests(unittest.TestCase):
    def test_docker_plan_includes_required_boundaries(self) -> None:
        plan = build_zizmor_docker_execution_plan(".")
        argv = " ".join(plan.docker_argv)
        rendered = json.dumps(plan.to_dict(), sort_keys=True)

        self.assertIn("--network none", argv)
        self.assertNotIn("/var/run/docker.sock", argv)
        self.assertNotIn("<host-home>", argv)
        self.assertNotIn("<credentials>", argv)
        self.assertFalse(plan.raw_output_retention)
        self.assertTrue(plan.raw_output_discard_required)
        self.assertFalse(plan.execution_authorized)
        for pattern in FORBIDDEN:
            self.assertNotIn(pattern, rendered)

    def test_fake_scanner_result_is_normalized_without_raw_output_retention(self) -> None:
        target = _target_repo()
        try:
            result = run_zizmor_in_docker(
                target,
                approval=_approval(),
                runner=_fake_runner("synthetic_findings_output.json"),
            )
        finally:
            shutil.rmtree(target)

        self.assertTrue(result.valid, result.to_dict())
        self.assertTrue(result.docker_invoked)
        self.assertTrue(result.raw_output_discarded)
        self.assertFalse(result.readiness.network_allowed)
        self.assertFalse(result.readiness.raw_output_retention)
        self.assertFalse(result.imported_report_result.execution_authorized)  # type: ignore[union-attr]

    def test_cleanup_failure_is_not_pass(self) -> None:
        target = _target_repo()

        def cleanup_then_fail(path: Path) -> None:
            shutil.rmtree(path)
            raise OSError("synthetic cleanup failure")

        try:
            result = run_zizmor_in_docker(
                target,
                approval=_approval(),
                runner=_fake_runner("synthetic_no_findings_output.json"),
                cleanup=cleanup_then_fail,
            )
        finally:
            shutil.rmtree(target)

        self.assertFalse(result.valid)
        self.assertFalse(result.cleanup_succeeded)
        self.assertIn("disposable_workspace_cleanup_failed", result.blocking_errors)

    def test_docs_describe_ci_path(self) -> None:
        content = DOC.read_text(encoding="utf-8")

        self.assertIn("always-on path", content.lower())
        self.assertIn("does not require a local Docker daemon", content)


if __name__ == "__main__":
    unittest.main()
