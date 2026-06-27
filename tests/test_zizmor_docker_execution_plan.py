from __future__ import annotations

import json
import re
import unittest

from repo_health_doctor.external_scanner import (
    build_zizmor_docker_execution_plan,
    evaluate_scanner_execution_readiness,
)
from tests.external_scanner_fixture_helpers import load_external_scanner_readiness_fixture


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


class ZizmorDockerExecutionPlanTests(unittest.TestCase):
    def test_dry_run_plan_does_not_execute_scanner(self) -> None:
        plan = build_zizmor_docker_execution_plan(".")
        self.assertFalse(plan.scanner_executed)
        self.assertFalse(plan.execution_authorized)
        self.assertTrue(plan.scanner_execution_planned)
        self.assertTrue(plan.requires_human_approval)
        self.assertFalse(plan.raw_output_retention)

    def test_docker_argv_contains_required_isolation_flags(self) -> None:
        argv = list(build_zizmor_docker_execution_plan(".").docker_argv)
        self.assertIn("--network", argv)
        self.assertIn("none", argv)
        self.assertIn("--cap-drop", argv)
        self.assertIn("ALL", argv)
        self.assertIn("--security-opt", argv)
        self.assertIn("no-new-privileges", argv)
        self.assertIn("--read-only", argv)
        self.assertNotIn("/var/run/docker.sock", " ".join(argv))
        self.assertNotIn("<host-home>", " ".join(argv))
        self.assertNotIn("<credentials>", " ".join(argv))

    def test_plan_is_readiness_compatible_with_synthetic_approval(self) -> None:
        plan = build_zizmor_docker_execution_plan(".").to_dict()
        approval = load_external_scanner_readiness_fixture("valid_plan_with_synthetic_approval.json")["approval"]
        result = evaluate_scanner_execution_readiness(plan, approval=approval)  # type: ignore[arg-type]
        self.assertTrue(result.ready)
        self.assertFalse(result.execution_authorized)
        self.assertTrue(result.docker_allowed)
        self.assertFalse(result.network_allowed)
        self.assertFalse(result.target_code_execution_allowed)
        self.assertFalse(result.raw_output_retention)

    def test_plan_rendering_does_not_contain_obvious_leak_patterns(self) -> None:
        rendered = json.dumps(build_zizmor_docker_execution_plan(".").to_dict(), sort_keys=True)
        for pattern in LEAK_PATTERNS:
            self.assertIsNone(pattern.search(rendered), pattern.pattern)


if __name__ == "__main__":
    unittest.main()
