from __future__ import annotations

import json
from pathlib import Path
import unittest

from repo_health_doctor.sandbox.approval_draft import generate_unknown_repo_approval_draft
from repo_health_doctor.sandbox.behavior_policy import (
    BEHAVIOR_POLICY_SCHEMA_VERSION,
    REPORT_KIND_BEHAVIOR_POLICY,
    REPORT_KIND_BEHAVIOR_VERDICT,
    build_default_behavior_policy,
    evaluate_behavior_policy,
    validate_behavior_policy,
)


FIXTURES_ROOT = Path(__file__).resolve().parent / "fixtures"
SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "sandbox-behavior-policy.schema.json"


class BehaviorPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = build_default_behavior_policy()

    def _evidence(self, **overrides: object) -> dict[str, object]:
        evidence: dict[str, object] = {
            "observer_available": True,
            "runtime_hook_available": True,
            "strace_log_present": True,
            "strace_parse_succeeded": True,
            "evidence_complete": True,
            "network_event_count": 0,
            "write_outside_allowed_prefix_count": 0,
            "docker_socket_access_count": 0,
            "host_home_access_count": 0,
            "denied_read_access_count": 0,
            "secret_event_count": 0,
            "execve_binaries": ["python"],
            "subprocess_binaries": [],
            "outside_writable_delete_count": 0,
            "timed_out": False,
            "return_code": 0,
        }
        evidence.update(overrides)
        return evidence

    def _verdict(self, **overrides: object) -> dict[str, object]:
        return evaluate_behavior_policy(self.policy, self._evidence(**overrides))

    def test_valid_minimal_policy_and_clean_controlled_evidence_pass(self) -> None:
        validate_behavior_policy(self.policy)
        verdict = self._verdict()
        self.assertEqual(verdict["verdict"], "pass")
        self.assertEqual(verdict["schema_version"], BEHAVIOR_POLICY_SCHEMA_VERSION)
        self.assertEqual(verdict["report_kind"], REPORT_KIND_BEHAVIOR_VERDICT)
        self.assertEqual(verdict["policy_version"], BEHAVIOR_POLICY_SCHEMA_VERSION)

    def test_policy_schema_is_closed_and_matches_constants(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["schema_version"]["enum"], [BEHAVIOR_POLICY_SCHEMA_VERSION])
        self.assertEqual(schema["properties"]["report_kind"]["enum"], [REPORT_KIND_BEHAVIOR_POLICY])
        for field in schema["required"]:
            self.assertIn(field, self.policy)

    def test_missing_or_unsupported_schema_version_fails_closed(self) -> None:
        missing = dict(self.policy)
        missing.pop("schema_version")
        self.assertEqual(evaluate_behavior_policy(missing, self._evidence())["verdict"], "block")
        unsupported = dict(self.policy)
        unsupported["schema_version"] = "999.0"
        self.assertEqual(evaluate_behavior_policy(unsupported, self._evidence())["verdict"], "block")

    def test_unknown_policy_or_evidence_field_fails_closed(self) -> None:
        unknown_policy = dict(self.policy)
        unknown_policy["network_exception"] = True
        self.assertEqual(evaluate_behavior_policy(unknown_policy, self._evidence())["verdict"], "block")
        evidence = self._evidence()
        evidence["raw_syscall_log"] = "not accepted"
        self.assertEqual(evaluate_behavior_policy(self.policy, evidence)["verdict"], "block")

    def test_security_events_block_by_default(self) -> None:
        cases = {
            "network_event_count": 1,
            "write_outside_allowed_prefix_count": 1,
            "docker_socket_access_count": 1,
            "host_home_access_count": 1,
            "denied_read_access_count": 1,
            "secret_event_count": 1,
            "outside_writable_delete_count": 1,
        }
        for field, value in cases.items():
            with self.subTest(field=field):
                self.assertEqual(self._verdict(**{field: value})["verdict"], "block")

    def test_unexpected_execve_and_subprocess_are_blocked_by_default(self) -> None:
        self.assertEqual(self._verdict(execve_binaries=["python", "curl"])["verdict"], "block")
        self.assertEqual(self._verdict(subprocess_binaries=["python"])["verdict"], "block")

    def test_limited_subprocess_policy_permits_only_exact_allowlist_and_limit(self) -> None:
        policy = build_default_behavior_policy(allow_subprocess="limited", limited_subprocess_binaries=("python",))
        evidence = self._evidence(subprocess_binaries=["python"])
        self.assertEqual(evaluate_behavior_policy(policy, evidence)["verdict"], "pass")
        self.assertEqual(evaluate_behavior_policy(policy, self._evidence(subprocess_binaries=["curl"]))["verdict"], "block")

    def test_missing_or_degraded_required_observers_never_pass(self) -> None:
        cases = (
            {"observer_available": False},
            {"runtime_hook_available": False},
            {"strace_log_present": False},
            {"strace_parse_succeeded": False},
            {"evidence_complete": False},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                self.assertEqual(self._verdict(**overrides)["verdict"], "block")

    def test_return_code_mismatch_and_timeout_block_by_default(self) -> None:
        self.assertEqual(self._verdict(return_code=2)["verdict"], "block")
        self.assertEqual(self._verdict(timed_out=True)["verdict"], "block")

    def test_verdict_does_not_render_raw_host_path_or_secret_like_value(self) -> None:
        evidence = self._evidence()
        raw_secret = "sk-" + "behavior_0123456789abcdef"
        evidence["execve_binaries"] = [raw_secret]
        payload = json.dumps(evaluate_behavior_policy(self.policy, evidence))
        self.assertNotIn(raw_secret, payload)
        self.assertEqual(evaluate_behavior_policy(self.policy, evidence)["verdict"], "block")

    def test_approval_draft_contract_remains_non_executable(self) -> None:
        draft = generate_unknown_repo_approval_draft(
            FIXTURES_ROOT / "sandbox-unknown-profile-t1",
            phase="phase2_install_probe",
            kind="install_probe",
            cwd="/workspace",
            argv=("python", "-m", "build"),
        )
        self.assertFalse(draft["approved"])
        self.assertFalse(draft["execution_permitted"])
        self.assertEqual(draft["behavior_policy"]["schema_version"], "unconfigured")
