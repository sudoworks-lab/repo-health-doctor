from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import unittest

from repo_health_doctor.sandbox.behavior_policy import build_default_behavior_policy, evaluate_behavior_policy
from repo_health_doctor.sandbox.observer_evidence import (
    NORMALIZED_OBSERVER_EVIDENCE_SCHEMA_VERSION,
    REPORT_KIND_NORMALIZED_OBSERVER_EVIDENCE,
    REPORT_KIND_NORMALIZED_OBSERVER_EVIDENCE_VALIDATION,
    validate_normalized_observer_evidence,
    validate_normalized_observer_evidence_report,
)


SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "sandbox-normalized-observer-evidence.schema.json"


def _synthetic_host_path(*parts: str) -> str:
    return "".join(parts)


def clean_evidence() -> dict[str, object]:
    return {
        "schema_version": NORMALIZED_OBSERVER_EVIDENCE_SCHEMA_VERSION,
        "report_kind": REPORT_KIND_NORMALIZED_OBSERVER_EVIDENCE,
        "evidence_id": "clean-static-evidence",
        "source": {"observer_mode": "strace_runtime_hook", "strace_available": True, "strace_log_present": True, "strace_parse_success": True, "runtime_hook_available": True, "runtime_hook_active": True, "runtime_hook_parse_success": True, "observer_degraded": False, "degraded_reasons": []},
        "command": {"phase": "phase2_install_probe", "kind": "install_probe", "cwd": "/workspace", "argv_fingerprint": "sha256:" + hashlib.sha256(b'["python","-m","build"]').hexdigest(), "shell": False, "network_policy": "none"},
        "execution": {"return_code": 0, "timeout": False, "duration_ms": 1, "completed": True},
        "counts": {"process_event_count": 1, "unexpected_exec_count": 0, "subprocess_event_count": 0, "network_event_count": 0, "file_write_event_count": 0, "outside_allowed_write_count": 0, "denied_read_count": 0, "docker_socket_access_count": 0, "host_home_access_count": 0, "secret_event_count": 0, "outside_writable_delete_count": 0, "strace_parse_error_count": 0, "runtime_hook_parse_error_count": 0},
        "flags": {"evidence_complete": True, "raw_logs_included": False, "stdout_included": False, "stderr_included": False, "host_paths_redacted": True, "secrets_redacted": True},
        "summaries": {"process_summary": ["clean"], "file_summary": ["clean"], "network_summary": ["none"], "secret_summary": ["none"], "limitations": ["static_fixture"], "residual_risks": ["observed_scope_only"]},
        "redaction": {"status": "redacted", "raw_host_path_present": False, "raw_secret_like_value_present": False},
    }


class NormalizedObserverEvidenceTests(unittest.TestCase):
    def _invalid(self, mutate: object) -> None:
        evidence = copy.deepcopy(clean_evidence())
        assert callable(mutate)
        mutate(evidence)
        report = validate_normalized_observer_evidence_report(evidence)
        self.assertFalse(report["valid"])
        self.assertEqual(report["verdict"], "block")

    def test_valid_clean_evidence_is_valid_and_pass_eligible(self) -> None:
        evidence = clean_evidence()
        validate_normalized_observer_evidence(evidence)
        report = validate_normalized_observer_evidence_report(evidence)
        self.assertTrue(report["valid"])
        self.assertEqual(report["verdict"], "pass")
        self.assertTrue(report["pass_eligible"])
        self.assertEqual(report["report_kind"], REPORT_KIND_NORMALIZED_OBSERVER_EVIDENCE_VALIDATION)

    def test_schema_is_closed_and_matches_constants(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["schema_version"]["enum"], [NORMALIZED_OBSERVER_EVIDENCE_SCHEMA_VERSION])
        self.assertEqual(schema["properties"]["report_kind"]["enum"], [REPORT_KIND_NORMALIZED_OBSERVER_EVIDENCE])

    def test_schema_kind_required_and_unknown_fields_fail_closed(self) -> None:
        self._invalid(lambda item: item.pop("schema_version"))
        self._invalid(lambda item: item.update({"schema_version": "99.0"}))
        self._invalid(lambda item: item.update({"report_kind": "wrong_kind"}))
        self._invalid(lambda item: item.pop("counts"))
        self._invalid(lambda item: item.update({"new_safety_signal": True}))

    def test_raw_logs_stdout_stderr_paths_and_secrets_fail_closed(self) -> None:
        self._invalid(lambda item: item.update({"raw_syscall_log": "execve(...)"}))
        self._invalid(lambda item: item.update({"stdout": "raw output"}))
        self._invalid(lambda item: item.update({"stderr": "raw error"}))
        self._invalid(lambda item: item["summaries"].update({"file_summary": [_synthetic_host_path("/ho", "me", "/private/file")]}))
        self._invalid(lambda item: item["summaries"].update({"secret_summary": ["sk-observer_0123456789abcdef"]}))

    def test_shape_can_be_valid_but_not_pass_eligible(self) -> None:
        cases = {
            "observer unavailable": lambda item: item["source"].update({"strace_available": False}),
            "strace log missing": lambda item: item["source"].update({"strace_log_present": False}),
            "strace parse failure": lambda item: item["source"].update({"strace_parse_success": False}),
            "runtime hook unavailable": lambda item: item["source"].update({"runtime_hook_available": False}),
            "runtime hook inactive": lambda item: item["source"].update({"runtime_hook_active": False}),
            "runtime hook parse failure": lambda item: item["source"].update({"runtime_hook_parse_success": False}),
            "observer degraded": lambda item: item["source"].update({"observer_degraded": True, "degraded_reasons": ["observer_partial"]}),
            "incomplete evidence": lambda item: item["flags"].update({"evidence_complete": False}),
        }
        for label, mutate in cases.items():
            with self.subTest(label=label):
                evidence = clean_evidence()
                mutate(evidence)
                report = validate_normalized_observer_evidence_report(evidence)
                self.assertTrue(report["valid"])
                self.assertFalse(report["pass_eligible"])

    def test_behavior_policy_consumes_canonical_evidence_and_blocks_failures(self) -> None:
        policy = build_default_behavior_policy()
        self.assertEqual(evaluate_behavior_policy(policy, clean_evidence())["verdict"], "pass")
        for field in ("network_event_count", "secret_event_count", "docker_socket_access_count", "host_home_access_count", "outside_allowed_write_count", "denied_read_count", "outside_writable_delete_count"):
            with self.subTest(field=field):
                evidence = clean_evidence()
                evidence["counts"][field] = 1
                self.assertEqual(evaluate_behavior_policy(policy, evidence)["verdict"], "block")
        for mutate in (
            lambda item: item["source"].update({"observer_degraded": True, "degraded_reasons": ["observer_partial"]}),
            lambda item: item["source"].update({"strace_parse_success": False}),
            lambda item: item["flags"].update({"evidence_complete": False}),
        ):
            evidence = clean_evidence()
            mutate(evidence)
            self.assertEqual(evaluate_behavior_policy(policy, evidence)["verdict"], "block")

    def test_canonical_evidence_must_bind_to_the_reviewed_command(self) -> None:
        evidence = clean_evidence()
        evidence["command"]["kind"] = "different_probe"
        self.assertEqual(evaluate_behavior_policy(build_default_behavior_policy(), evidence)["verdict"], "block")
        malformed = {"report_kind": REPORT_KIND_NORMALIZED_OBSERVER_EVIDENCE}
        self.assertEqual(evaluate_behavior_policy(build_default_behavior_policy(), malformed)["verdict"], "block")
