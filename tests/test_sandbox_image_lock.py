from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from repo_health_doctor.sandbox.approval_draft import generate_unknown_repo_approval_draft
from repo_health_doctor.sandbox.behavior_policy import build_default_behavior_policy, evaluate_behavior_policy
from repo_health_doctor.sandbox.image_lock import (
    IMAGE_LOCK_SCHEMA_VERSION,
    REPORT_KIND_IMAGE_LOCK,
    REPORT_KIND_IMAGE_LOCK_VALIDATION,
    build_registry_image_lock,
    validate_sandbox_image_lock,
    validate_sandbox_image_lock_report,
)


FIXTURES_ROOT = Path(__file__).resolve().parent / "fixtures"
SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "sandbox-image-lock.schema.json"


class SandboxImageLockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lock = build_registry_image_lock()

    def _invalid(self, mutate: callable) -> None:
        lock = copy.deepcopy(self.lock)
        mutate(lock)
        report = validate_sandbox_image_lock_report(lock)
        self.assertEqual(report["verdict"], "block")
        self.assertFalse(report["valid"])

    def test_valid_registry_digest_pinned_lock(self) -> None:
        validate_sandbox_image_lock(self.lock)
        report = validate_sandbox_image_lock_report(self.lock)
        self.assertTrue(report["valid"])
        self.assertEqual(report["verdict"], "pass")
        self.assertEqual(report["schema_version"], IMAGE_LOCK_SCHEMA_VERSION)
        self.assertEqual(report["report_kind"], REPORT_KIND_IMAGE_LOCK_VALIDATION)
        self.assertTrue(report["image_summary"][0]["digest_pinned"])

    def test_schema_is_closed_and_matches_constants(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["schema_version"]["enum"], [IMAGE_LOCK_SCHEMA_VERSION])
        self.assertEqual(schema["properties"]["report_kind"]["enum"], [REPORT_KIND_IMAGE_LOCK])
        for field in schema["required"]:
            self.assertIn(field, self.lock)

    def test_tag_only_or_missing_digest_is_invalid(self) -> None:
        self._invalid(lambda lock: lock["images"][0].update({"registry_reference": "registry.example.invalid/rhd/python312:stable", "registry_digest": None}))
        self._invalid(lambda lock: lock["images"][0].update({"registry_digest": None}))

    def test_missing_or_unsupported_schema_version_is_invalid(self) -> None:
        self._invalid(lambda lock: lock.pop("schema_version"))
        self._invalid(lambda lock: lock.update({"schema_version": "99.0"}))

    def test_missing_required_or_unknown_safety_field_is_invalid(self) -> None:
        self._invalid(lambda lock: lock["images"][0].pop("purpose"))
        self._invalid(lambda lock: lock["images"][0].pop("supported_phases"))
        self._invalid(lambda lock: lock.update({"allow_network": True}))

    def test_local_image_requires_explicit_opt_in_full_id_and_limitations(self) -> None:
        local = copy.deepcopy(self.lock)
        image = local["images"][0]
        image.update(
            {
                "distribution": "local_dev_only",
                "registry_reference": "rhd-python312-strace:local",
                "registry_digest": None,
                "expected_image_id": "sha256:" + "b" * 64,
                "local_sanctioned_allowed": True,
                "local_sanctioned_limitations": ["dev_only_not_portable"],
            }
        )
        report = validate_sandbox_image_lock_report(local)
        self.assertTrue(report["valid"])
        self.assertIn("local_dev_only_image_portability_limited", report["warnings"])
        self._invalid(lambda lock: lock["images"][0].update({"distribution": "local_dev_only", "registry_reference": "rhd-python312-strace:local", "registry_digest": None, "expected_image_id": "sha256:" + "b" * 64, "local_sanctioned_allowed": False, "local_sanctioned_limitations": ["dev_only_not_portable"]}))
        self._invalid(lambda lock: lock["images"][0].update({"distribution": "local_dev_only", "registry_reference": "rhd-python312-strace:local", "registry_digest": None, "expected_image_id": "sha256:short", "local_sanctioned_allowed": True, "local_sanctioned_limitations": ["dev_only_not_portable"]}))

    def test_unsafe_runtime_flags_are_invalid(self) -> None:
        for field, value in (("pull_policy", "always"), ("network", "host"), ("shell", True), ("host_home", True), ("docker_socket", True)):
            with self.subTest(field=field):
                self._invalid(lambda lock, field=field, value=value: lock["required_runtime_flags"].update({field: value}))

    def test_lock_report_does_not_echo_raw_host_path_or_secret_like_value(self) -> None:
        raw_secret = "sk-" + "image_0123456789abcdef"
        raw_host_path = "/" + "home/private/image"
        for raw_value in (raw_secret, raw_host_path):
            with self.subTest(raw_value=raw_value):
                lock = copy.deepcopy(self.lock)
                lock["images"][0]["source_build_metadata"]["build_reference"] = raw_value
                payload = json.dumps(validate_sandbox_image_lock_report(lock))
                self.assertNotIn(raw_value, payload)
                self.assertEqual(validate_sandbox_image_lock_report(lock)["verdict"], "block")

    def test_approval_draft_and_behavior_policy_remain_static_and_non_executable(self) -> None:
        draft = generate_unknown_repo_approval_draft(
            FIXTURES_ROOT / "sandbox-unknown-profile-t1",
            phase="phase2_install_probe",
            kind="install_probe",
            cwd="/workspace",
            argv=("python", "-m", "build"),
        )
        self.assertFalse(draft["approved"])
        self.assertFalse(draft["execution_permitted"])
        policy = build_default_behavior_policy()
        clean_evidence = {
            "observer_available": True, "runtime_hook_available": True, "strace_log_present": True, "strace_parse_succeeded": True,
            "evidence_complete": True, "network_event_count": 0, "write_outside_allowed_prefix_count": 0, "docker_socket_access_count": 0,
            "host_home_access_count": 0, "denied_read_access_count": 0, "secret_event_count": 0, "execve_binaries": ["python"],
            "subprocess_binaries": [], "outside_writable_delete_count": 0, "timed_out": False, "return_code": 0,
        }
        self.assertEqual(evaluate_behavior_policy(policy, clean_evidence)["verdict"], "pass")
