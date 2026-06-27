from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from repo_health_doctor.cli import build_parser
from repo_health_doctor.sandbox.approval_draft import (
    APPROVAL_DRAFT_SCHEMA_VERSION,
    REPORT_KIND_APPROVAL_DRAFT,
    _candidate_key_material,
    generate_unknown_repo_approval_draft,
    validate_unknown_repo_approval_draft,
)
from repo_health_doctor.sandbox.report import format_unknown_repo_approval_draft_json
from repo_health_doctor.sandbox.unknown_profile import profile_unknown_repo


FIXTURES_ROOT = Path(__file__).resolve().parent / "fixtures"
SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "sandbox-approval-draft.schema.json"


class UnknownRepositoryApprovalDraftTests(unittest.TestCase):
    def _fixture(self, tier: str) -> Path:
        return FIXTURES_ROOT / f"sandbox-unknown-profile-{tier}"

    def _draft(self, tier: str, **overrides: object) -> dict[str, object]:
        values: dict[str, object] = {
            "phase": "phase2_install_probe",
            "kind": "install_probe",
            "cwd": "/workspace",
            "argv": ("python", "-m", "build"),
            "env_allowlist": ("PYTHONPATH",),
        }
        values.update(overrides)
        return generate_unknown_repo_approval_draft(self._fixture(tier), **values)  # type: ignore[arg-type]

    def _assert_non_executable_draft(self, report: dict[str, object]) -> None:
        self.assertEqual(report["schema_version"], APPROVAL_DRAFT_SCHEMA_VERSION)
        self.assertEqual(report["report_kind"], REPORT_KIND_APPROVAL_DRAFT)
        self.assertEqual(report["status"], "draft_requires_human_review")
        self.assertEqual(report["approval_status"], "draft_requires_human_review")
        self.assertFalse(report["approved"])
        self.assertFalse(report["execution_permitted"])

    def test_t1_t2_t3_generate_review_only_drafts(self) -> None:
        for tier in ("t1", "t2", "t3"):
            with self.subTest(tier=tier):
                report = self._draft(tier)
                self._assert_non_executable_draft(report)
                self.assertTrue(report["live_candidate_generated"])
                self.assertIsInstance(report["candidate"], dict)
                self.assertIsInstance(report["candidate_key"], str)
        self.assertIn(
            "phase1_fetch_and_phase1_5_rescan_required_before_any_promotion",
            self._draft("t2")["reasons"],
        )
        self.assertIn("needs_review_and_stronger_isolation_required", self._draft("t3")["reasons"])

    def test_t4_and_t5_never_generate_live_candidates(self) -> None:
        for tier in ("t4", "t5"):
            with self.subTest(tier=tier):
                report = self._draft(tier)
                self._assert_non_executable_draft(report)
                self.assertFalse(report["live_candidate_generated"])
                self.assertIsNone(report["candidate"])
                self.assertIsNone(report["candidate_key"])
                self.assertIn("dedicated_vm_or_specialist_review_required", report["blockers"])

    def test_t0_is_candidate_free_or_harmless_only(self) -> None:
        candidate_free = generate_unknown_repo_approval_draft(self._fixture("t0"))
        self.assertFalse(candidate_free["live_candidate_generated"])
        harmless = self._draft("t0", kind="harmless_static_probe")
        self.assertTrue(harmless["live_candidate_generated"])
        with self.assertRaisesRegex(ValueError, "harmless_"):
            self._draft("t0", kind="install_probe")

    def test_candidate_key_binds_every_security_decision_field(self) -> None:
        baseline = self._draft("t1")
        variants = (
            self._draft("t1", phase="phase3_runtime_probe"),
            self._draft("t1", kind="alternate_probe"),
            self._draft("t1", cwd="/workspace/subdir"),
            self._draft("t1", argv=("python", "-m", "pytest")),
            self._draft("t1", env_allowlist=("PATH", "PYTHONPATH")),
        )
        for report in variants:
            self.assertNotEqual(baseline["candidate_key"], report["candidate_key"])
        candidate = baseline["candidate"]
        self.assertIsInstance(candidate, dict)
        assert isinstance(candidate, dict)
        self.assertEqual(candidate["shell"], False)
        self.assertEqual(baseline["execution_constraints"]["network_policy"], "none")  # type: ignore[index]
        self.assertIn("image_policy", baseline["execution_constraints"])  # type: ignore[operator]
        self.assertIn("schema_version", baseline["behavior_policy"])  # type: ignore[operator]
        material = _candidate_key_material(
            repository_identity=baseline["repo_scope"]["repository_identity"],  # type: ignore[index]
            commit=baseline["repo_scope"]["commit"],  # type: ignore[index]
            source_risk_tier=baseline["source_risk_tier"],  # type: ignore[arg-type]
            candidate=candidate,
            network_policy="none",
            image_policy=baseline["execution_constraints"]["image_policy"],  # type: ignore[index]
            behavior_policy=baseline["behavior_policy"],  # type: ignore[arg-type]
        )
        self.assertEqual(
            set(material),
            {
                "repository_identity", "commit", "source_risk_tier", "phase", "kind", "cwd", "argv", "env_allowlist", "shell",
                "network_policy", "image_policy", "behavior_policy_schema_version", "behavior_policy_report_kind",
            },
        )

    def test_phase2_and_phase3_keys_are_distinct(self) -> None:
        phase2 = self._draft("t1", phase="phase2_install_probe")
        phase3 = self._draft("t1", phase="phase3_runtime_probe")
        self.assertNotEqual(phase2["candidate_key"], phase3["candidate_key"])
        self.assertIn("phase2_approval_cannot_authorize_phase3_and_vice_versa", phase2["promotion_requirements"])

    def test_shell_or_network_candidate_is_rejected_before_draft_generation(self) -> None:
        with self.assertRaisesRegex(ValueError, "shell candidates"):
            self._draft("t1", shell=True)
        with self.assertRaisesRegex(ValueError, "network-enabled"):
            self._draft("t1", network_policy="egress_allowed")
        with self.assertRaisesRegex(ValueError, "shell candidates"):
            self._draft("t4", shell=True)

    def test_report_redacts_host_path_and_secret_like_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            secret = "sk-" + "draft_0123456789abcdef"
            (root / "package.json").write_text(
                json.dumps({"name": "draft-redaction", "scripts": {secret: f"echo token={secret}"}}),
                encoding="utf-8",
            )
            report = generate_unknown_repo_approval_draft(
                root,
                phase="phase2_install_probe",
                kind="install_probe",
                cwd="/workspace",
                argv=("python", "-m", "build"),
            )
            payload = format_unknown_repo_approval_draft_json(report)

        self.assertNotIn(str(root), payload)
        self.assertNotIn(secret, payload)
        self.assertTrue(report["redaction"]["raw_host_paths_redacted"])  # type: ignore[index]
        self.assertTrue(report["redaction"]["secret_like_values_redacted"])  # type: ignore[index]

    def test_schema_contract_and_mismatch_fail_closed(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        report = self._draft("t1")
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["report_kind"]["enum"], [REPORT_KIND_APPROVAL_DRAFT])
        self.assertEqual(schema["properties"]["schema_version"]["enum"], [APPROVAL_DRAFT_SCHEMA_VERSION])
        for field in schema["required"]:
            self.assertIn(field, report)
        invalid = dict(report)
        invalid.pop("approved")
        with self.assertRaisesRegex(ValueError, "schema mismatch"):
            validate_unknown_repo_approval_draft(invalid)
        invalid_nested = dict(report)
        invalid_candidate = dict(report["candidate"])  # type: ignore[arg-type]
        invalid_candidate.pop("argv")
        invalid_nested["candidate"] = invalid_candidate
        with self.assertRaisesRegex(ValueError, "candidate schema mismatch"):
            validate_unknown_repo_approval_draft(invalid_nested)
        invalid_profile = profile_unknown_repo(self._fixture("t1"))
        invalid_profile["schema_version"] = "unsupported"
        with self.assertRaisesRegex(ValueError, "schema_version"):
            generate_unknown_repo_approval_draft(self._fixture("t1"), source_profile=invalid_profile)

    def test_no_draft_contains_approved_true(self) -> None:
        report = self._draft("t1")
        payload = format_unknown_repo_approval_draft_json(report)
        self.assertNotIn('"approved": true', payload)
        self.assertNotIn('"execution_permitted": true', payload)

    def test_cli_parser_has_only_review_draft_inputs(self) -> None:
        parser = build_parser("sandbox-approval-draft")
        args = parser.parse_args(
            [".", "--phase", "phase2_install_probe", "--kind", "install_probe", "--cwd", "/workspace", "--argv", "python", "-m", "build"]
        )
        self.assertEqual(args.phase, "phase2_install_probe")
        self.assertFalse(args.shell)
        self.assertEqual(args.network_policy, "none")
        self.assertFalse(hasattr(args, "run_phase1"))
        self.assertFalse(hasattr(args, "approval_file"))
