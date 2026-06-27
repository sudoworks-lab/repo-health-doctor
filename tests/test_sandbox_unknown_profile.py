from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from repo_health_doctor.cli import build_parser
from repo_health_doctor.sandbox import REPORT_KIND_UNKNOWN_REPO_PROFILE, profile_unknown_repo
from repo_health_doctor.sandbox.report import format_unknown_repo_profile_json
from repo_health_doctor.sandbox.unknown_profile import UNKNOWN_PROFILE_SCHEMA_VERSION


FIXTURES_ROOT = Path(__file__).resolve().parent / "fixtures"
PROFILE_SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "sandbox-unknown-repo-profile.schema.json"


class UnknownRepositoryProfileTests(unittest.TestCase):
    def _fixture(self, tier: str) -> Path:
        return FIXTURES_ROOT / f"sandbox-unknown-profile-{tier}"

    def _assert_read_only_contract(self, report: dict[str, object]) -> None:
        self.assertEqual(report["schema_version"], UNKNOWN_PROFILE_SCHEMA_VERSION)
        self.assertEqual(report["report_kind"], REPORT_KIND_UNKNOWN_REPO_PROFILE)
        self.assertEqual(report["mode"], "plan_only")
        self.assertFalse(report["execution_permitted"])
        self.assertEqual(report["approval_status"], "not_generated")
        execution = report["execution"]
        self.assertIsInstance(execution, dict)
        assert isinstance(execution, dict)
        self.assertFalse(any(execution.values()))
        approval = report["approval"]
        self.assertIsInstance(approval, dict)
        assert isinstance(approval, dict)
        self.assertFalse(approval["draft_generated"])
        self.assertFalse(approval["approved"])
        self.assertEqual(approval["candidate_count"], 0)

    def test_tier_fixtures_follow_documented_t0_to_t5_boundaries(self) -> None:
        expected = {
            "t0": "T0",
            "t1": "T1",
            "t2": "T2",
            "t3": "T3",
            "t4": "T4",
            "t5": "T5",
        }
        for fixture, tier in expected.items():
            with self.subTest(fixture=fixture):
                report = profile_unknown_repo(self._fixture(fixture))
                self._assert_read_only_contract(report)
                self.assertEqual(report["risk"]["tier"], tier)
                if tier in {"T4", "T5"}:
                    self.assertEqual(report["overall_status"], "block")
                    self.assertEqual(report["risk"]["live_eligibility"], "not_a_candidate")
                else:
                    self.assertEqual(report["overall_status"], "warn")

    def test_profile_collects_dependency_build_and_static_indicator_categories(self) -> None:
        tier2 = profile_unknown_repo(self._fixture("t2"))
        self.assertEqual(tier2["profile"]["dependency_sources"]["regular_count"], 1)

        tier3 = profile_unknown_repo(self._fixture("t3"))
        self.assertEqual(tier3["profile"]["python_build"]["backend_status"], "declared")
        self.assertEqual(len(tier3["profile"]["lifecycle_scripts"]), 1)
        self.assertGreater(tier3["profile"]["shell_command_references"]["count"], 0)

        tier4 = profile_unknown_repo(self._fixture("t4"))
        dependencies = tier4["profile"]["dependency_sources"]
        self.assertGreater(dependencies["direct_url_count"], 0)
        self.assertGreater(dependencies["vcs_count"], 0)
        self.assertGreater(dependencies["editable_count"], 0)
        self.assertGreater(tier4["profile"]["native_binaries"]["count"], 0)
        self.assertGreater(tier4["profile"]["credential_path_references"]["count"], 0)
        self.assertGreater(tier4["profile"]["network_related_references"]["count"], 0)
        self.assertGreater(tier4["profile"]["obfuscation_indicators"]["count"], 0)

    def test_ambiguous_manifest_is_needs_review_not_a_lower_tier(self) -> None:
        report = profile_unknown_repo(self._fixture("ambiguous"))
        self._assert_read_only_contract(report)
        self.assertEqual(report["risk"]["tier"], "T3")
        self.assertEqual(report["risk"]["disposition"], "needs_review")
        self.assertGreater(report["profile"]["analysis"]["ambiguous_field_count"], 0)

    def test_parse_error_manifest_is_needs_review_not_a_lower_tier(self) -> None:
        report = profile_unknown_repo(self._fixture("parse-error"))

        self._assert_read_only_contract(report)
        self.assertEqual(report["risk"]["tier"], "T3")
        self.assertEqual(report["risk"]["disposition"], "needs_review")
        self.assertGreater(report["profile"]["analysis"]["parse_error_count"], 0)

    def test_symlink_risk_is_reported_without_following_the_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            outside = Path(temporary) / "outside"
            root.mkdir()
            outside.mkdir()
            (root / "escape").symlink_to(outside, target_is_directory=True)

            report = profile_unknown_repo(root)

        self.assertEqual(report["risk"]["tier"], "T3")
        self.assertEqual(report["profile"]["symlink_risks"]["outside_repo_count"], 1)

    def test_report_redacts_host_paths_and_untrusted_secret_like_script_text(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            token = "sk-" + "profile_0123456789abcdef"
            (root / "package.json").write_text(
                json.dumps(
                    {
                        "name": "redaction-profile",
                        "scripts": {token: f"echo token={token}"},
                    }
                ),
                encoding="utf-8",
            )
            report = profile_unknown_repo(root)
            payload = format_unknown_repo_profile_json(report)

        self.assertNotIn(str(root), payload)
        self.assertNotIn(token, payload)
        self.assertIn("sha256:", payload)
        self.assertTrue(report["redaction"]["raw_host_paths_redacted"])
        self.assertTrue(report["redaction"]["secret_like_values_redacted"])

    def test_profile_schema_is_closed_and_matches_required_report_structure(self) -> None:
        schema = json.loads(PROFILE_SCHEMA_PATH.read_text(encoding="utf-8"))
        report = json.loads(format_unknown_repo_profile_json(profile_unknown_repo(self._fixture("t1"))))

        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["schema_version"]["enum"], [UNKNOWN_PROFILE_SCHEMA_VERSION])
        for field in schema["required"]:
            self.assertIn(field, report)
        for field in schema["$defs"]["profile"]["required"]:
            self.assertIn(field, report["profile"])

    def test_profile_never_runs_subprocess_or_generates_docker_activity(self) -> None:
        with mock.patch("subprocess.run") as run:
            report = profile_unknown_repo(self._fixture("t4"))

        run.assert_not_called()
        self.assertFalse(report["execution"]["docker_used"])
        self.assertFalse(report["execution"]["image_pull_performed"])

    def test_sandbox_profile_cli_outputs_read_only_json(self) -> None:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor",
                "sandbox-profile",
                str(self._fixture("t1")),
                "--format",
                "json",
            ],
            check=True,
            capture_output=True,
            text=True,
            env=env,
        )

        report = json.loads(result.stdout)
        self._assert_read_only_contract(report)
        self.assertEqual(report["risk"]["tier"], "T1")

    def test_sandbox_profile_parser_has_no_execution_options(self) -> None:
        parser = build_parser("sandbox-profile")
        args = parser.parse_args([".", "--format", "json"])

        self.assertEqual(args.path, ".")
        self.assertEqual(args.format, "json")
        self.assertFalse(hasattr(args, "run_phase1"))
        self.assertFalse(hasattr(args, "run_phase2"))
        self.assertFalse(hasattr(args, "run_phase3"))
