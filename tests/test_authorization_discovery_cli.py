from __future__ import annotations

from copy import deepcopy
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from repo_health_doctor import cli
from repo_health_doctor.gate import build_execution_authorization_draft
from repo_health_doctor.gate.authorization_discovery import AUTHORIZATION_DISCOVERY_FILENAME
from repo_health_doctor.sandbox.run_workspace import create_verified_snapshot


ROOT = Path(__file__).resolve().parents[1]
GATE_FIXTURE = ROOT / "tests" / "fixtures" / "execution-authorization" / "gate-allow-limited.json"
ARGV = ["python3", "-m", "pytest", "tests"]


class AuthorizationDiscoveryCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.test_root = Path(self.temporary_directory.name)
        self.repo = self.test_root / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=self.repo, check=True, capture_output=True)
        (self.repo / "README.md").write_text("discovery\n", encoding="utf-8")
        nested = self.repo / "nested"
        nested.mkdir()
        (nested / "README.md").write_text("nested fixture\n", encoding="utf-8")
        subprocess.run(
            ["git", "add", "README.md", "nested/README.md"],
            cwd=self.repo,
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "git",
                "-c",
                "user.email=test@example.invalid",
                "-c",
                "user.name=test",
                "commit",
                "-qm",
                "initial",
            ],
            cwd=self.repo,
            check=True,
            capture_output=True,
        )
        self.gate_decision = json.loads(GATE_FIXTURE.read_text(encoding="utf-8"))
        workspace = create_verified_snapshot(self.repo)
        snapshot = workspace.verified_snapshot
        assert snapshot is not None
        self.gate_decision["subject"] = {
            "repo": snapshot.source_identity_redacted,
            "commit": snapshot.source_commit,
            "tree_hash": snapshot.source_tree,
            "snapshot_id": snapshot.snapshot_id,
            "manifest_fingerprint": snapshot.manifest_fingerprint,
            "binding_kind": "snapshot_bound",
        }
        workspace.cleanup()

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _authorization(self) -> dict[str, object]:
        authorization = dict(
            build_execution_authorization_draft(
                self.gate_decision,
                ARGV,
                expires_at="2099-01-01T00:00:00Z",
            )
        )
        authorization["approved"] = True
        authorization["approved_by"] = "redacted@example.invalid"
        authorization["approved_at"] = "2026-01-01T00:00:00Z"
        return authorization

    def _write_authorization(self, path: Path) -> None:
        path.write_text(json.dumps(self._authorization()) + "\n", encoding="utf-8")

    def _run_gate_check(self, *arguments: str) -> tuple[int, dict[str, object], str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(
            cli,
            "scan_verified_snapshot_report",
            return_value=object(),
        ), mock.patch.object(
            cli,
            "evaluate_gate_decision_from_scan_envelope",
            return_value=deepcopy(self.gate_decision),
        ), redirect_stdout(stdout), redirect_stderr(stderr):
            return_code = cli.main(["gate-check", str(self.repo), *arguments])
        return return_code, json.loads(stdout.getvalue()), stderr.getvalue()

    def test_argv_absence_does_not_trigger_discovery(self) -> None:
        self._write_authorization(self.repo / AUTHORIZATION_DISCOVERY_FILENAME)
        with mock.patch.object(cli, "discover_execution_authorization") as discover:
            return_code, report, _ = self._run_gate_check("--format", "json")

        self.assertEqual(return_code, 2)
        discover.assert_not_called()
        self.assertIn("authorization_missing", report["blocking_reasons"])

    def test_single_candidate_is_discovered_for_trailing_argv(self) -> None:
        self._write_authorization(self.repo / AUTHORIZATION_DISCOVERY_FILENAME)
        return_code, report, stderr = self._run_gate_check("--format", "json", "--", *ARGV)

        self.assertEqual(return_code, 0, stderr)
        self.assertEqual(report["status"], "authorized")
        self.assertTrue(report["execution_authorized"])

    def test_explicit_authorization_has_priority_over_discovery(self) -> None:
        candidate = self.repo / AUTHORIZATION_DISCOVERY_FILENAME
        candidate.write_text("{invalid json\n", encoding="utf-8")
        explicit = self.test_root / "explicit-authorization.json"
        self._write_authorization(explicit)

        with mock.patch.object(cli, "discover_execution_authorization") as discover:
            return_code, report, stderr = self._run_gate_check(
                "--authorization",
                str(explicit),
                "--format",
                "json",
                "--",
                *ARGV,
            )

        self.assertEqual(return_code, 0, stderr)
        discover.assert_not_called()
        self.assertEqual(report["status"], "authorized")

    def test_no_discover_keeps_trailing_argv_unauthorized_without_explicit_auth(self) -> None:
        self._write_authorization(self.repo / AUTHORIZATION_DISCOVERY_FILENAME)
        with mock.patch.object(cli, "discover_execution_authorization") as discover:
            return_code, report, _ = self._run_gate_check(
                "--no-discover",
                "--format",
                "json",
                "--",
                *ARGV,
            )

        self.assertEqual(return_code, 2)
        discover.assert_not_called()
        self.assertIn("authorization_missing", report["blocking_reasons"])

    def test_discovery_does_not_fallback_to_nested_candidates(self) -> None:
        nested = self.repo / "nested"
        self._write_authorization(nested / AUTHORIZATION_DISCOVERY_FILENAME)

        return_code, report, _ = self._run_gate_check("--format", "json", "--", *ARGV)

        self.assertEqual(return_code, 2)
        self.assertIn("authorization_missing", report["blocking_reasons"])


if __name__ == "__main__":
    unittest.main()
