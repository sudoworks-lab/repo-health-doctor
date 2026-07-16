from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import unittest

from repo_health_doctor.evidence.sandbox_run import normalize_sandbox_run_evidence


ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "tests" / "fixtures" / "golden" / "sandbox-run-evidence.json"


def _source_report() -> dict[str, object]:
    raw_path = "/" + "home/alice/private-repo"
    return {
        "schema_version": "0.1-draft",
        "report_kind": "sandbox_run",
        "run": {
            "run_id": "rhd-sandbox-run-fixed",
            "started_at": "2026-07-16T00:00:00Z",
            "ended_at": "2026-07-16T00:00:01Z",
            "dry_run": False,
        },
        "target": {
            "identity": "path:repo",
            "path_redacted": raw_path,
            "fingerprint": "sha256:" + "1" * 64,
        },
        "gate": {
            "evaluated": True,
            "policy_version": "0.1",
            "decision_fingerprint": "sha256:" + "2" * 64,
            "policy_blocked": False,
        },
        "authorization": {
            "execution_authorized": False,
            "worktree_binding": {
                "checked": True,
                "status": "matched",
                "matched": True,
                "refusal_reasons": [],
            },
        },
        "sandbox_profile": {"name": "no-network-default"},
        "seccomp": {"profile": "runtime-default"},
        "docker": {
            "image": "python:3.12-slim",
            "runner": "docker",
            "docker_invoked": True,
            "stdout_preview_redacted": "raw-preview-value",
            "stderr_preview_redacted": "raw-stderr-value",
        },
        "disposable_workspace": {"cleanup": "ok"},
        "workspace_diff": {
            "created_count": 1,
            "modified_count": 2,
            "deleted_count": 0,
            "interesting_paths_redacted": [raw_path],
        },
        "result": {
            "status": "completed",
            "exit_code": 0,
            "timed_out": False,
        },
        "policy_blocked": False,
        "command_started": True,
        "command_exit_code": 0,
        "output_summary": {
            "stdout_preview_redacted": "raw-output-summary",
            "stderr_preview_redacted": "raw-output-summary-error",
            "raw_stdout_stderr_persisted": False,
        },
        "limitations": ["source limitation text"],
    }


class SandboxEvidenceNormalizerTests(unittest.TestCase):
    def test_success_matches_golden_and_keeps_success_note_informational_only(self) -> None:
        normalized = normalize_sandbox_run_evidence(_source_report())
        expected = json.loads(GOLDEN.read_text(encoding="utf-8"))

        self.assertEqual(normalized, expected)
        self.assertIn("successful_execution_is_not_safety", normalized["informational_notes"])
        self.assertNotIn("successful_execution_is_not_safety", normalized["decision_signals"])
        self.assertEqual(normalized["execution"]["exit_category"], "success")

    def test_normalized_output_does_not_retain_raw_preview_stdout_stderr_or_path(self) -> None:
        raw_path = "/" + "home/alice/private-repo"
        report = _source_report()
        normalized = normalize_sandbox_run_evidence(report)
        rendered = json.dumps(normalized, sort_keys=True)

        for value in ("raw-preview-value", "raw-stderr-value", "raw-output-summary", "raw-output-summary-error", raw_path):
            self.assertNotIn(value, rendered)
        self.assertNotIn("stdout_preview_redacted", normalized)
        self.assertNotIn("stderr_preview_redacted", normalized)
        self.assertNotIn("path_redacted", normalized)

    def test_problem_states_are_distinguished_as_decision_signals(self) -> None:
        cases = (
            ("timeout", {"result": {"status": "timed_out", "exit_code": None, "timed_out": True}}, "execution_timeout"),
            ("policy", {"policy_blocked": True, "result": {"status": "blocked", "exit_code": 2, "timed_out": False}}, "execution_policy_blocked"),
            ("cleanup", {"result": {"status": "cleanup_uncertain", "exit_code": 1, "timed_out": False}, "disposable_workspace": {"cleanup": "failed"}}, "workspace_cleanup_failed"),
            ("observer", {"observer": {"status": "degraded"}}, "observer_degraded"),
            ("binding", {"authorization": {"worktree_binding": {"checked": True, "status": "mismatch", "matched": False, "refusal_reasons": ["binding_mismatch"]}}}, "subject_binding_mismatch"),
            ("fake", {"docker": {"runner": "fake", "docker_invoked": False}, "run": {"run_id": "rhd-sandbox-run-fixed", "started_at": "2026-07-16T00:00:00Z", "ended_at": "2026-07-16T00:00:01Z", "dry_run": False}}, "not_real_execution_evidence"),
        )
        for label, updates, signal in cases:
            with self.subTest(label=label):
                report = deepcopy(_source_report())
                for key, value in updates.items():
                    if isinstance(value, dict) and isinstance(report.get(key), dict):
                        report[key] = {**report[key], **value}  # type: ignore[index]
                    else:
                        report[key] = value
                normalized = normalize_sandbox_run_evidence(report)
                self.assertIn(signal, normalized["decision_signals"])


if __name__ == "__main__":
    unittest.main()
