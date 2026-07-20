from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from repo_health_doctor.sandbox.docker_runner import DockerRunner
from repo_health_doctor.sandbox.profiles import SECCOMP_PROFILE_CHOICES
from repo_health_doctor.sandbox.profiles import (
    PROFILE_LOCKED_DOWN_SECCOMP,
    resolve_seccomp_profile,
)
from repo_health_doctor.sandbox.run import run_sandbox_run
from repo_health_doctor.sandbox.run_workspace import fingerprint_target
from scripts.run_candidate_seccomp_review import CASES, _build_docker_argv
from scripts.validate_final_security_gates import validate_final_security_gates


ROOT = Path(__file__).resolve().parents[1]
CANDIDATE_NAME = "rhd-locked-down-v1"
CANDIDATE_PATH = ROOT / "docs" / "human-review" / "rhd-locked-down-v1.candidate.json"
PACKET_PATH = ROOT / "docs" / "human-review" / "seccomp-review-packet.json"
MARKDOWN_PATH = ROOT / "docs" / "human-review" / "seccomp-review-packet.md"
SCRIPT_PATH = ROOT / "scripts" / "run_candidate_seccomp_review.py"
REAL_DOCKER_ENABLED = os.environ.get("RHD_REAL_DOCKER_TEST") == "1"
EXPECTED_CASE_IDS = {1, 2, 3, 4, 5, 6, 8, 10}
PACKAGE_PATH = (
    ROOT
    / "src"
    / "repo_health_doctor"
    / "sandbox"
    / "resources"
    / "rhd-locked-down-v1.json"
)
FINAL_GATES_PATH = ROOT / "docs" / "human-review" / "final-security-gates.json"


class CandidateSeccompReviewContractTests(unittest.TestCase):
    def _record(self) -> dict[str, object]:
        packet = json.loads(PACKET_PATH.read_text(encoding="utf-8"))
        record = packet["candidate_local_regression"]
        self.assertIsInstance(record, dict)
        return record

    def test_candidate_argv_is_review_only_pull_never_and_network_none(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            out = root / "out"
            workspace.mkdir()
            out.mkdir()
            argv = _build_docker_argv(
                image="<existing-local-image>@sha256:" + ("0" * 64),
                candidate_path=CANDIDATE_PATH,
                workspace=workspace,
                out=out,
                container_name="rhd-candidate-review-contract",
                command=("python3", "-c", "print('contract')"),
            )

        self.assertEqual(1, argv.count("--pull=never"))
        self.assertNotIn("pull", argv)
        network_index = argv.index("--network")
        self.assertEqual("none", argv[network_index + 1])
        self.assertIn(f"seccomp={CANDIDATE_PATH}", argv)
        self.assertIn(CANDIDATE_NAME, SECCOMP_PROFILE_CHOICES)

    def test_packet_records_environment_profile_cases_and_every_failure(self) -> None:
        record = self._record()
        candidate_hash = hashlib.sha256(CANDIDATE_PATH.read_bytes()).hexdigest()
        cases = record["cases"]
        failures = record["failures"]

        self.assertEqual("F030", record["recorded_by_feature_id"])
        self.assertEqual(candidate_hash, record["profile_sha256"])
        self.assertEqual("human_unapproved", record["approval_state"])
        self.assertEqual("disconnected", record["product_connection_state"])
        self.assertEqual("never", record["pull_policy"])
        self.assertEqual("none", record["network_mode"])
        self.assertFalse(record["raw_process_output_recorded"])
        self.assertEqual(EXPECTED_CASE_IDS, set(record["required_case_ids"]))
        self.assertEqual(EXPECTED_CASE_IDS, {case["case_id"] for case in cases})
        self.assertTrue(record["all_required_cases_recorded"])
        self.assertEqual(len(CASES), len(cases))
        self.assertEqual(
            len(cases),
            record["passed_case_count"] + record["failed_case_count"] + record["not_run_case_count"],
        )
        environment = record["environment"]
        for field in (
            "docker_server_version",
            "docker_os",
            "docker_architecture",
            "kernel_version",
            "rootless",
            "userns_remap",
            "image_selection_source",
            "image_digest",
            "local_image_id",
        ):
            self.assertIn(field, environment)

        recorded_case_failures = {
            (case["case_id"], code)
            for case in cases
            for code in case["failure_codes"]
        }
        flattened_case_failures = {
            (failure["case_id"], failure["failure_code"])
            for failure in failures
            if failure["scope"] == "case"
        }
        self.assertEqual(recorded_case_failures, flattened_case_failures)
        serialized = json.dumps(record, ensure_ascii=False).lower()
        self.assertNotIn("stdout", serialized)
        self.assertNotIn("stderr", serialized)
        self.assertNotIn(str(ROOT).lower(), serialized)

        markdown = MARKDOWN_PATH.read_text(encoding="utf-8")
        self.assertIn(record["profile_sha256"], markdown)
        for case_id in EXPECTED_CASE_IDS:
            self.assertIn(f"| {case_id} |", markdown)


@unittest.skipUnless(
    REAL_DOCKER_ENABLED,
    "set RHD_REAL_DOCKER_TEST=1 to run the candidate-only real Docker regression",
)
class CandidateSeccompRealDockerTests(unittest.TestCase):
    def test_candidate_regression_attempt_is_fully_recorded(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(SCRIPT_PATH)],
            cwd=ROOT,
            env={**os.environ, "PYTHONPATH": "src"},
            check=False,
            capture_output=True,
            text=True,
            timeout=180,
        )
        self.assertIn(completed.returncode, {0, 1})

        packet = json.loads(PACKET_PATH.read_text(encoding="utf-8"))
        record = packet["candidate_local_regression"]
        self.assertEqual(EXPECTED_CASE_IDS, {case["case_id"] for case in record["cases"]})
        self.assertTrue(record["all_required_cases_recorded"])
        self.assertEqual(
            len(record["cases"]),
            record["passed_case_count"]
            + record["failed_case_count"]
            + record["not_run_case_count"],
        )
        self.assertEqual("disconnected", record["product_connection_state"])
        self.assertIn(CANDIDATE_NAME, SECCOMP_PROFILE_CHOICES)


@unittest.skipUnless(
    REAL_DOCKER_ENABLED,
    "set RHD_REAL_DOCKER_TEST=1 to run the approved product profile regression",
)
class ApprovedLockedDownProductRealDockerTests(unittest.TestCase):
    def _docker_value(self, argv: list[str]) -> str:
        completed = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(0, completed.returncode)
        value = completed.stdout.strip()
        self.assertTrue(value)
        return value

    def test_approved_product_profile_cases_are_bounded_and_fully_recorded(self) -> None:
        image = os.environ.get("RHD_REAL_DOCKER_IMAGE", "").strip()
        self.assertRegex(image, r"@sha256:[0-9a-f]{64}\Z")
        runner = DockerRunner()
        self.assertTrue(runner.docker_available())
        self.assertTrue(runner.image_available_locally(image))

        valid, reason_codes = validate_final_security_gates(FINAL_GATES_PATH)
        self.assertTrue(valid, reason_codes)
        approval = json.loads(FINAL_GATES_PATH.read_text(encoding="utf-8"))["seccomp_approval"]
        resolved = resolve_seccomp_profile(PROFILE_LOCKED_DOWN_SECCOMP)
        expected_hash = os.environ.get("EXPECTED_LOCKED_DOWN_SHA256", resolved.profile_sha256)
        candidate_bytes = CANDIDATE_PATH.read_bytes()
        package_bytes = PACKAGE_PATH.read_bytes()
        self.assertIn(PROFILE_LOCKED_DOWN_SECCOMP, SECCOMP_PROFILE_CHOICES)
        self.assertEqual(candidate_bytes, package_bytes)
        self.assertEqual(expected_hash, resolved.profile_sha256)
        self.assertEqual(approval["approved_profile_sha256"], resolved.profile_sha256)
        docker_server_version = self._docker_value(
            ["docker", "version", "--format", "{{.Server.Version}}"]
        )
        docker_os = self._docker_value(
            ["docker", "info", "--format", "{{.OperatingSystem}}"]
        )
        docker_architecture = self._docker_value(
            ["docker", "info", "--format", "{{.Architecture}}"]
        )
        kernel_version = self._docker_value(
            ["docker", "info", "--format", "{{.KernelVersion}}"]
        )
        local_image_id = self._docker_value(
            ["docker", "image", "inspect", "--format", "{{.Id}}", image]
        )
        runtime = runner.detect_runtime()

        cases: list[dict[str, object]] = []
        for case in CASES:
            failure_codes: list[str] = []
            with tempfile.TemporaryDirectory() as temporary:
                repo = Path(temporary) / "repo"
                repo.mkdir()
                (repo / "README.md").write_text(
                    "approved locked-down product regression\n",
                    encoding="utf-8",
                )
                original_fingerprint = fingerprint_target(repo).fingerprint
                report = run_sandbox_run(
                    repo,
                    image=image,
                    profile_name="no-network-readonly",
                    seccomp_profile_name=PROFILE_LOCKED_DOWN_SECCOMP,
                    command_argv=list(case.command),
                    timeout_seconds=case.timeout_seconds,
                    runner=runner,
                )
                if fingerprint_target(repo).fingerprint != original_fingerprint:
                    failure_codes.append("original_repo_changed")

            timed_out = report["result"]["timed_out"] is True
            if case.expected_outcome == "timed_out":
                if not timed_out:
                    failure_codes.append("expected_timeout_not_observed")
            elif timed_out:
                failure_codes.append("unexpected_timeout")
            elif report["result"]["status"] != "completed":
                failure_codes.append("product_run_not_completed")
            elif report["result"]["exit_code"] != 0:
                failure_codes.append("product_run_nonzero_exit")

            argv = report["docker"]["argv_redacted"]
            if argv.count("--pull=never") != 1:
                failure_codes.append("pull_never_contract_mismatch")
            if argv.count("seccomp=<sandbox-run-root>/rhd-locked-down-v1.json") != 1:
                failure_codes.append("locked_down_seccomp_argv_mismatch")
            if any("docs/human-review" in str(token) for token in argv):
                failure_codes.append("candidate_docs_path_exposed")
            if report["docker"]["network"] != "none":
                failure_codes.append("network_mode_mismatch")
            if report["disposable_workspace"]["cleanup"] != "ok":
                failure_codes.append("workspace_cleanup_failed")
            if report["output_summary"]["raw_stdout_stderr_persisted"] is not False:
                failure_codes.append("raw_process_output_recorded")

            cases.append(
                {
                    "case_id": case.case_id,
                    "status": "pass" if not failure_codes else "fail",
                    "failure_codes": failure_codes,
                }
            )

        passed_case_count = sum(case["status"] == "pass" for case in cases)
        failed_case_count = sum(case["status"] == "fail" for case in cases)
        evidence = {
            "schema_version": "0.1-draft",
            "evidence_kind": "hosted_locked_down_product_regression",
            "provider": "github_actions",
            "runner_environment": "github_hosted",
            "workflow_path": ".github/workflows/real-docker-verification.yml",
            "event": os.environ.get("GITHUB_EVENT_NAME", "local_opt_in"),
            "run_id": int(os.environ.get("GITHUB_RUN_ID", "0")),
            "head_sha": os.environ.get("GITHUB_SHA", "local_opt_in"),
            "profile": PROFILE_LOCKED_DOWN_SECCOMP,
            "profile_sha256": resolved.profile_sha256,
            "source": "package_data",
            "docker_server_version": docker_server_version,
            "docker_os": docker_os,
            "docker_architecture": docker_architecture,
            "kernel_version": kernel_version,
            "rootless": runtime["rootless_docker_detected"],
            "userns_remap": runtime["userns_remap_detected"],
            "image_digest": image.rsplit("@", maxsplit=1)[1],
            "local_image_id": local_image_id,
            "required_case_ids": sorted(EXPECTED_CASE_IDS),
            "attempted_case_count": len(cases),
            "passed_case_count": passed_case_count,
            "failed_case_count": failed_case_count,
            "not_run_case_count": 0,
            "cases": cases,
            "pull_policy": "never",
            "network_mode": "none",
            "candidate_docs_path_passed_to_docker": False,
            "raw_process_output_recorded": False,
            "conclusion": "success" if failed_case_count == 0 else "failure",
        }
        print(
            "RHD_HOSTED_LOCKED_DOWN_PRODUCT_EVIDENCE="
            + json.dumps(evidence, sort_keys=True, separators=(",", ":"))
        )

        self.assertEqual(EXPECTED_CASE_IDS, {case["case_id"] for case in cases})
        self.assertEqual(8, len(cases))
        self.assertEqual(8, passed_case_count, evidence)
        self.assertEqual(0, failed_case_count, evidence)


if __name__ == "__main__":
    unittest.main()
