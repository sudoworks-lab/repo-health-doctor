from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import unittest

from repo_health_doctor.sandbox.approval import (
    build_demo_sandbox_run_approval,
    validate_sandbox_run_approval,
)
from repo_health_doctor.sandbox.profiles import get_sandbox_profile
from repo_health_doctor.sandbox.run_workspace import fingerprint_target


COMMAND = ["python3", "-c", "print('hello from sandbox')"]
IMAGE = "python:3.12-slim"


def _repo(path: Path) -> Path:
    path.mkdir()
    (path / "README.md").write_text("demo\n", encoding="utf-8")
    return path


def _approval(repo: Path) -> dict[str, object]:
    profile = get_sandbox_profile("no-network-default")
    return build_demo_sandbox_run_approval(
        target_path=repo,
        target_inventory=fingerprint_target(repo),
        command_argv=COMMAND,
        image=IMAGE,
        profile=profile,
        expires_at="2099-01-01T00:00:00Z",
    )


class SandboxRunApprovalTests(unittest.TestCase):
    def test_exact_sandbox_run_approval_matches(self) -> None:
        with self.subTest(case="exact"):
            repo = _repo(self._tmp_path() / "repo")
            profile = get_sandbox_profile("no-network-default")
            result = validate_sandbox_run_approval(
                _approval(repo),
                target_path=repo,
                target_inventory=fingerprint_target(repo),
                command_argv=COMMAND,
                image=IMAGE,
                profile=profile,
                timeout_seconds=30,
            )

            self.assertTrue(result.approved)
            self.assertTrue(result.matched)
            self.assertEqual(result.refusal_reasons, ())

    def test_sandbox_run_approval_blocks_mismatches(self) -> None:
        with self.subTest(case="mismatches"):
            repo = _repo(self._tmp_path() / "repo")
            cases: list[tuple[str, dict[str, object], list[str], str, str, int, str]] = []

            approval = deepcopy(_approval(repo))
            approval["command"] = {"argv": ["python3", "-c", "print('different')"], "shell": False}
            cases.append(("command", approval, COMMAND, IMAGE, "no-network-default", 30, "command_argv_mismatch"))

            approval = deepcopy(_approval(repo))
            approval["image"] = {"reference": "python:3.11-slim", "pull_policy": "never"}
            cases.append(("image", approval, COMMAND, IMAGE, "no-network-default", 30, "image_reference_mismatch"))

            approval = deepcopy(_approval(repo))
            approval["sandbox_profile"] = {"name": "no-network-readonly", "network": "none"}
            cases.append(("profile", approval, COMMAND, IMAGE, "no-network-default", 30, "sandbox_profile_mismatch"))

            approval = deepcopy(_approval(repo))
            approval["network"] = "bridge"
            cases.append(("network", approval, COMMAND, IMAGE, "no-network-default", 30, "network_mismatch"))

            approval = deepcopy(_approval(repo))
            approval["timeout_seconds"] = 1
            cases.append(("timeout", approval, COMMAND, IMAGE, "no-network-default", 2, "timeout_exceeds_approval"))

            for label, approval_doc, argv, image, profile_name, timeout, expected in cases:
                with self.subTest(case=label):
                    result = validate_sandbox_run_approval(
                        approval_doc,
                        target_path=repo,
                        target_inventory=fingerprint_target(repo),
                        command_argv=argv,
                        image=image,
                        profile=get_sandbox_profile(profile_name),
                        timeout_seconds=timeout,
                    )
                    self.assertFalse(result.matched)
                    self.assertIn(expected, result.refusal_reasons)

    def _tmp_path(self) -> Path:
        import tempfile

        path = Path(tempfile.mkdtemp(prefix="rhd-approval-test-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(path, ignore_errors=True))
        return path
