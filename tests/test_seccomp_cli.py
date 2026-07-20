from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from repo_health_doctor.sandbox.profiles import (
    PROFILE_LOCKED_DOWN_SECCOMP,
    PROFILE_MOBY_DEFAULT,
    resolve_seccomp_profile,
)


ROOT = Path(__file__).resolve().parents[1]
COMMAND = ["python3", "-c", "print('seccomp contract')"]


def _assert_schema_valid(report: dict[str, object]) -> None:
    schema = json.loads((ROOT / "schemas" / "sandbox-run.schema.json").read_text(encoding="utf-8"))
    try:
        from jsonschema import Draft202012Validator
    except ModuleNotFoundError:
        assert set(schema["required"]).issubset(report)
    else:
        Draft202012Validator(schema).validate(report)


class SeccompCliTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        (self.repo / "README.md").write_text("seccomp cli test\n", encoding="utf-8")

    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT / "src")
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor",
                "sandbox-run",
                str(self.repo),
                "--format",
                "json",
                "--runner",
                "fake",
                "--dry-run",
                *args,
                "--",
                *COMMAND,
            ],
            cwd=ROOT,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )

    def test_runtime_default_is_default_and_omits_seccomp_docker_option(self) -> None:
        result = self._run()
        report = json.loads(result.stdout)

        self.assertEqual(0, result.returncode, result.stderr)
        _assert_schema_valid(report)
        self.assertEqual(
            {
                "profile": "runtime-default",
                "profile_sha256": None,
                "source": "runtime_default",
            },
            report["seccomp"],
        )
        self.assertFalse(any(str(token).startswith("seccomp=") for token in report["docker"]["argv_redacted"]))

    def test_arbitrary_path_and_unconfined_are_rejected_without_echo(self) -> None:
        for unsupported in ("unconfined", "/tmp/untrusted-seccomp.json"):
            with self.subTest(unsupported=unsupported):
                result = self._run("--seccomp", unsupported)

                self.assertEqual(2, result.returncode)
                self.assertEqual("", result.stdout)
                self.assertIn(
                    "must be runtime-default, rhd-moby-default-v1, or rhd-locked-down-v1",
                    result.stderr,
                )
                self.assertNotIn(unsupported, result.stderr)

    def test_packaged_profile_adds_docker_argv_and_schema_valid_evidence(self) -> None:
        result = self._run("--seccomp", PROFILE_MOBY_DEFAULT)
        report = json.loads(result.stdout)
        resolved = resolve_seccomp_profile()

        self.assertEqual(0, result.returncode, result.stderr)
        _assert_schema_valid(report)
        self.assertEqual(PROFILE_MOBY_DEFAULT, report["seccomp"]["profile"])
        self.assertEqual(resolved.profile_sha256, report["seccomp"]["profile_sha256"])
        self.assertEqual("package_data", report["seccomp"]["source"])
        argv = report["docker"]["argv_redacted"]
        self.assertIn("--security-opt", argv)
        self.assertIn(
            "seccomp=<sandbox-run-root>/rhd-moby-default-v1.json",
            argv,
        )

    def test_locked_down_profile_is_explicit_package_data_choice(self) -> None:
        result = self._run("--seccomp", PROFILE_LOCKED_DOWN_SECCOMP)
        report = json.loads(result.stdout)
        resolved = resolve_seccomp_profile(PROFILE_LOCKED_DOWN_SECCOMP)

        self.assertEqual(0, result.returncode, result.stderr)
        _assert_schema_valid(report)
        self.assertEqual(PROFILE_LOCKED_DOWN_SECCOMP, report["seccomp"]["profile"])
        self.assertEqual(resolved.profile_sha256, report["seccomp"]["profile_sha256"])
        self.assertEqual("package_data", report["seccomp"]["source"])
        argv = report["docker"]["argv_redacted"]
        self.assertEqual(1, argv.count("--pull=never"))
        self.assertEqual(2, argv.count("--security-opt"))
        self.assertEqual(
            1,
            argv.count("seccomp=<sandbox-run-root>/rhd-locked-down-v1.json"),
        )
        self.assertFalse(any("docs/human-review" in str(token) for token in argv))


if __name__ == "__main__":
    unittest.main()
