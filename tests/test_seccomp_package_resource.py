from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from importlib import resources

from repo_health_doctor.sandbox.profiles import (
    PROFILE_LOCKED_DOWN_SECCOMP,
    PROFILE_MOBY_DEFAULT,
    resolve_seccomp_profile,
)


ROOT = Path(__file__).resolve().parents[1]
CANDIDATE_PATH = ROOT / "docs" / "human-review" / "rhd-locked-down-v1.candidate.json"


class SeccompPackageResourceTests(unittest.TestCase):
    def test_source_resource_has_provenance_license_and_stable_hash(self) -> None:
        resolved = resolve_seccomp_profile()
        resource_root = resources.files("repo_health_doctor.sandbox.resources")
        profile_bytes = resource_root.joinpath("rhd-moby-default-v1.json").read_bytes()
        provenance = json.loads(
            resource_root.joinpath("rhd-moby-default-v1.provenance.json").read_text(encoding="utf-8")
        )

        self.assertEqual(PROFILE_MOBY_DEFAULT, resolved.name)
        self.assertEqual("SCMP_ACT_ERRNO", resolved.profile["defaultAction"])
        self.assertTrue(resolved.profile["architectures"])
        self.assertTrue(resolved.profile["syscalls"])
        allowed_names = [
            name
            for group in resolved.profile["syscalls"]
            if group["action"] == "SCMP_ACT_ALLOW"
            for name in group["names"]
        ]
        expected_mqueue = {
            "mq_getsetattr",
            "mq_notify",
            "mq_open",
            "mq_timedreceive",
            "mq_timedreceive_time64",
            "mq_timedsend",
            "mq_timedsend_time64",
            "mq_unlink",
        }
        self.assertEqual(281, len(allowed_names))
        self.assertEqual(281, len(set(allowed_names)))
        self.assertEqual(1, allowed_names.count("statx"))
        self.assertEqual(expected_mqueue, {name for name in allowed_names if name.startswith("mq_")})
        self.assertEqual(0, allowed_names.count("mq_send"))
        self.assertEqual(hashlib.sha256(profile_bytes).hexdigest(), resolved.profile_sha256)
        self.assertEqual(resolved.profile_sha256, provenance["profile_sha256"])
        self.assertEqual(PROFILE_MOBY_DEFAULT, provenance["profile_name"])
        self.assertEqual("https://github.com/moby/moby", provenance["source"]["repository"])
        self.assertTrue(provenance["source"]["version"])
        self.assertTrue(provenance["source"]["revision"])
        self.assertEqual("Apache-2.0", provenance["license"]["spdx_id"])
        self.assertTrue(provenance["retrieved_date"])
        self.assertEqual(281, provenance["allowlisted_syscall_count"])
        self.assertTrue(provenance["upstream_contract"]["statx_present"])
        self.assertEqual(
            expected_mqueue,
            set(provenance["upstream_contract"]["posix_message_queue_syscalls"]),
        )
        self.assertTrue(provenance["changes"])
        changes = "\n".join(provenance["changes"])
        for expected in (
            "statx",
            "Docker Engine 29.5.3",
            "runc 1.3.6",
            "2026-07-17 JST",
            "python@sha256:d764629ce0ddd8c71fd371e9901efb324a95789d2315a47db7e4d27e78f1b0e9",
            "minimal run",
            "sandbox boundary run",
            "upstream-contract normalization",
            "normalized artifact",
            "Human-shell real Docker reverification",
            "completed",
            "recorded local environment",
            "do not establish general compatibility",
        ):
            self.assertIn(expected, changes)
        self.assertIn("Apache License", resolved.license_text)

    def test_arbitrary_profile_names_are_not_filesystem_resource_lookup(self) -> None:
        with self.assertRaises(ValueError) as path_error:
            resolve_seccomp_profile("/tmp/untrusted-profile.json")
        self.assertNotIn("/tmp/untrusted-profile.json", str(path_error.exception))
        with self.assertRaises(ValueError) as name_error:
            resolve_seccomp_profile("locked-down")
        self.assertNotIn("locked-down", str(name_error.exception))

    def test_locked_down_resource_matches_approved_candidate_and_provenance(self) -> None:
        resolved = resolve_seccomp_profile(PROFILE_LOCKED_DOWN_SECCOMP)
        resource_root = resources.files("repo_health_doctor.sandbox.resources")
        profile_bytes = resource_root.joinpath("rhd-locked-down-v1.json").read_bytes()
        provenance = json.loads(
            resource_root.joinpath("rhd-locked-down-v1.provenance.json").read_text(
                encoding="utf-8"
            )
        )
        candidate_bytes = CANDIDATE_PATH.read_bytes()

        self.assertEqual(candidate_bytes, profile_bytes)
        self.assertEqual(PROFILE_LOCKED_DOWN_SECCOMP, resolved.name)
        self.assertEqual(hashlib.sha256(candidate_bytes).hexdigest(), resolved.profile_sha256)
        self.assertEqual(resolved.profile_sha256, provenance["profile_sha256"])
        self.assertEqual(PROFILE_MOBY_DEFAULT, provenance["derived_from"])
        self.assertEqual(266, provenance["allowlisted_syscall_count"])
        self.assertEqual(15, len(provenance["removed_syscalls"]))
        self.assertEqual("Apache-2.0", provenance["license"]["spdx_id"])
        self.assertTrue(provenance["final_security_gates"]["human_approval_recorded"])
        self.assertEqual(8, provenance["bounded_regressions"]["local"]["passed_case_count"])
        self.assertEqual(8, provenance["bounded_regressions"]["hosted"]["passed_case_count"])
        self.assertEqual(29764489485, provenance["bounded_regressions"]["hosted"]["run_id"])

    def test_installed_wheel_resolves_same_resource_hash(self) -> None:
        source = resolve_seccomp_profile()
        locked_source = resolve_seccomp_profile(PROFILE_LOCKED_DOWN_SECCOMP)
        repository_root = Path(__file__).resolve().parents[1]

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wheel_dir = root / "wheel"
            install_dir = root / "install"
            wheel_dir.mkdir()
            install_dir.mkdir()
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "wheel",
                    str(repository_root),
                    "--no-deps",
                    "--no-build-isolation",
                    "--wheel-dir",
                    str(wheel_dir),
                ],
                check=False,
                capture_output=True,
                text=True,
                env={**os.environ, "PYTHONPATH": ""},
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            wheels = sorted(wheel_dir.glob("repo_health_doctor-*.whl"))
            self.assertEqual(1, len(wheels), completed.stdout)

            installed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "install",
                    "--no-deps",
                    "--no-index",
                    "--target",
                    str(install_dir),
                    str(wheels[0]),
                ],
                check=False,
                capture_output=True,
                text=True,
                env={**os.environ, "PYTHONPATH": ""},
            )
            self.assertEqual(0, installed.returncode, installed.stderr)

            installed_locked_resource = (
                install_dir
                / "repo_health_doctor"
                / "sandbox"
                / "resources"
                / "rhd-locked-down-v1.json"
            )
            installed_locked_provenance = installed_locked_resource.with_name(
                "rhd-locked-down-v1.provenance.json"
            )
            self.assertEqual(CANDIDATE_PATH.read_bytes(), installed_locked_resource.read_bytes())
            self.assertEqual(
                locked_source.profile_sha256,
                json.loads(installed_locked_provenance.read_text(encoding="utf-8"))[
                    "profile_sha256"
                ],
            )

            probe = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "from repo_health_doctor.sandbox.profiles import resolve_seccomp_profile; "
                    "r = resolve_seccomp_profile(); "
                    "locked = resolve_seccomp_profile('rhd-locked-down-v1'); "
                    "print(r.name); print(r.profile_sha256); print(r.provenance['source']['version']); "
                    "print(r.provenance['license']['spdx_id']); "
                    "names = [n for g in r.profile['syscalls'] if g['action'] == 'SCMP_ACT_ALLOW' for n in g['names']]; "
                    "print(len(names)); print(names.count('statx')); "
                    "print(','.join(n for n in names if n.startswith('mq_'))); "
                    "print(names.count('mq_send')); print(bool(r.license_text)); "
                    "print(locked.name); print(locked.profile_sha256); "
                    "print(locked.provenance['profile_sha256']); "
                    "print(locked.provenance['allowlisted_syscall_count']); "
                    "print(len(locked.provenance['removed_syscalls'])); "
                    "print(locked.provenance['license']['spdx_id']); "
                    "print(bool(locked.license_text))",
                ],
                check=False,
                capture_output=True,
                text=True,
                cwd=root,
                env={**os.environ, "PYTHONPATH": str(install_dir)},
            )
            self.assertEqual(0, probe.returncode, probe.stderr)
            self.assertEqual(
                [
                    source.name,
                    source.profile_sha256,
                    source.provenance["source"]["version"],
                    source.provenance["license"]["spdx_id"],
                    "281",
                    "1",
                    "mq_getsetattr,mq_notify,mq_open,mq_timedreceive,mq_timedreceive_time64,mq_timedsend,mq_timedsend_time64,mq_unlink",
                    "0",
                    "True",
                    locked_source.name,
                    locked_source.profile_sha256,
                    locked_source.profile_sha256,
                    "266",
                    "15",
                    "Apache-2.0",
                    "True",
                ],
                probe.stdout.splitlines(),
            )


if __name__ == "__main__":
    unittest.main()
