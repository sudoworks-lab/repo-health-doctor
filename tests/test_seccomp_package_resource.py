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

from repo_health_doctor.sandbox.profiles import PROFILE_MOBY_DEFAULT, resolve_seccomp_profile


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
        self.assertEqual(hashlib.sha256(profile_bytes).hexdigest(), resolved.profile_sha256)
        self.assertEqual(resolved.profile_sha256, provenance["profile_sha256"])
        self.assertEqual(PROFILE_MOBY_DEFAULT, provenance["profile_name"])
        self.assertEqual("https://github.com/moby/moby", provenance["source"]["repository"])
        self.assertTrue(provenance["source"]["version"])
        self.assertTrue(provenance["source"]["revision"])
        self.assertEqual("Apache-2.0", provenance["license"]["spdx_id"])
        self.assertTrue(provenance["retrieved_date"])
        self.assertTrue(provenance["changes"])
        self.assertIn("Apache License", resolved.license_text)

    def test_arbitrary_profile_names_are_not_filesystem_resource_lookup(self) -> None:
        with self.assertRaises(ValueError):
            resolve_seccomp_profile("/tmp/untrusted-profile.json")
        with self.assertRaises(ValueError):
            resolve_seccomp_profile("locked-down")

    def test_installed_wheel_resolves_same_resource_hash(self) -> None:
        source = resolve_seccomp_profile()
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

            probe = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "from repo_health_doctor.sandbox.profiles import resolve_seccomp_profile; "
                    "r = resolve_seccomp_profile(); "
                    "print(r.name); print(r.profile_sha256); print(r.provenance['source']['version']); "
                    "print(r.provenance['license']['spdx_id']); print(bool(r.license_text))",
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
                    "True",
                ],
                probe.stdout.splitlines(),
            )


if __name__ == "__main__":
    unittest.main()
