from __future__ import annotations

from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = [
    ROOT / "scripts" / "regenerate-gitleaks-compat-fixtures.sh",
    ROOT / "scripts" / "regenerate-osv-compat-fixtures.sh",
]


class CompatibilityRegenerationScriptTests(unittest.TestCase):
    def test_scripts_exist_and_pass_bash_syntax_check(self) -> None:
        for path in SCRIPTS:
            with self.subTest(path=path.relative_to(ROOT)):
                self.assertTrue(path.is_file())
                subprocess.run(["bash", "-n", str(path)], check=True)

    def test_scripts_explain_safe_synthetic_only_scope(self) -> None:
        for path in SCRIPTS:
            content = path.read_text(encoding="utf-8")
            with self.subTest(path=path.name):
                self.assertIn("safe synthetic fixtures only", content)
                self.assertIn("does not scan unknown repositories", content)
                self.assertIn("does not install scanners on the host", content)
                self.assertIn("does not run a host scanner", content)
                self.assertIn("does not commit raw scanner output", content)
                self.assertIn("only examples/ or tests/fixtures/ paths are allowed", content)
                self.assertIn("Review, redact, and normalize manually", content)

    def test_scripts_keep_image_acquisition_and_raw_output_bounded(self) -> None:
        for path in SCRIPTS:
            content = path.read_text(encoding="utf-8")
            with self.subTest(path=path.name):
                self.assertIn("--pull=never", content)
                self.assertIn("${TMPDIR:-/tmp}", content)
                self.assertIn("Do not commit raw output", content)
                self.assertIn("docker run", content)
                self.assertNotIn("docker pull", content)
                self.assertNotIn("pip install", content)
                self.assertNotIn("brew install", content)
                self.assertNotIn("curl ", content)
                self.assertNotIn("wget ", content)
                self.assertNotIn("/var/run/docker.sock", content)
                self.assertNotIn("$HOME", content)

    def test_osv_network_requires_explicit_flag(self) -> None:
        content = (ROOT / "scripts" / "regenerate-osv-compat-fixtures.sh").read_text(encoding="utf-8")

        self.assertIn('NETWORK_MODE="none"', content)
        self.assertIn("--allow-network-for-osv-db", content)
        self.assertIn('NETWORK_MODE="bridge"', content)


if __name__ == "__main__":
    unittest.main()
