from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
PYTHON_HOOK_DIR = REPO_ROOT / "src" / "repo_health_doctor" / "sandbox_hooks" / "python"
NODE_HOOK_PATH = REPO_ROOT / "src" / "repo_health_doctor" / "sandbox_hooks" / "node" / "node-hook.js"


def _load_event_payloads(event_path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in event_path.read_text(encoding="utf-8").splitlines() if line.strip()]


class SandboxHookRuntimeTests(unittest.TestCase):
    def test_python_runtime_hook_emits_redacted_observer_events(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            home_dir = root / "home"
            writable_dir = root / "writable"
            outside_target = root / "outside.txt"
            inside_target = writable_dir / "inside.txt"
            event_path = root / "observer-events.jsonl"
            home_dir.mkdir()
            writable_dir.mkdir()
            (home_dir / ".netrc").write_text(
                "machine example.invalid login rhd password RHD_HONEYPOT\n",
                encoding="utf-8",
            )
            outside_target.write_text("outside\n", encoding="utf-8")

            env = os.environ.copy()
            env.update(
                {
                    "HOME": str(home_dir),
                    "PYTHONPATH": str(PYTHON_HOOK_DIR),
                    "RHD_OBSERVER_EVENT_FILE": str(event_path),
                    "RHD_SECRET_ENV_NAMES": "AWS_SECRET_ACCESS_KEY,GITHUB_TOKEN",
                    "RHD_ALLOWED_WRITE_ROOTS": str(writable_dir),
                    "AWS_SECRET_ACCESS_KEY": "RHD_HONEYPOT_SECRET_VALUE",
                    "RHD_INSIDE_TARGET": str(inside_target),
                    "RHD_OUTSIDE_TARGET": str(outside_target),
                    "RHD_CHILD_PYTHON": sys.executable,
                }
            )

            subprocess.run(
                [
                    sys.executable,
                    "-c",
                    (
                        "import os, pathlib, subprocess; "
                        "pathlib.Path(os.environ['RHD_INSIDE_TARGET']).write_text('inside\\n', encoding='utf-8'); "
                        "pathlib.Path.home().joinpath('.netrc').read_text(encoding='utf-8'); "
                        "_ = os.environ['AWS_SECRET_ACCESS_KEY']; "
                        "list(os.environ.items()); "
                        "pathlib.Path(os.environ['RHD_INSIDE_TARGET']).unlink(); "
                        "pathlib.Path(os.environ['RHD_OUTSIDE_TARGET']).unlink(); "
                        "subprocess.run([os.environ['RHD_CHILD_PYTHON'], '-c', 'print(\"child\")'], check=False)"
                    ),
                ],
                check=True,
                capture_output=True,
                text=True,
                env=env,
            )

            payloads = _load_event_payloads(event_path)
            event_types = {payload["event_type"] for payload in payloads}
            delete_zones = {
                payload["detail"]["zone"]
                for payload in payloads
                if payload["event_type"] == "file_delete_attempt"
            }
            raw_event_text = event_path.read_text(encoding="utf-8")

            self.assertIn("secret_file_open", event_types)
            self.assertIn("secret_env_access", event_types)
            self.assertIn("env_sweep", event_types)
            self.assertIn("subprocess_spawn", event_types)
            self.assertIn("file_delete_attempt", event_types)
            self.assertEqual(delete_zones, {"sandbox_writable", "outside_sandbox_writable"})
            self.assertNotIn(str(home_dir), raw_event_text)
            self.assertNotIn(str(outside_target), raw_event_text)
            self.assertNotIn("RHD_HONEYPOT_SECRET_VALUE", raw_event_text)

    def test_node_runtime_hook_emits_redacted_observer_events(self) -> None:
        node_binary = shutil.which("node")
        if node_binary is None:
            self.skipTest("node is unavailable on this platform")

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            home_dir = root / "home"
            writable_dir = root / "writable"
            outside_target = root / "outside.txt"
            inside_target = writable_dir / "inside.txt"
            event_path = root / "observer-events.jsonl"
            home_dir.mkdir()
            writable_dir.mkdir()
            (home_dir / ".netrc").write_text(
                "machine example.invalid login rhd password RHD_HONEYPOT\n",
                encoding="utf-8",
            )
            outside_target.write_text("outside\n", encoding="utf-8")

            env = os.environ.copy()
            env.update(
                {
                    "HOME": str(home_dir),
                    "NODE_OPTIONS": f"--require={NODE_HOOK_PATH}",
                    "RHD_OBSERVER_EVENT_FILE": str(event_path),
                    "RHD_SECRET_ENV_NAMES": "AWS_SECRET_ACCESS_KEY,GITHUB_TOKEN",
                    "RHD_ALLOWED_WRITE_ROOTS": str(writable_dir),
                    "AWS_SECRET_ACCESS_KEY": "RHD_HONEYPOT_SECRET_VALUE",
                    "RHD_INSIDE_TARGET": str(inside_target),
                    "RHD_OUTSIDE_TARGET": str(outside_target),
                }
            )

            subprocess.run(
                [
                    node_binary,
                    "-e",
                    (
                        "const cp = require('node:child_process');"
                        "const fs = require('node:fs');"
                        "const path = require('node:path');"
                        "fs.writeFileSync(process.env.RHD_INSIDE_TARGET, 'inside\\n');"
                        "fs.readFileSync(path.join(process.env.HOME, '.netrc'), 'utf8');"
                        "void process.env.AWS_SECRET_ACCESS_KEY;"
                        "Object.keys(process.env);"
                        "fs.unlinkSync(process.env.RHD_INSIDE_TARGET);"
                        "fs.unlinkSync(process.env.RHD_OUTSIDE_TARGET);"
                        "cp.spawnSync(process.execPath, ['-e', 'console.log(\"child\")'], {stdio: 'ignore'});"
                    ),
                ],
                check=True,
                capture_output=True,
                text=True,
                env=env,
            )

            payloads = _load_event_payloads(event_path)
            event_types = {payload["event_type"] for payload in payloads}
            delete_zones = {
                payload["detail"]["zone"]
                for payload in payloads
                if payload["event_type"] == "file_delete_attempt"
            }
            raw_event_text = event_path.read_text(encoding="utf-8")

            self.assertIn("secret_file_open", event_types)
            self.assertIn("secret_env_access", event_types)
            self.assertIn("env_sweep", event_types)
            self.assertIn("subprocess_spawn", event_types)
            self.assertIn("file_delete_attempt", event_types)
            self.assertEqual(delete_zones, {"sandbox_writable", "outside_sandbox_writable"})
            self.assertNotIn(str(home_dir), raw_event_text)
            self.assertNotIn(str(outside_target), raw_event_text)
            self.assertNotIn("RHD_HONEYPOT_SECRET_VALUE", raw_event_text)
