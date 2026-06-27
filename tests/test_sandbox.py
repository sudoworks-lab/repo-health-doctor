from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest
from unittest import mock

from repo_health_doctor.cli import build_parser
from repo_health_doctor.sandbox.command import (
    REPORT_KIND_SANDBOX,
    _has_successful_observed_dynamic_result,
    run_sandbox,
)
from repo_health_doctor.sandbox.docker import build_docker_spec, default_docker_user, resolve_docker_argv
from repo_health_doctor.sandbox import dynamic as sandbox_dynamic
from repo_health_doctor.sandbox.fetch_plan import build_fetch_plan
from repo_health_doctor.sandbox.observer import build_observer_plan
from repo_health_doctor.sandbox.report import format_sandbox_json
from repo_health_doctor.sandbox.rescan import run_phase1_rescan
from repo_health_doctor.sandbox.workspace import (
    build_disposable_workspace_plan,
    materialize_disposable_workspace,
)


SANDBOX_SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "sandbox-report.schema.json"
FIXTURES_ROOT = Path(__file__).resolve().parent / "fixtures"


def _assert_matches_schema(
    testcase: unittest.TestCase,
    value: object,
    schema: dict,
    path: str = "$",
    root_schema: dict | None = None,
) -> None:
    if root_schema is None:
        root_schema = schema
    if "$ref" in schema:
        ref = schema["$ref"]
        testcase.assertTrue(ref.startswith("#/"), f"{path} uses unsupported ref: {ref}")
        resolved_schema = root_schema
        for part in ref[2:].split("/"):
            resolved_schema = resolved_schema[part]
        schema = {**resolved_schema, **{key: item for key, item in schema.items() if key != "$ref"}}

    expected_type = schema.get("type")
    if isinstance(expected_type, list):
        if value is None and "null" in expected_type:
            pass
        elif isinstance(value, bool):
            testcase.assertIn("boolean", expected_type, f"{path} should match one of {expected_type}")
        elif isinstance(value, int):
            testcase.assertIn("integer", expected_type, f"{path} should match one of {expected_type}")
        elif isinstance(value, str):
            testcase.assertIn("string", expected_type, f"{path} should match one of {expected_type}")
        elif isinstance(value, dict):
            testcase.assertIn("object", expected_type, f"{path} should match one of {expected_type}")
        elif isinstance(value, list):
            testcase.assertIn("array", expected_type, f"{path} should match one of {expected_type}")
        else:
            testcase.fail(f"{path} should match one of {expected_type}")
        expected_type = None
    if expected_type == "object":
        testcase.assertIsInstance(value, dict, f"{path} should be an object")
        assert isinstance(value, dict)
        for key in schema.get("required", []):
            testcase.assertIn(key, value, f"{path} missing required key: {key}")
        properties = schema.get("properties", {})
        for key, child_schema in properties.items():
            if key in value:
                _assert_matches_schema(testcase, value[key], child_schema, f"{path}.{key}", root_schema)
        if schema.get("additionalProperties") is False:
            extra_keys = sorted(set(value) - set(properties))
            testcase.assertEqual(extra_keys, [], f"{path} has unexpected keys")
    elif expected_type == "array":
        testcase.assertIsInstance(value, list, f"{path} should be an array")
        assert isinstance(value, list)
        item_schema = schema.get("items")
        if item_schema:
            for index, item in enumerate(value):
                _assert_matches_schema(testcase, item, item_schema, f"{path}[{index}]", root_schema)
    elif expected_type == "string":
        testcase.assertIsInstance(value, str, f"{path} should be a string")
    elif expected_type == "integer":
        testcase.assertIsInstance(value, int, f"{path} should be an integer")
        testcase.assertNotIsInstance(value, bool, f"{path} should be an integer, not boolean")
    elif expected_type == "boolean":
        testcase.assertIsInstance(value, bool, f"{path} should be a boolean")

    if "enum" in schema:
        testcase.assertIn(value, schema["enum"], f"{path} has invalid enum value")
    if "minimum" in schema:
        testcase.assertGreaterEqual(value, schema["minimum"], f"{path} is below minimum")
    if "minItems" in schema:
        testcase.assertGreaterEqual(len(value), schema["minItems"], f"{path} has too few items")


class SandboxSliceTests(unittest.TestCase):
    LOCAL_IMAGE_ID = "sha256:58513b66cedda1be08bb3c5ada38214894f601ad0b528936129881fdc75c1e55"
    PHASE3_RUNTIME_FIXTURE_ARGV = [
        "python",
        "-c",
        "import os, pathlib; pathlib.Path('/tmp/tmp/rhd-phase3-runtime.txt').write_text('ok', encoding='utf-8'); print(os.getpid())",
    ]
    GENERIC_AWS_ACCESS_KEY = "A" + "KIA1234567890ABCDEF"
    GENERIC_SECRET_OUTPUT = "\n".join(
        [
            "sk-probe_0123456789abcdef",
            "ghp_0123456789abcdefghijklmnopqrstuv",
            GENERIC_AWS_ACCESS_KEY,
            "-----BEGIN PRIVATE KEY-----\nprivate-key-material\n-----END PRIVATE KEY-----",
            "password=plain-password token=plain-token api_key=plain-api-key secret=plain-secret",
        ]
    )
    GENERIC_SECRET_VALUES = (
        "sk-probe_0123456789abcdef",
        "ghp_0123456789abcdefghijklmnopqrstuv",
        GENERIC_AWS_ACCESS_KEY,
        "private-key-material",
        "plain-password",
        "plain-token",
        "plain-api-key",
        "plain-secret",
    )

    def setUp(self) -> None:
        self._tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmp_dir.name)

    def tearDown(self) -> None:
        self._tmp_dir.cleanup()

    def _cli_env(self) -> dict[str, str]:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
        return env

    def _fixture_path(self, relative_path: str) -> Path:
        return FIXTURES_ROOT / relative_path

    @staticmethod
    def _docker_inspect_result(image_id: str) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=["docker", "image", "inspect"],
            returncode=0,
            stdout=json.dumps([{"Id": image_id}]),
            stderr="",
        )

    @staticmethod
    def _phase3_runtime_fixture_command(
        *,
        phase: str = "phase3_runtime_probe",
        kind: str = "test_probe",
        cwd: str = ".",
        argv: list[str] | None = None,
        env_allowlist: list[str] | None = None,
        shell: bool = False,
    ) -> dict[str, object]:
        return {
            "phase": phase,
            "kind": kind,
            "cwd": cwd,
            "argv": list(SandboxSliceTests.PHASE3_RUNTIME_FIXTURE_ARGV) if argv is None else argv,
            "env_allowlist": [] if env_allowlist is None else env_allowlist,
            "shell": shell,
        }

    def _write_demo_repo(self) -> Path:
        repo_path = self.tmp_path / "sandbox-demo"
        repo_path.mkdir()
        (repo_path / "package.json").write_text(
            json.dumps(
                {
                    "name": "sandbox-demo",
                    "scripts": {
                        "preinstall": "node scripts/preinstall.js",
                        "test": "node test.js",
                        "start": "node server.js",
                    },
                }
            ),
            encoding="utf-8",
        )
        (repo_path / "package-lock.json").write_text("{}", encoding="utf-8")
        (repo_path / "pyproject.toml").write_text(
            "[project]\nname = 'sandbox-demo'\nversion = '0.0.1'\n",
            encoding="utf-8",
        )
        (repo_path / "requirements.txt").write_text("pytest==8.0.0\n", encoding="utf-8")
        (repo_path / "tests").mkdir()
        (repo_path / "tests" / "test_smoke.py").write_text("def test_smoke():\n    assert True\n", encoding="utf-8")
        return repo_path

    def _write_python_build_repo(self) -> Path:
        repo_path = self.tmp_path / "python-build-demo"
        repo_path.mkdir()
        (repo_path / "pyproject.toml").write_text(
            "\n".join(
                [
                    "[build-system]",
                    "requires = ['setuptools>=68']",
                    "build-backend = 'setuptools.build_meta'",
                    "",
                    "[project]",
                    "name = 'python-build-demo'",
                    "version = '0.0.1'",
                    "[project.scripts]",
                    "demo-cli = 'demo.cli:main'",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        (repo_path / "tests").mkdir()
        (repo_path / "tests" / "test_smoke.py").write_text("def test_smoke():\n    assert True\n", encoding="utf-8")
        return repo_path

    def _write_python_scripts_repo(self) -> Path:
        repo_path = self.tmp_path / "python-scripts-demo"
        repo_path.mkdir()
        (repo_path / "pyproject.toml").write_text(
            "\n".join(
                [
                    "[build-system]",
                    "requires = ['setuptools>=68']",
                    "build-backend = 'setuptools.build_meta'",
                    "",
                    "[project]",
                    "name = 'python-scripts-demo'",
                    "version = '0.0.1'",
                    "",
                    "[project.scripts]",
                    "demo-cli = 'demo.cli:main'",
                    "test = 'demo.tests:main'",
                    "\"bad script\" = 'bash -c echo nope'",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        return repo_path

    def _write_python_local_backend_repo(self, *, dependency_line: str | None = None) -> Path:
        repo_path = self.tmp_path / "python-local-backend-demo"
        repo_path.mkdir()
        pyproject_lines = [
            "[build-system]",
            "requires = []",
            "build-backend = 'local_backend'",
            "backend-path = ['.']",
            "",
            "[project]",
            "name = 'python-local-backend-demo'",
            "version = '0.0.1'",
        ]
        if dependency_line is not None:
            pyproject_lines.extend(
                [
                    "dependencies = [",
                    f"  \"{dependency_line}\",",
                    "]",
                ]
            )
        (repo_path / "pyproject.toml").write_text("\n".join(pyproject_lines) + "\n", encoding="utf-8")
        (repo_path / "local_backend.py").write_text(
            "from pathlib import Path\n\n"
            "def build_wheel(*args, **kwargs):\n"
            "    Path('dist').mkdir(exist_ok=True)\n"
            "    return 'demo.whl'\n",
            encoding="utf-8",
        )
        return repo_path

    def _write_poetry_lock_repo(self) -> Path:
        repo_path = self.tmp_path / "poetry-lock-demo"
        repo_path.mkdir()
        (repo_path / "pyproject.toml").write_text(
            "[project]\nname = 'poetry-lock-demo'\nversion = '0.0.1'\n",
            encoding="utf-8",
        )
        (repo_path / "poetry.lock").write_text(
            "\n".join(
                [
                    "[[package]]",
                    "name = 'requests'",
                    "version = '2.31.0'",
                    "",
                    "[[package]]",
                    "name = 'demo-local'",
                    "version = '0.1.0'",
                    "[package.source]",
                    "type = 'directory'",
                    "url = '../demo-local'",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        return repo_path

    def _write_uv_lock_repo(self) -> Path:
        repo_path = self.tmp_path / "uv-lock-demo"
        repo_path.mkdir()
        (repo_path / "pyproject.toml").write_text(
            "[project]\nname = 'uv-lock-demo'\nversion = '0.0.1'\n",
            encoding="utf-8",
        )
        (repo_path / "uv.lock").write_text(
            "\n".join(
                [
                    "version = 1",
                    "",
                    "[[package]]",
                    "name = 'click'",
                    "version = '8.1.7'",
                    "source = { registry = 'https://pypi.org/simple' }",
                    "",
                    "[[package]]",
                    "name = 'editable-demo'",
                    "version = '0.0.1'",
                    "source = { editable = '.' }",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        return repo_path

    def _write_ambiguous_python_lock_repo(self) -> Path:
        repo_path = self.tmp_path / "ambiguous-lock-demo"
        repo_path.mkdir()
        (repo_path / "pyproject.toml").write_text(
            "[project]\nname = 'ambiguous-lock-demo'\nversion = '0.0.1'\n",
            encoding="utf-8",
        )
        (repo_path / "poetry.lock").write_text(
            "[[package]]\nname = 'requests'\nversion = '2.31.0'\n",
            encoding="utf-8",
        )
        (repo_path / "uv.lock").write_text(
            "version = 1\n\n[[package]]\nname = 'click'\nversion = '8.1.7'\nsource = { registry = 'https://pypi.org/simple' }\n",
            encoding="utf-8",
        )
        return repo_path

    def _write_materialization_repo(self) -> Path:
        repo_path = self.tmp_path / "materialization-demo"
        repo_path.mkdir()
        (repo_path / "keep.txt").write_text("keep\n", encoding="utf-8")
        (repo_path / ".env").write_text("SECRET=***REDACTED***\n", encoding="utf-8")
        (repo_path / ".npmrc").write_text("//registry.npmjs.org/:_authToken=***REDACTED***\n", encoding="utf-8")
        (repo_path / ".pypirc").write_text("[distutils]\nindex-servers=pypi\n", encoding="utf-8")
        (repo_path / ".netrc").write_text("machine example.com login demo password ***REDACTED***\n", encoding="utf-8")
        (repo_path / ".git").mkdir()
        (repo_path / ".git" / "config").write_text("[core]\nrepositoryformatversion = 0\n", encoding="utf-8")
        (repo_path / ".venv").mkdir()
        (repo_path / ".venv" / "ignored.txt").write_text("ignored\n", encoding="utf-8")
        (repo_path / "node_modules").mkdir()
        (repo_path / "node_modules" / "ignored.js").write_text("ignored\n", encoding="utf-8")
        (repo_path / "__pycache__").mkdir()
        (repo_path / "__pycache__" / "module.pyc").write_bytes(b"pyc")
        (repo_path / ".aws").mkdir()
        (repo_path / ".aws" / "credentials").write_text("[default]\naws_access_key_id = ***REDACTED***\n", encoding="utf-8")
        (repo_path / ".ssh").mkdir()
        (repo_path / ".ssh" / "id_rsa").write_text("***REDACTED***\n", encoding="utf-8")
        outside_target = self.tmp_path / "outside.txt"
        outside_target.write_text("outside\n", encoding="utf-8")
        try:
            os.symlink(outside_target, repo_path / "escape-link")
        except OSError:
            self.skipTest("symlink creation is unavailable on this platform")
        return repo_path

    @staticmethod
    def _successful_preflight_result() -> dict[str, object]:
        return {
            "requested": True,
            "performed": True,
            "status": "passed",
            "timeout_seconds": 7,
            "commands": [],
            "results": [],
            "limitations": [],
            "phase_gate_limitations": [],
        }

    @staticmethod
    def _successful_phase1_result() -> dict[str, object]:
        return {
            "requested": True,
            "performed": True,
            "status": "passed",
            "network_mode": "bridge",
            "timeout_seconds": 11,
            "results": [],
            "limitations": [],
            "phase_gate_limitations": [],
        }

    @staticmethod
    def _successful_rescan_result() -> dict[str, object]:
        return {
            "requested": True,
            "performed": True,
            "status": "passed",
            "artifact_summary": {
                "scanned_file_count": 1,
                "artifact_candidate_count": 1,
                "read_error_count": 0,
                "artifact_kind_counts": {
                    "node_package_manifest": 1,
                    "node_package_archive": 0,
                    "python_archive": 0,
                    "plain_text_artifact": 0,
                },
            },
            "finding_summary": {
                "blocked_count": 0,
                "warn_count": 0,
                "info_count": 0,
                "unknown_count": 0,
            },
            "findings": [],
            "blocked_findings": [],
            "warn_findings": [],
            "info_findings": [],
            "unknown_findings": [],
            "ordinary_library_capabilities": [],
            "install_time_risks": [],
            "dependency_source_risks": [],
            "limitations": [],
            "residual_risks": [],
        }

    @staticmethod
    def _fully_ready_observer() -> dict[str, object]:
        return {
            "mode": "strace+runtime_hook",
            "status": "ready",
            "languages": ["python"],
            "syscall_observer": {
                "kind": "strace",
                "available": True,
                "active": True,
                "binary_name": "strace",
                "limitations": [],
            },
            "runtime_hooks": [],
            "runtime_hook_active_languages": ["python"],
            "pass_possible": True,
            "event_sink": "/tmp/tmp/rhd-observer-events.jsonl",
            "phase2_ready": True,
            "phase3_ready": True,
            "limitations": [],
        }

    def test_sandbox_parser_exists(self) -> None:
        parser = build_parser("sandbox")
        args = parser.parse_args(
            [
                ".",
                "--format",
                "json",
                "--run-preflight",
                "--run-strace-smoke",
                "--docker-image",
                "example@sha256:abc",
                "--allow-local-image",
                "--expected-image-id",
                self.LOCAL_IMAGE_ID,
                "--preflight-timeout-seconds",
                "5",
                "--run-phase1",
                "--phase1-timeout-seconds",
                "9",
                "--run-phase2",
                "--run-phase3",
                "--dynamic-timeout-seconds",
                "13",
            ]
        )
        self.assertEqual(args.path, ".")
        self.assertEqual(args.format, "json")
        self.assertTrue(args.run_preflight)
        self.assertTrue(args.run_strace_smoke)
        self.assertEqual(args.docker_image, "example@sha256:abc")
        self.assertTrue(args.allow_local_image)
        self.assertEqual(args.expected_image_id, self.LOCAL_IMAGE_ID)
        self.assertEqual(args.preflight_timeout_seconds, 5)
        self.assertTrue(args.run_phase1)
        self.assertEqual(args.phase1_timeout_seconds, 9)
        self.assertTrue(args.run_phase2)
        self.assertTrue(args.run_phase3)
        self.assertEqual(args.dynamic_timeout_seconds, 13)

    def test_run_sandbox_returns_plan_only_report(self) -> None:
        repo_path = self._write_demo_repo()
        report = run_sandbox(repo_path)

        self.assertEqual(report["report_kind"], REPORT_KIND_SANDBOX)
        self.assertEqual(report["execution_plan"]["mode"], "plan_only")
        self.assertEqual(report["overall_status"], "warn")
        self.assertFalse(report["execution_plan"]["approval"]["provided"])
        self.assertIn("dynamic_observation_degraded", report["residual_risks"])
        self.assertEqual(report["sandbox"]["preflight"]["status"], "not_requested")
        self.assertEqual(report["sandbox"]["strace_target_wrap_smoke"]["status"], "not_requested")
        self.assertEqual(report["sandbox"]["phase1_fetch"]["status"], "not_requested")
        self.assertEqual(report["sandbox"]["phase2_install_probes"]["status"], "not_requested")
        self.assertEqual(report["sandbox"]["phase3_runtime_probes"]["status"], "not_requested")

    def test_execution_plan_uses_normalized_argv_form(self) -> None:
        repo_path = self._write_demo_repo()
        report = run_sandbox(repo_path)
        commands = report["execution_plan"]["commands"]

        self.assertGreaterEqual(len(commands), 3)
        for command in commands:
            self.assertIn("argv", command)
            self.assertIsInstance(command["argv"], list)
            self.assertTrue(command["argv"])
            self.assertFalse(command["shell"])
            self.assertNotIn("command", command)
            self.assertEqual(command["cwd"], ".")

    def test_python_build_metadata_generates_phase2_install_probe_candidates(self) -> None:
        repo_path = self._write_python_build_repo()
        report = run_sandbox(repo_path)
        phase2_commands = [
            command for command in report["execution_plan"]["commands"] if command["phase"] == "phase2_install_probe"
        ]
        skipped_reasons = {item["reason"] for item in report["execution_plan"]["skipped_commands"]}

        self.assertEqual({command["kind"] for command in phase2_commands}, {"editable_install_probe", "install_script_probe"})
        self.assertIn(
            ["python", "-m", "pip", "install", "--no-deps", "--no-build-isolation", "."],
            [command["argv"] for command in phase2_commands],
        )
        self.assertIn(
            ["python", "-m", "pip", "install", "--no-deps", "--no-build-isolation", "-e", "."],
            [command["argv"] for command in phase2_commands],
        )
        self.assertNotIn("python_install_probe_not_implemented_in_slice1", skipped_reasons)

    def test_python_project_scripts_generate_runtime_candidates_and_skip_unsafe_entries(self) -> None:
        repo_path = self._write_python_scripts_repo()
        report = run_sandbox(repo_path)
        runtime_commands = [
            command for command in report["execution_plan"]["commands"] if command["phase"] == "phase3_runtime_probe"
        ]
        skipped_commands = [
            command for command in report["execution_plan"]["skipped_commands"] if command.get("phase") == "phase3_runtime_probe"
        ]
        discovery_check = next(item for item in report["checks"] if item["id"] == "sandbox.discovery")

        self.assertIn(["demo-cli"], [command["argv"] for command in runtime_commands])
        self.assertIn(["test"], [command["argv"] for command in runtime_commands])
        self.assertIn("runtime candidates", " ".join(discovery_check["limitations"]).lower())
        self.assertIn("unsafe_or_ambiguous", {command["reason"] for command in skipped_commands})

    def test_approval_file_without_exact_match_does_not_approve_commands(self) -> None:
        repo_path = self._write_demo_repo()
        approval_path = self.tmp_path / "approvals.json"
        approval_path.write_text(
            json.dumps(
                {
                    "commands": [
                        {
                            "phase": "phase3_runtime_probe",
                            "kind": "test_probe",
                            "cwd": ".",
                            "argv": ["python", "-m", "pytest", "-q"],
                            "env_allowlist": [],
                            "shell": False,
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        report = run_sandbox(repo_path, approval_file=approval_path)
        commands = report["execution_plan"]["commands"]
        skipped = report["execution_plan"]["skipped_commands"]

        self.assertTrue(all(not command["approved"] for command in commands))
        self.assertIn("approval_mismatch", {item["reason"] for item in skipped})
        self.assertEqual(report["execution_plan"]["approval"]["status"], "partial")

    def test_approval_file_marks_exact_match_as_approved(self) -> None:
        repo_path = self._write_demo_repo()
        baseline = run_sandbox(repo_path)
        first_command = baseline["execution_plan"]["commands"][0]
        approval_path = self.tmp_path / "approved.json"
        approval_path.write_text(json.dumps({"commands": [first_command]}), encoding="utf-8")

        report = run_sandbox(repo_path, approval_file=approval_path)
        commands = report["execution_plan"]["commands"]

        self.assertTrue(any(command["approved"] for command in commands))
        self.assertEqual(report["execution_plan"]["approval"]["matched_command_count"], 1)
        self.assertEqual(report["execution_plan"]["approval"]["status"], "partial")

    def test_phase2_approval_fixture_matches_controlled_candidate_plan_only(self) -> None:
        repo_path = self._fixture_path("sandbox-phase2-python-build")
        approval_path = self._fixture_path("approvals/phase2-python-build-install.json")

        with mock.patch(
            "repo_health_doctor.sandbox.docker.subprocess.run",
            return_value=self._docker_inspect_result(self.LOCAL_IMAGE_ID),
        ):
            report = run_sandbox(
                repo_path,
                approval_file=approval_path,
                docker_image="rhd-python312-strace:local",
                allow_local_image=True,
                expected_image_id=self.LOCAL_IMAGE_ID,
            )

        commands = report["execution_plan"]["commands"]
        approved_phase2 = [
            command
            for command in commands
            if command["phase"] == "phase2_install_probe" and command["approved"]
        ]
        approval = report["execution_plan"]["approval"]
        payload = json.dumps(report)

        self.assertEqual(len(approved_phase2), 1)
        self.assertEqual(approved_phase2[0]["kind"], "install_script_probe")
        self.assertEqual(approved_phase2[0]["cwd"], ".")
        self.assertEqual(
            approved_phase2[0]["argv"],
            ["python", "-m", "pip", "install", "--no-deps", "--no-build-isolation", "."],
        )
        self.assertEqual(approved_phase2[0]["env_allowlist"], [])
        self.assertFalse(approved_phase2[0]["shell"])
        self.assertEqual(approval["status"], "partial")
        self.assertEqual(approval["matched_command_count"], 1)
        self.assertEqual(approval["path_handle"], "tests/fixtures/approvals/phase2-python-build-install.json")
        self.assertEqual(approval["docker_image"], "rhd-python312-strace:local")
        self.assertEqual(approval["expected_image_id"], self.LOCAL_IMAGE_ID)
        self.assertTrue(approval["local_sanctioned_image"])
        self.assertEqual(approval["network_policy"], "none")
        self.assertEqual(approval["approval_scope"]["kind"], "controlled_fixture_only")
        self.assertNotIn(str(approval_path.resolve()), payload)
        self.assertNotIn(str(repo_path.resolve()), payload)

    def test_phase2_approval_rejects_cwd_mismatch(self) -> None:
        repo_path = self._fixture_path("sandbox-phase2-python-build")
        approval_path = self.tmp_path / "cwd-mismatch.json"
        approval_path.write_text(
            json.dumps(
                {
                    "commands": [
                        {
                            "phase": "phase2_install_probe",
                            "kind": "install_script_probe",
                            "cwd": "subdir",
                            "argv": ["python", "-m", "pip", "install", "--no-deps", "--no-build-isolation", "."],
                            "env_allowlist": [],
                            "shell": False,
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        report = run_sandbox(repo_path, approval_file=approval_path)

        self.assertEqual(report["execution_plan"]["approval"]["matched_command_count"], 0)
        self.assertIn("approval_mismatch", {item["reason"] for item in report["execution_plan"]["skipped_commands"]})

    def test_phase2_approval_rejects_env_allowlist_expansion(self) -> None:
        repo_path = self._fixture_path("sandbox-phase2-python-build")
        approval_path = self.tmp_path / "env-allowlist-mismatch.json"
        approval_path.write_text(
            json.dumps(
                {
                    "commands": [
                        {
                            "phase": "phase2_install_probe",
                            "kind": "install_script_probe",
                            "cwd": ".",
                            "argv": ["python", "-m", "pip", "install", "--no-deps", "--no-build-isolation", "."],
                            "env_allowlist": ["HOME"],
                            "shell": False,
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        report = run_sandbox(repo_path, approval_file=approval_path)

        self.assertEqual(report["execution_plan"]["approval"]["matched_command_count"], 0)
        self.assertIn("approval_mismatch", {item["reason"] for item in report["execution_plan"]["skipped_commands"]})

    def test_phase2_approval_rejects_image_id_mismatch(self) -> None:
        repo_path = self._fixture_path("sandbox-phase2-python-build")
        approval_path = self._fixture_path("approvals/phase2-python-build-install.json")
        mismatch_id = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

        with mock.patch(
            "repo_health_doctor.sandbox.docker.subprocess.run",
            return_value=self._docker_inspect_result(self.LOCAL_IMAGE_ID),
        ):
            report = run_sandbox(
                repo_path,
                approval_file=approval_path,
                docker_image="rhd-python312-strace:local",
                allow_local_image=True,
                expected_image_id=mismatch_id,
            )

        approval = report["execution_plan"]["approval"]
        self.assertEqual(approval["status"], "invalid")
        self.assertIn("approval_expected_image_id_mismatch", approval["mismatch_reasons"])

    def test_phase2_approval_rejects_scope_outside_fixture(self) -> None:
        repo_path = self._fixture_path("sandbox-phase2-python-build")
        approval_path = self.tmp_path / "scope-mismatch.json"
        approval_path.write_text(
            json.dumps(
                {
                    "approval_contract": {
                        "approval_scope": {
                            "kind": "controlled_fixture_only",
                            "repo_path": "../wrong-fixture",
                        }
                    },
                    "commands": [
                        {
                            "phase": "phase2_install_probe",
                            "kind": "install_script_probe",
                            "cwd": ".",
                            "argv": ["python", "-m", "pip", "install", "--no-deps", "--no-build-isolation", "."],
                            "env_allowlist": [],
                            "shell": False,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        report = run_sandbox(repo_path, approval_file=approval_path)

        approval = report["execution_plan"]["approval"]
        self.assertEqual(approval["status"], "invalid")
        self.assertIn("approval_scope_mismatch", approval["mismatch_reasons"])

    def test_phase2_local_backend_fixture_generates_plan_only_candidates_without_fetch_plan(self) -> None:
        repo_path = self._fixture_path("sandbox-phase2-python-local-backend")

        report = run_sandbox(repo_path)

        commands = report["execution_plan"]["commands"]
        phase2_commands = [item for item in commands if item["phase"] == "phase2_install_probe"]
        phase1_plan = next(item for item in report["phase_plan"] if item["phase"] == "phase1_fetch")
        phase1 = report["sandbox"]["phase1_fetch"]
        phase1_5 = report["sandbox"]["phase1_5_rescan"]
        phase2 = report["sandbox"]["phase2_install_probes"]

        self.assertEqual(len(phase2_commands), 2)
        self.assertEqual({item["kind"] for item in phase2_commands}, {"install_script_probe", "editable_install_probe"})
        self.assertEqual(phase1["status"], "not_required")
        self.assertFalse(phase1["performed"])
        self.assertEqual(phase1_5["status"], "not_required")
        self.assertFalse(phase1_5["performed"])
        self.assertFalse(phase2["performed"])
        self.assertIn("Phase 2 prior-phase dependency gate is cleared", " ".join(phase2["limitations"]))
        self.assertEqual(phase1_plan["status"], "not_required")
        self.assertEqual(phase1_plan["commands"], [])
        self.assertEqual(phase1_plan["skipped_commands"], [])
        self.assertFalse(phase1_plan["execution_enabled"])
        self.assertIn(
            "skipped-safe: Phase 1 external dependency fetch is not_required",
            " ".join(phase1_plan["limitations"]),
        )

    def test_phase2_local_backend_approval_fixture_matches_plan_only_candidate(self) -> None:
        repo_path = self._fixture_path("sandbox-phase2-python-local-backend")
        approval_path = self._fixture_path("approvals/phase2-python-local-backend-install.json")

        with mock.patch(
            "repo_health_doctor.sandbox.docker.subprocess.run",
            return_value=self._docker_inspect_result(self.LOCAL_IMAGE_ID),
        ):
            report = run_sandbox(
                repo_path,
                approval_file=approval_path,
                docker_image="rhd-python312-strace:local",
                allow_local_image=True,
                expected_image_id=self.LOCAL_IMAGE_ID,
            )

        approved_phase2 = [
            command
            for command in report["execution_plan"]["commands"]
            if command["phase"] == "phase2_install_probe" and command["approved"]
        ]
        approval = report["execution_plan"]["approval"]

        self.assertEqual(len(approved_phase2), 1)
        self.assertEqual(approved_phase2[0]["kind"], "install_script_probe")
        self.assertEqual(
            approved_phase2[0]["argv"],
            ["python", "-m", "pip", "install", "--no-deps", "--no-build-isolation", "."],
        )
        self.assertEqual(approval["status"], "partial")
        self.assertEqual(approval["matched_command_count"], 1)
        self.assertEqual(
            approval["path_handle"],
            "tests/fixtures/approvals/phase2-python-local-backend-install.json",
        )
        self.assertEqual(approval["approval_scope"]["kind"], "controlled_fixture_only")

    def test_phase2_local_backend_not_required_gate_stops_at_approval_without_live_execution(self) -> None:
        repo_path = self._fixture_path("sandbox-phase2-python-local-backend")

        with mock.patch(
            "repo_health_doctor.sandbox.command.run_docker_preflight",
            return_value=self._successful_preflight_result(),
        ), mock.patch(
            "repo_health_doctor.sandbox.command.build_observer_plan",
            return_value=self._fully_ready_observer(),
        ), mock.patch("repo_health_doctor.sandbox.command.run_dynamic_phase") as mocked_dynamic_run:
            report = run_sandbox(
                repo_path,
                docker_image="python:3.12-slim-bookworm@sha256:0123456789abcdef",
                run_preflight=True,
                run_phase2=True,
            )

        phase1 = report["sandbox"]["phase1_fetch"]
        phase1_5 = report["sandbox"]["phase1_5_rescan"]
        phase2 = report["sandbox"]["phase2_install_probes"]

        self.assertFalse(mocked_dynamic_run.called)
        self.assertEqual(phase1["status"], "not_required")
        self.assertEqual(phase1_5["status"], "not_required")
        self.assertEqual(phase2["status"], "skipped")
        self.assertFalse(phase2["performed"])
        self.assertIn("Phase 2 prior-phase dependency gate is cleared", " ".join(phase2["limitations"]))
        self.assertIn("explicitly approved install-script command", " ".join(phase2["limitations"]))

    def test_phase2_local_backend_not_required_gate_does_not_clear_with_direct_url_dependency(self) -> None:
        repo_path = self._write_python_local_backend_repo(dependency_line="demo @ https://example.test/demo.whl")

        with mock.patch(
            "repo_health_doctor.sandbox.command.run_docker_preflight",
            return_value=self._successful_preflight_result(),
        ), mock.patch(
            "repo_health_doctor.sandbox.command.build_observer_plan",
            return_value=self._fully_ready_observer(),
        ), mock.patch("repo_health_doctor.sandbox.command.run_dynamic_phase") as mocked_dynamic_run:
            report = run_sandbox(
                repo_path,
                docker_image="python:3.12-slim-bookworm@sha256:0123456789abcdef",
                run_preflight=True,
                run_phase2=True,
            )

        phase1 = report["sandbox"]["phase1_fetch"]
        phase1_plan = next(item for item in report["phase_plan"] if item["phase"] == "phase1_fetch")
        phase2 = report["sandbox"]["phase2_install_probes"]

        self.assertFalse(mocked_dynamic_run.called)
        self.assertEqual(phase1["status"], "not_requested")
        self.assertIn("unsupported_python_dependency_source", {item["reason"] for item in phase1_plan["skipped_commands"]})
        self.assertEqual(phase2["status"], "skipped")
        self.assertNotIn("Phase 2 prior-phase dependency gate is cleared", " ".join(phase2["limitations"]))
        self.assertIn("successful Phase 1 dependency fetch", " ".join(phase2["limitations"]))

    def test_phase3_approval_fixture_matches_controlled_candidate_plan_only(self) -> None:
        repo_path = self._fixture_path("sandbox-phase3-python-runtime")
        approval_path = self._fixture_path("approvals/phase3-python-runtime-test.json")

        with mock.patch(
            "repo_health_doctor.sandbox.docker.subprocess.run",
            return_value=self._docker_inspect_result(self.LOCAL_IMAGE_ID),
        ):
            report = run_sandbox(
                repo_path,
                approval_file=approval_path,
                docker_image="rhd-python312-strace:local",
                allow_local_image=True,
                expected_image_id=self.LOCAL_IMAGE_ID,
            )

        commands = report["execution_plan"]["commands"]
        approved_phase3 = [
            command
            for command in commands
            if command["phase"] == "phase3_runtime_probe" and command["approved"]
        ]
        approval = report["execution_plan"]["approval"]
        payload = json.dumps(report)

        self.assertEqual(len(commands), 1)
        self.assertEqual(len(approved_phase3), 1)
        self.assertEqual(approved_phase3[0]["kind"], "test_probe")
        self.assertEqual(approved_phase3[0]["cwd"], ".")
        self.assertEqual(approved_phase3[0]["argv"], self.PHASE3_RUNTIME_FIXTURE_ARGV)
        self.assertEqual(approved_phase3[0]["env_allowlist"], [])
        self.assertFalse(approved_phase3[0]["shell"])
        self.assertEqual(approved_phase3[0]["evidence"]["source"], "controlled_fixture_runtime_probe")
        self.assertEqual(approval["status"], "matched")
        self.assertEqual(approval["matched_command_count"], 1)
        self.assertEqual(approval["path_handle"], "tests/fixtures/approvals/phase3-python-runtime-test.json")
        self.assertEqual(approval["docker_image"], "rhd-python312-strace:local")
        self.assertEqual(approval["expected_image_id"], self.LOCAL_IMAGE_ID)
        self.assertTrue(approval["local_sanctioned_image"])
        self.assertEqual(approval["network_policy"], "none")
        self.assertEqual(approval["approval_scope"]["kind"], "controlled_fixture_only")
        self.assertEqual(report["sandbox"]["phase1_fetch"]["status"], "not_required")
        self.assertEqual(report["sandbox"]["phase1_5_rescan"]["status"], "not_required")
        self.assertEqual(report["sandbox"]["phase3_runtime_probes"]["status"], "not_requested")
        self.assertFalse(report["sandbox"]["phase3_runtime_probes"]["performed"])
        self.assertNotIn(str(approval_path.resolve()), payload)
        self.assertNotIn(str(repo_path.resolve()), payload)

    def test_phase3_controlled_fixture_runs_after_safe_no_fetch_bypass(self) -> None:
        repo_path = self._fixture_path("sandbox-phase3-python-runtime")
        approval_path = self._fixture_path("approvals/phase3-python-runtime-test.json")
        dynamic_result = {
            "requested": True,
            "performed": True,
            "status": "passed",
            "network_mode": "none",
            "timeout_seconds": 60,
            "approved_command_count": 1,
            "results": [],
            "limitations": [],
        }

        with mock.patch(
            "repo_health_doctor.sandbox.docker.subprocess.run",
            return_value=self._docker_inspect_result(self.LOCAL_IMAGE_ID),
        ), mock.patch(
            "repo_health_doctor.sandbox.command.run_docker_preflight",
            return_value=self._successful_preflight_result(),
        ), mock.patch(
            "repo_health_doctor.sandbox.command.build_observer_plan",
            return_value=self._fully_ready_observer(),
        ), mock.patch(
            "repo_health_doctor.sandbox.command.run_dynamic_phase",
            return_value=dynamic_result,
        ) as mocked_dynamic_run:
            report = run_sandbox(
                repo_path,
                approval_file=approval_path,
                docker_image="rhd-python312-strace:local",
                allow_local_image=True,
                expected_image_id=self.LOCAL_IMAGE_ID,
                run_preflight=True,
                run_phase3=True,
            )

        phase2 = report["sandbox"]["phase2_install_probes"]
        phase3 = report["sandbox"]["phase3_runtime_probes"]
        self.assertFalse(phase2["requested"])
        self.assertFalse(phase2["performed"])
        self.assertEqual(phase3["status"], "passed")
        self.assertTrue(phase3["performed"])
        self.assertEqual(mocked_dynamic_run.call_count, 1)
        commands = mocked_dynamic_run.call_args.kwargs["commands"]
        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0]["phase"], "phase3_runtime_probe")
        self.assertEqual(commands[0]["argv"], self.PHASE3_RUNTIME_FIXTURE_ARGV)
        self.assertFalse(commands[0]["shell"])

    def test_phase3_approval_rejects_argv_mismatch(self) -> None:
        repo_path = self._fixture_path("sandbox-phase3-python-runtime")
        approval_path = self.tmp_path / "phase3-argv-mismatch.json"
        approval_path.write_text(
            json.dumps({"commands": [self._phase3_runtime_fixture_command(argv=["demo-cli"])]}),
            encoding="utf-8",
        )

        report = run_sandbox(repo_path, approval_file=approval_path)

        self.assertEqual(report["execution_plan"]["approval"]["matched_command_count"], 0)
        self.assertIn("approval_mismatch", {item["reason"] for item in report["execution_plan"]["skipped_commands"]})

    def test_phase3_approval_rejects_cwd_mismatch(self) -> None:
        repo_path = self._fixture_path("sandbox-phase3-python-runtime")
        approval_path = self.tmp_path / "phase3-cwd-mismatch.json"
        approval_path.write_text(
            json.dumps({"commands": [self._phase3_runtime_fixture_command(cwd="subdir")]}),
            encoding="utf-8",
        )

        report = run_sandbox(repo_path, approval_file=approval_path)

        self.assertEqual(report["execution_plan"]["approval"]["matched_command_count"], 0)
        self.assertIn("approval_mismatch", {item["reason"] for item in report["execution_plan"]["skipped_commands"]})

    def test_phase3_approval_rejects_env_allowlist_expansion(self) -> None:
        repo_path = self._fixture_path("sandbox-phase3-python-runtime")
        approval_path = self.tmp_path / "phase3-env-mismatch.json"
        approval_path.write_text(
            json.dumps({"commands": [self._phase3_runtime_fixture_command(env_allowlist=["HOME"])]}),
            encoding="utf-8",
        )

        report = run_sandbox(repo_path, approval_file=approval_path)

        self.assertEqual(report["execution_plan"]["approval"]["matched_command_count"], 0)
        self.assertIn("approval_mismatch", {item["reason"] for item in report["execution_plan"]["skipped_commands"]})

    def test_phase3_approval_rejects_phase_mismatch(self) -> None:
        repo_path = self._fixture_path("sandbox-phase3-python-runtime")
        approval_path = self.tmp_path / "phase3-phase-mismatch.json"
        approval_path.write_text(
            json.dumps({"commands": [self._phase3_runtime_fixture_command(phase="phase2_install_probe")]}),
            encoding="utf-8",
        )

        report = run_sandbox(repo_path, approval_file=approval_path)

        self.assertEqual(report["execution_plan"]["approval"]["matched_command_count"], 0)
        self.assertIn("approval_mismatch", {item["reason"] for item in report["execution_plan"]["skipped_commands"]})

    def test_phase3_approval_rejects_shell_true(self) -> None:
        repo_path = self._fixture_path("sandbox-phase3-python-runtime")
        approval_path = self.tmp_path / "phase3-shell.json"
        approval_path.write_text(
            json.dumps({"commands": [self._phase3_runtime_fixture_command(shell=True)]}),
            encoding="utf-8",
        )

        report = run_sandbox(repo_path, approval_file=approval_path)

        self.assertEqual(report["execution_plan"]["approval"]["matched_command_count"], 0)
        self.assertIn("unsafe_or_ambiguous", {item["reason"] for item in report["execution_plan"]["skipped_commands"]})

    def test_phase3_approval_rejects_image_id_mismatch(self) -> None:
        repo_path = self._fixture_path("sandbox-phase3-python-runtime")
        approval_path = self._fixture_path("approvals/phase3-python-runtime-test.json")
        mismatch_id = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

        with mock.patch(
            "repo_health_doctor.sandbox.docker.subprocess.run",
            return_value=self._docker_inspect_result(self.LOCAL_IMAGE_ID),
        ):
            report = run_sandbox(
                repo_path,
                approval_file=approval_path,
                docker_image="rhd-python312-strace:local",
                allow_local_image=True,
                expected_image_id=mismatch_id,
            )

        approval = report["execution_plan"]["approval"]
        self.assertEqual(approval["status"], "invalid")
        self.assertIn("approval_expected_image_id_mismatch", approval["mismatch_reasons"])

    def test_phase2_approval_fixture_is_not_reusable_for_phase3_controlled_fixture(self) -> None:
        repo_path = self._fixture_path("sandbox-phase3-python-runtime")
        approval_path = self._fixture_path("approvals/phase2-python-build-install.json")

        with mock.patch(
            "repo_health_doctor.sandbox.docker.subprocess.run",
            return_value=self._docker_inspect_result(self.LOCAL_IMAGE_ID),
        ):
            report = run_sandbox(
                repo_path,
                approval_file=approval_path,
                docker_image="rhd-python312-strace:local",
                allow_local_image=True,
                expected_image_id=self.LOCAL_IMAGE_ID,
            )

        approval = report["execution_plan"]["approval"]
        self.assertEqual(approval["status"], "invalid")
        self.assertIn("approval_scope_mismatch", approval["mismatch_reasons"])
        self.assertEqual(approval["matched_command_count"], 0)

    def test_phase2_approval_does_not_authorize_phase3_commands(self) -> None:
        repo_path = self._write_python_build_repo()
        baseline = run_sandbox(repo_path)
        approved_install = next(
            command
            for command in baseline["execution_plan"]["commands"]
            if command["phase"] == "phase2_install_probe" and command["kind"] == "install_script_probe"
        )
        approval_path = self.tmp_path / "approved-phase2-only.json"
        approval_path.write_text(json.dumps({"commands": [approved_install]}), encoding="utf-8")

        report = run_sandbox(repo_path, approval_file=approval_path)

        phase2_commands = [item for item in report["execution_plan"]["commands"] if item["phase"] == "phase2_install_probe"]
        phase3_commands = [item for item in report["execution_plan"]["commands"] if item["phase"] == "phase3_runtime_probe"]
        self.assertTrue(any(item["approved"] for item in phase2_commands))
        self.assertTrue(all(not item["approved"] for item in phase3_commands))

    def test_shell_true_approval_is_skipped(self) -> None:
        repo_path = self._write_demo_repo()
        approval_path = self.tmp_path / "shell.json"
        approval_path.write_text(
            json.dumps(
                {
                    "commands": [
                        {
                            "phase": "phase3_runtime_probe",
                            "kind": "runtime_smoke",
                            "cwd": ".",
                            "argv": ["npm", "start"],
                            "env_allowlist": [],
                            "shell": True,
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        report = run_sandbox(repo_path, approval_file=approval_path)
        skipped = report["execution_plan"]["skipped_commands"]

        self.assertIn("unsafe_or_ambiguous", {item["reason"] for item in skipped})
        self.assertEqual(report["overall_status"], "warn")

    def test_explicit_shell_script_detection_is_skipped(self) -> None:
        repo_path = self.tmp_path / "shell-scripts"
        repo_path.mkdir()
        (repo_path / "package.json").write_text(
            json.dumps(
                {
                    "name": "shell-scripts",
                    "scripts": {
                        "postinstall": "bash -c 'echo hi'",
                        "test": "sh -c 'echo test'",
                    },
                }
            ),
            encoding="utf-8",
        )

        report = run_sandbox(repo_path)
        skipped = report["execution_plan"]["skipped_commands"]

        self.assertIn("unsafe_or_ambiguous", {item["reason"] for item in skipped})
        self.assertEqual(report["execution_plan"]["commands"], [])

    def test_whitespace_shell_script_variants_are_skipped(self) -> None:
        repo_path = self.tmp_path / "shell-whitespace-scripts"
        repo_path.mkdir()
        (repo_path / "package.json").write_text(
            json.dumps(
                {
                    "name": "shell-whitespace-scripts",
                    "scripts": {
                        "postinstall": "/bin/sh\t-c 'echo install'",
                        "test": "bash\t-c 'echo test'",
                    },
                }
            ),
            encoding="utf-8",
        )

        report = run_sandbox(repo_path)
        skipped = report["execution_plan"]["skipped_commands"]

        self.assertIn("script:postinstall", {item.get("detail") for item in skipped})
        self.assertIn("script:test", {item.get("detail") for item in skipped})
        self.assertTrue(all(item["reason"] == "unsafe_or_ambiguous" for item in skipped))

    def test_sandbox_report_contains_required_contract_fields(self) -> None:
        repo_path = self._write_demo_repo()
        report = run_sandbox(repo_path)

        for check in report["checks"]:
            self.assertIn("confidence", check)
            self.assertIn("limitations", check)
            self.assertIn("severity_detail", check)
        self.assertIn("residual_risks", report)
        self.assertTrue(report["residual_risks"])
        self.assertIn("phase_plan", report)
        self.assertIn("docker_spec", report["sandbox"])
        self.assertIn("disposable_workspace", report["sandbox"])
        self.assertIn("phase1_5_rescan", report["sandbox"])
        self.assertIn("observer", report["sandbox"])
        dynamic_evidence = report["sandbox"]["dynamic_evidence"]
        self.assertEqual(dynamic_evidence["observer_mode"], "runtime_hook")
        self.assertEqual(dynamic_evidence["confidence"], "low")
        self.assertIn("phase2", dynamic_evidence["phase_statuses"])
        self.assertIn("phase3", dynamic_evidence["phase_statuses"])
        self.assertIn("event_counts", dynamic_evidence)
        self.assertIn("syscall_trace", dynamic_evidence)
        self.assertTrue(dynamic_evidence["limitations"])
        self.assertTrue(dynamic_evidence["degraded_reasons"])
        self.assertIn("phase2_install_probes", report["sandbox"])
        self.assertIn("phase3_runtime_probes", report["sandbox"])
        self.assertIn("honeypots", report["sandbox"]["disposable_workspace"])

    def test_docker_spec_uses_argv_and_isolation_flags(self) -> None:
        repo_path = self._write_demo_repo()
        report = run_sandbox(repo_path)
        docker_spec = report["sandbox"]["docker_spec"]
        argv = docker_spec["argv"]

        self.assertIsInstance(argv, list)
        self.assertIn("--rm", argv)
        self.assertIn("--network", argv)
        self.assertIn("none", argv)
        self.assertIn("--cap-drop", argv)
        self.assertIn("ALL", argv)
        self.assertIn("--security-opt", argv)
        self.assertIn("no-new-privileges", argv)
        self.assertIn("--read-only", argv)
        self.assertIn("--user", argv)
        self.assertIn(default_docker_user(), argv)
        self.assertIn("--pull=never", argv)
        self.assertFalse(docker_spec["shell"])
        self.assertNotIn(" ".join(argv), argv)
        self.assertEqual(docker_spec["user"], default_docker_user())

    def test_docker_spec_does_not_mount_host_home_or_socket(self) -> None:
        repo_path = self._write_demo_repo()
        report = run_sandbox(repo_path)
        docker_spec = report["sandbox"]["docker_spec"]
        argv_text = "\n".join(docker_spec["argv"])

        self.assertFalse(docker_spec["docker_socket_mounted"])
        self.assertFalse(docker_spec["host_home_mounted"])
        self.assertNotIn("/var/run/docker.sock", argv_text)
        self.assertNotIn(str(Path.home()), argv_text)

    def test_disposable_workspace_plan_uses_logical_paths_and_redaction(self) -> None:
        repo_path = self._write_demo_repo()
        report = run_sandbox(repo_path)
        workspace_plan = report["sandbox"]["disposable_workspace"]
        payload = json.dumps(report)

        self.assertEqual(workspace_plan["logical_paths"]["workspace"], "/workspace")
        self.assertEqual(workspace_plan["environment"]["HOME"], "/tmp/home")
        self.assertEqual(workspace_plan["environment"]["NPM_CONFIG_CACHE"], "/tmp/npm-cache")
        self.assertEqual(workspace_plan["environment"]["PIP_CACHE_DIR"], "/tmp/pip-cache")
        self.assertEqual(workspace_plan["environment"]["XDG_CACHE_HOME"], "/tmp/xdg-cache")
        self.assertEqual(workspace_plan["environment"]["TMPDIR"], "/tmp/tmp")
        self.assertGreaterEqual(workspace_plan["honeypots"]["file_handle_count"], 1)
        self.assertIn("AWS_SECRET_ACCESS_KEY", workspace_plan["honeypots"]["env_names"])
        self.assertNotIn(str(repo_path.resolve()), payload)
        self.assertEqual(workspace_plan["materialization_status"], "completed")
        self.assertEqual(workspace_plan["cleanup_status"], "completed")
        self.assertIn("<workspace>", payload)

    def test_workspace_materialization_creates_and_cleans_disposable_tree(self) -> None:
        repo_path = self._write_materialization_repo()
        materialized = materialize_disposable_workspace(repo_path, build_disposable_workspace_plan())
        sandbox_root = materialized.sandbox_root
        assert sandbox_root is not None

        self.assertEqual(materialized.materialization_status, "completed")
        self.assertTrue(materialized.host_paths["workspace"].is_dir())
        self.assertTrue(materialized.host_paths["home"].is_dir())
        self.assertTrue(materialized.host_paths["npm_cache"].is_dir())
        self.assertTrue(materialized.host_paths["pip_cache"].is_dir())
        self.assertTrue(materialized.host_paths["xdg_cache"].is_dir())
        self.assertTrue(materialized.host_paths["tmp"].is_dir())
        self.assertTrue((materialized.host_paths["workspace"] / "keep.txt").is_file())
        self.assertTrue((repo_path / "keep.txt").is_file())

        materialized.cleanup()
        self.assertEqual(materialized.cleanup_status, "completed")
        self.assertFalse(sandbox_root.exists())

    def test_copy_policy_excludes_git_dependencies_caches_and_credentials(self) -> None:
        repo_path = self._write_materialization_repo()
        materialized = materialize_disposable_workspace(repo_path, build_disposable_workspace_plan())
        workspace_copy = materialized.host_paths["workspace"]
        try:
            self.assertFalse((workspace_copy / ".git").exists())
            self.assertFalse((workspace_copy / "node_modules").exists())
            self.assertFalse((workspace_copy / ".venv").exists())
            self.assertFalse((workspace_copy / "__pycache__").exists())
            self.assertFalse((workspace_copy / ".npmrc").exists())
            self.assertFalse((workspace_copy / ".pypirc").exists())
            self.assertFalse((workspace_copy / ".netrc").exists())
            self.assertFalse((workspace_copy / ".aws").exists())
            self.assertFalse((workspace_copy / ".ssh").exists())
            self.assertTrue((workspace_copy / ".env").is_file())
            self.assertIn("RHD_HONEYPOT", (workspace_copy / ".env").read_text(encoding="utf-8"))
            self.assertIn("vcs_metadata", materialized.excluded_counts)
            self.assertIn("dependency_tree", materialized.excluded_counts)
            self.assertIn("virtualenv", materialized.excluded_counts)
            self.assertIn("cache", materialized.excluded_counts)
            self.assertIn("credential_like", materialized.excluded_counts)
        finally:
            materialized.cleanup()

    def test_unsafe_symlink_is_skipped_and_reported(self) -> None:
        repo_path = self._write_materialization_repo()
        materialized = materialize_disposable_workspace(repo_path, build_disposable_workspace_plan())
        try:
            self.assertFalse((materialized.host_paths["workspace"] / "escape-link").exists())
            self.assertEqual(len(materialized.unsafe_symlinks), 1)
            self.assertEqual(materialized.unsafe_symlinks[0]["reason"], "outside_repo")
        finally:
            materialized.cleanup()

    def test_cleanup_failure_is_recorded_fail_closed(self) -> None:
        repo_path = self._write_materialization_repo()
        materialized = materialize_disposable_workspace(repo_path, build_disposable_workspace_plan())
        sandbox_root = materialized.sandbox_root
        assert sandbox_root is not None
        try:
            with mock.patch("repo_health_doctor.sandbox.workspace.shutil.rmtree", side_effect=OSError("cleanup denied")):
                materialized.cleanup()
            self.assertEqual(materialized.cleanup_status, "failed")
            self.assertTrue(materialized.cleanup_error)
            self.assertIn("fail-closed", " ".join(materialized.limitations))
        finally:
            if sandbox_root.exists():
                shutil.rmtree(sandbox_root)

    def test_path_redaction_hides_repo_and_sandbox_absolute_paths(self) -> None:
        repo_path = self._write_materialization_repo()
        materialized = materialize_disposable_workspace(repo_path, build_disposable_workspace_plan())
        try:
            sample = (
                f"{repo_path.resolve()} -> {materialized.host_paths['workspace']} "
                f"AWS_SECRET_ACCESS_KEY={materialized.honeypot_env['AWS_SECRET_ACCESS_KEY']} "
                "RHD_HONEYPOT_SECRET"
            )
            redacted = materialized.redact_text(sample)

            self.assertNotIn(str(repo_path.resolve()), redacted)
            self.assertNotIn(str(materialized.host_paths["workspace"]), redacted)
            self.assertNotIn(materialized.honeypot_env["AWS_SECRET_ACCESS_KEY"], redacted)
            self.assertNotIn("RHD_HONEYPOT_SECRET", redacted)
            self.assertIn("<repo>", redacted)
            self.assertIn("<workspace>", redacted)
            self.assertIn("AWS_SECRET_ACCESS_KEY=***REDACTED***", redacted)
        finally:
            materialized.cleanup()

    def test_dynamic_output_summary_redacts_generic_secret_values(self) -> None:
        materialized = materialize_disposable_workspace(
            self._fixture_path("sandbox-phase3-python-runtime"),
            build_disposable_workspace_plan(),
        )
        strace_log = materialized.host_paths["tmp"] / "rhd-strace.1"
        completed = subprocess.CompletedProcess(
            args=["docker"],
            returncode=0,
            stdout=self.GENERIC_SECRET_OUTPUT,
            stderr=self.GENERIC_SECRET_OUTPUT,
        )

        def _complete_with_strace_log(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            strace_log.write_text("", encoding="utf-8")
            return completed

        try:
            with mock.patch(
                "repo_health_doctor.sandbox.dynamic.subprocess.run",
                side_effect=_complete_with_strace_log,
            ):
                result = sandbox_dynamic.run_dynamic_phase(
                    resolved_base_argv=["docker", "run", "--network", "none", "rhd-python312-strace:local"],
                    commands=[self._phase3_runtime_fixture_command()],
                    materialized=materialized,
                    observer=self._fully_ready_observer(),
                    detected_languages=["python"],
                )

            command_result = result["results"][0]
            summary_text = f"{command_result['stdout_summary']}\n{command_result['stderr_summary']}"
            self.assertEqual(command_result["status"], "passed")
            self.assertEqual(command_result["observer_summary"]["syscall_log_file_count"], 1)
            self.assertIn("***REDACTED***", summary_text)
            for value in self.GENERIC_SECRET_VALUES:
                self.assertNotIn(value, summary_text)
        finally:
            materialized.cleanup()

    def test_dynamic_observation_activation_requires_successful_parseable_strace_result(self) -> None:
        observed_result = {
            "status": "passed",
            "observer_summary": {
                "pass_possible": True,
                "syscall_log_file_count": 1,
                "syscall_read_error_count": 0,
            },
        }
        phase = {"performed": True, "results": [observed_result]}

        self.assertTrue(_has_successful_observed_dynamic_result(phase))
        observed_result["status"] = "failed"
        self.assertFalse(_has_successful_observed_dynamic_result(phase))
        observed_result["status"] = "passed"
        observed_result["observer_summary"]["syscall_log_file_count"] = 0
        self.assertFalse(_has_successful_observed_dynamic_result(phase))
        observed_result["observer_summary"]["syscall_log_file_count"] = 1
        observed_result["observer_summary"]["syscall_read_error_count"] = 1
        self.assertFalse(_has_successful_observed_dynamic_result(phase))

    def test_final_report_redacts_generic_dynamic_text_and_marks_observation_activated(self) -> None:
        repo_path = self._fixture_path("sandbox-phase3-python-runtime")
        approval_path = self._fixture_path("approvals/phase3-python-runtime-test.json")
        dynamic_result = {
            "requested": True,
            "performed": True,
            "status": "passed",
            "network_mode": "none",
            "timeout_seconds": 60,
            "approved_command_count": 1,
            "results": [
                {
                    "kind": "test_probe",
                    "argv": self.PHASE3_RUNTIME_FIXTURE_ARGV,
                    "return_code": 0,
                    "status": "passed",
                    "timed_out": False,
                    "stdout_summary": self.GENERIC_SECRET_OUTPUT,
                    "stderr_summary": self.GENERIC_SECRET_OUTPUT,
                    "error": self.GENERIC_SECRET_OUTPUT,
                    "observer_summary": {
                        "network_event_count": 0,
                        "secret_event_count": 0,
                        "process_event_count": 0,
                        "env_sweep_count": 0,
                        "delete_inside_writable_count": 0,
                        "delete_outside_writable_count": 0,
                        "observer_mode": "strace+runtime_hook",
                        "pass_possible": True,
                        "syscall_log_file_count": 1,
                        "syscall_read_error_count": 0,
                        "syscall_secret_file_open_count": 0,
                        "syscall_event_type_counts": {"execve": 1, "openat": 1, "write": 1, "exit_group": 1},
                    },
                }
            ],
            "limitations": [self.GENERIC_SECRET_OUTPUT],
        }

        with mock.patch(
            "repo_health_doctor.sandbox.docker.subprocess.run",
            return_value=self._docker_inspect_result(self.LOCAL_IMAGE_ID),
        ), mock.patch(
            "repo_health_doctor.sandbox.command.run_docker_preflight",
            return_value=self._successful_preflight_result(),
        ), mock.patch(
            "repo_health_doctor.sandbox.command.build_observer_plan",
            return_value=self._fully_ready_observer(),
        ), mock.patch(
            "repo_health_doctor.sandbox.command.run_dynamic_phase",
            return_value=dynamic_result,
        ):
            report = run_sandbox(
                repo_path,
                approval_file=approval_path,
                docker_image="rhd-python312-strace:local",
                allow_local_image=True,
                expected_image_id=self.LOCAL_IMAGE_ID,
                run_preflight=True,
                run_phase3=True,
            )

        payload = json.dumps(report)
        result = report["sandbox"]["phase3_runtime_probes"]["results"][0]
        self.assertIn("***REDACTED***", result["stdout_summary"])
        self.assertIn("***REDACTED***", result["stderr_summary"])
        self.assertIn("***REDACTED***", result["error"])
        self.assertNotIn("dynamic_observation_not_yet_activated", report["residual_risks"])
        self.assertIn("dynamic_observation_evidence_limited", report["residual_risks"])
        for value in self.GENERIC_SECRET_VALUES:
            self.assertNotIn(value, payload)

    def test_phase1_fetch_plan_generates_fixed_node_and_python_candidates(self) -> None:
        repo_path = self._write_demo_repo()
        report = run_sandbox(repo_path)
        phase1 = next(item for item in report["phase_plan"] if item["phase"] == "phase1_fetch")
        commands = phase1["commands"]

        npm_command = next(item for item in commands if item["argv"][0] == "npm")
        pip_command = next(item for item in commands if item["argv"][0] == "python")

        self.assertEqual(
            npm_command["argv"],
            ["npm", "ci", "--ignore-scripts", "--audit=false", "--fund=false"],
        )
        self.assertEqual(
            pip_command["argv"],
            ["python", "-m", "pip", "download", "--only-binary=:all:", "-r", "requirements.txt"],
        )
        self.assertFalse(npm_command["shell"])
        self.assertFalse(pip_command["shell"])

    def test_phase1_fetch_plan_generates_python_candidate_from_poetry_lock(self) -> None:
        repo_path = self._write_poetry_lock_repo()
        report = run_sandbox(repo_path)
        phase1 = next(item for item in report["phase_plan"] if item["phase"] == "phase1_fetch")
        commands = phase1["commands"]
        skipped = phase1["skipped_commands"]

        self.assertEqual(len(commands), 1)
        self.assertEqual(
            commands[0]["argv"],
            ["python", "-m", "pip", "download", "--only-binary=:all:", "requests==2.31.0"],
        )
        self.assertFalse(commands[0]["shell"])
        self.assertIn("unsupported_python_dependency_source", {item["reason"] for item in skipped})
        self.assertIn("poetry.lock", " ".join(phase1["limitations"]))

    def test_phase1_fetch_plan_generates_python_candidate_from_uv_lock(self) -> None:
        repo_path = self._write_uv_lock_repo()
        report = run_sandbox(repo_path)
        phase1 = next(item for item in report["phase_plan"] if item["phase"] == "phase1_fetch")
        commands = phase1["commands"]
        skipped = phase1["skipped_commands"]

        self.assertEqual(len(commands), 1)
        self.assertEqual(
            commands[0]["argv"],
            ["python", "-m", "pip", "download", "--only-binary=:all:", "click==8.1.7"],
        )
        self.assertFalse(commands[0]["shell"])
        self.assertIn("unsupported_python_dependency_source", {item["reason"] for item in skipped})
        self.assertIn("uv.lock", " ".join(phase1["limitations"]))

    def test_phase1_fetch_plan_is_fail_closed_for_ambiguous_python_lockfiles(self) -> None:
        repo_path = self._write_ambiguous_python_lock_repo()
        report = run_sandbox(repo_path)
        phase1 = next(item for item in report["phase_plan"] if item["phase"] == "phase1_fetch")

        self.assertEqual(phase1["commands"], [])
        self.assertIn("python_fetch_plan_not_generated", {item["reason"] for item in phase1["skipped_commands"]})
        self.assertIn("both poetry.lock and uv.lock", " ".join(phase1["limitations"]))

    def test_phase1_5_rescan_is_non_pass_when_no_artifacts_are_available(self) -> None:
        repo_path = self._write_demo_repo()
        report = run_sandbox(repo_path)
        rescan = report["sandbox"]["phase1_5_rescan"]
        rescan_check = next(item for item in report["checks"] if item["id"] == "sandbox.phase1_5_rescan")

        self.assertEqual(rescan["status"], "skipped")
        self.assertFalse(rescan["performed"])
        self.assertEqual(rescan_check["status"], "warn")

    def test_phase1_5_rescan_detects_suspicious_fetched_node_artifacts(self) -> None:
        repo_path = self._write_demo_repo()
        materialized = materialize_disposable_workspace(repo_path, build_disposable_workspace_plan())
        try:
            fetched_package = materialized.host_paths["workspace"] / "node_modules" / "left-pad"
            fetched_package.mkdir(parents=True)
            (fetched_package / "package.json").write_text(
                json.dumps(
                    {
                        "name": "left-pad",
                        "scripts": {
                            "postinstall": "node -e \"require('https').request('https://example.test'); process.env.AWS_SECRET_ACCESS_KEY\""
                        },
                    }
                ),
                encoding="utf-8",
            )

            rescan = run_phase1_rescan(materialized)
            categories = {item["category"] for item in rescan["findings"]}

            self.assertTrue(rescan["performed"])
            self.assertEqual(rescan["status"], "blocked")
            self.assertIn("lifecycle_script_present", categories)
            self.assertTrue(rescan["install_time_risks"])
            self.assertIn("<workspace>/node_modules/left-pad/package.json", json.dumps(rescan))
        finally:
            materialized.cleanup()

    def test_phase1_5_rescan_detects_suspicious_python_wheel_metadata(self) -> None:
        repo_path = self._write_demo_repo()
        materialized = materialize_disposable_workspace(repo_path, build_disposable_workspace_plan())
        try:
            wheel_path = materialized.host_paths["workspace"] / "demo_pkg-0.0.1-py3-none-any.whl"
            import zipfile

            with zipfile.ZipFile(wheel_path, "w") as archive:
                archive.writestr("demo_pkg/setup.py", "import requests\nrequests.get('https://example.test')\n")
                archive.writestr("demo_pkg/__init__.py", "import socket\nsocket.getaddrinfo('example.test', 443)\n")

            rescan = run_phase1_rescan(materialized)
            categories = {item["category"] for item in rescan["findings"]}

            self.assertTrue(rescan["performed"])
            self.assertEqual(rescan["status"], "warn")
            self.assertIn("packaged_build_script_reference", categories)
            self.assertIn("network_api_reference", categories)
            self.assertFalse(rescan["blocked_findings"])
            self.assertTrue(rescan["unknown_findings"])
        finally:
            materialized.cleanup()

    def test_phase1_5_rescan_treats_requests_like_wheel_as_warn_not_block(self) -> None:
        repo_path = self._write_demo_repo()
        materialized = materialize_disposable_workspace(repo_path, build_disposable_workspace_plan())
        try:
            wheel_path = materialized.host_paths["workspace"] / "requests_like-0.0.1-py3-none-any.whl"
            import zipfile

            with zipfile.ZipFile(wheel_path, "w") as archive:
                archive.writestr(
                    "requests_like/sessions.py",
                    "\n".join(
                        [
                            "import os",
                            "import socket",
                            "REQUESTS_CA_BUNDLE = os.environ.get('REQUESTS_CA_BUNDLE')",
                            "NETRC_PATH = '.netrc'",
                            "socket.getaddrinfo('example.test', 443)",
                        ]
                    )
                    + "\n",
                )
                archive.writestr(
                    "requests_like-0.0.1.dist-info/METADATA",
                    "Home-page: https://example.test\nProject-URL: Source, https://example.test/src\n",
                )

            rescan = run_phase1_rescan(materialized)
            categories = {item["category"] for item in rescan["findings"]}

            self.assertTrue(rescan["performed"])
            self.assertEqual(rescan["status"], "warn")
            self.assertFalse(rescan["blocked_findings"])
            self.assertIn("network_api_reference", categories)
            self.assertIn("env_reference", categories)
            self.assertIn("expected_secret_or_path_reference", categories)
            self.assertIn("metadata_reference", categories)
            self.assertTrue(rescan["ordinary_library_capabilities"])
            self.assertTrue(rescan["info_findings"])
            self.assertIn("phase1_5_warn_findings_require_human_review", rescan["residual_risks"])
        finally:
            materialized.cleanup()

    def test_phase1_5_rescan_blocks_python_source_distribution(self) -> None:
        repo_path = self._write_demo_repo()
        materialized = materialize_disposable_workspace(repo_path, build_disposable_workspace_plan())
        try:
            import io
            import tarfile

            sdist_path = materialized.host_paths["pip_cache"] / "demo_pkg-0.0.1.tar.gz"
            setup_py = b"import subprocess\nsubprocess.run(['python', '-V'])\n"
            pyproject = b"[build-system]\nbuild-backend = 'setuptools.build_meta'\n"
            with tarfile.open(sdist_path, "w:gz") as archive:
                setup_member = tarfile.TarInfo("demo_pkg/setup.py")
                setup_member.size = len(setup_py)
                archive.addfile(setup_member, io.BytesIO(setup_py))
                pyproject_member = tarfile.TarInfo("demo_pkg/pyproject.toml")
                pyproject_member.size = len(pyproject)
                archive.addfile(pyproject_member, io.BytesIO(pyproject))

            rescan = run_phase1_rescan(materialized)
            categories = {item["category"] for item in rescan["findings"]}

            self.assertEqual(rescan["status"], "blocked")
            self.assertIn("source_distribution_present", categories)
            self.assertIn("python_build_script_present", categories)
            self.assertIn("python_build_backend_present", categories)
            self.assertTrue(rescan["dependency_source_risks"])
            self.assertTrue(rescan["install_time_risks"])
        finally:
            materialized.cleanup()

    def test_phase1_5_rescan_blocks_obfuscated_dynamic_exec_in_wheel(self) -> None:
        repo_path = self._write_demo_repo()
        materialized = materialize_disposable_workspace(repo_path, build_disposable_workspace_plan())
        try:
            wheel_path = materialized.host_paths["workspace"] / "bad_pkg-0.0.1-py3-none-any.whl"
            import zipfile

            with zipfile.ZipFile(wheel_path, "w") as archive:
                archive.writestr(
                    "bad_pkg/payload.py",
                    "import base64, subprocess, os\nbase64.b64decode('ZXhlYw==')\nsubprocess.run(['python', '-V'])\nos.environ.get('AWS_SECRET_ACCESS_KEY')\n",
                )

            rescan = run_phase1_rescan(materialized)
            categories = {item["category"] for item in rescan["findings"]}

            self.assertEqual(rescan["status"], "blocked")
            self.assertIn("obfuscated_dynamic_execution", categories)
            self.assertTrue(rescan["blocked_findings"])
        finally:
            materialized.cleanup()

    def test_phase1_5_rescan_keeps_backend_dynamic_exec_blocked_but_downgrades_packaged_tests(self) -> None:
        repo_path = self._write_demo_repo()
        materialized = materialize_disposable_workspace(repo_path, build_disposable_workspace_plan())
        try:
            wheel_path = materialized.host_paths["workspace"] / "setuptools_like-0.0.1-py3-none-any.whl"
            import zipfile

            with zipfile.ZipFile(wheel_path, "w") as archive:
                archive.writestr(
                    "setuptools_like/backend.py",
                    "import os, subprocess\nsubprocess.check_call(['python', '-V'])\nos.environ.get('PIP_INDEX_URL')\n",
                )
                archive.writestr(
                    "setuptools_like/tests/helper.py",
                    "import os, subprocess\nsubprocess.run(['python', '-V'])\nos.environ.get('AWS_SECRET_ACCESS_KEY')\n",
                )

            rescan = run_phase1_rescan(materialized)
            blocked_paths = {item["path"] for item in rescan["blocked_findings"]}
            unknown_categories = {item["category"] for item in rescan["unknown_findings"]}
            unknown_paths = {item["path"] for item in rescan["unknown_findings"]}

            self.assertEqual(rescan["status"], "blocked")
            self.assertIn("<workspace>/setuptools_like-0.0.1-py3-none-any.whl!/setuptools_like/backend.py", blocked_paths)
            self.assertNotIn("<workspace>/setuptools_like-0.0.1-py3-none-any.whl!/setuptools_like/tests/helper.py", blocked_paths)
            self.assertIn("packaged_test_support_dynamic_execution", unknown_categories)
            self.assertIn(
                "<workspace>/setuptools_like-0.0.1-py3-none-any.whl!/setuptools_like/tests/helper.py",
                unknown_paths,
            )
        finally:
            materialized.cleanup()

    def test_phase1_5_rescan_avoids_comment_and_literal_eval_dynamic_exec_false_positives(self) -> None:
        repo_path = self._write_demo_repo()
        materialized = materialize_disposable_workspace(repo_path, build_disposable_workspace_plan())
        try:
            wheel_path = materialized.host_paths["workspace"] / "commentary-0.0.1-py3-none-any.whl"
            import zipfile

            with zipfile.ZipFile(wheel_path, "w") as archive:
                archive.writestr(
                    "commentary/tests/module.py",
                    "\n".join(
                        [
                            "# For subprocess.run coverage only",
                            "import ast, os, subprocess",
                            "ERR = subprocess.CalledProcessError",
                            "VALUE = ast.literal_eval('{}')",
                            "SYSTEMROOT = os.environ.get('SYSTEMROOT')",
                        ]
                    )
                    + "\n",
                )

            rescan = run_phase1_rescan(materialized)
            categories = {item["category"] for item in rescan["findings"]}

            self.assertEqual(rescan["status"], "warn")
            self.assertFalse(rescan["blocked_findings"])
            self.assertNotIn("packaged_test_support_dynamic_execution", categories)
            self.assertIn("env_reference", categories)
        finally:
            materialized.cleanup()

    def test_phase1_5_rescan_covers_npm_tarball_build_backend_and_ip_markers(self) -> None:
        repo_path = self._write_demo_repo()
        materialized = materialize_disposable_workspace(repo_path, build_disposable_workspace_plan())
        try:
            import io
            import tarfile
            import zipfile

            tarball_path = materialized.host_paths["npm_cache"] / "example-package.tgz"
            package_json = json.dumps(
                {
                    "name": "example-package",
                    "scripts": {
                        "postinstall": (
                            "node -e \"Buffer.from('ZXhlYw==', 'base64'); "
                            "require('child_process').exec('echo no'); "
                            "fetch('http://198.51.100.24/check')\""
                        )
                    },
                }
            ).encode("utf-8")
            with tarfile.open(tarball_path, "w:gz") as archive:
                member = tarfile.TarInfo("package/package.json")
                member.size = len(package_json)
                archive.addfile(member, io.BytesIO(package_json))

            wheel_path = materialized.host_paths["pip_cache"] / "demo_pkg-0.0.1-py3-none-any.whl"
            with zipfile.ZipFile(wheel_path, "w") as archive:
                archive.writestr(
                    "demo_pkg/pyproject.toml",
                    "[build-system]\nbuild-backend = 'setuptools.build_meta'\n",
                )
                archive.writestr("demo_pkg/setup.py", "from setuptools import setup\n")

            rescan = run_phase1_rescan(materialized)
            categories = {item["category"] for item in rescan["findings"]}
            artifact_kinds = rescan["artifact_summary"]["artifact_kind_counts"]

            self.assertTrue(rescan["performed"])
            self.assertEqual(rescan["status"], "blocked")
            self.assertIn("lifecycle_script_present", categories)
            self.assertIn("obfuscated_dynamic_execution", categories)
            self.assertIn("packaged_build_backend_reference", categories)
            self.assertIn("packaged_build_script_reference", categories)
            self.assertEqual(artifact_kinds["node_package_archive"], 1)
            self.assertEqual(artifact_kinds["python_archive"], 1)
        finally:
            materialized.cleanup()

    def test_observer_plan_starts_degraded_until_preflight_confirms_syscall_trace(self) -> None:
        observer = build_observer_plan(["python", "node"])
        self.assertEqual(observer["mode"], "runtime_hook")
        self.assertEqual(observer["status"], "ready")
        self.assertFalse(observer["syscall_observer"]["available"])
        self.assertFalse(observer["syscall_observer"]["active"])
        self.assertEqual(len(observer["runtime_hooks"]), 2)
        self.assertTrue(all(item["implemented"] for item in observer["runtime_hooks"]))
        self.assertEqual(observer["runtime_hook_active_languages"], ["python", "node"])
        self.assertTrue(observer["phase2_ready"])
        self.assertTrue(observer["phase3_ready"])
        self.assertFalse(observer["pass_possible"])
        self.assertIn("Docker preflight", " ".join(observer["limitations"]))

    def test_phase1_is_not_requested_by_default(self) -> None:
        repo_path = self._write_demo_repo()
        report = run_sandbox(repo_path)
        phase1 = report["sandbox"]["phase1_fetch"]

        self.assertFalse(phase1["requested"])
        self.assertFalse(phase1["performed"])
        self.assertEqual(phase1["status"], "not_requested")
        self.assertTrue(phase1["limitations"])

    def test_phase1_is_skipped_without_successful_preflight(self) -> None:
        repo_path = self._write_demo_repo()
        with mock.patch("repo_health_doctor.sandbox.fetch_plan.subprocess.run") as mocked_run:
            report = run_sandbox(
                repo_path,
                run_phase1=True,
                docker_image="python:3.12-slim-bookworm@sha256:0123456789abcdef",
            )

        phase1 = report["sandbox"]["phase1_fetch"]
        self.assertFalse(mocked_run.called)
        self.assertTrue(phase1["requested"])
        self.assertFalse(phase1["performed"])
        self.assertEqual(phase1["status"], "skipped")
        self.assertIn("successful Docker preflight", " ".join(phase1["limitations"]))

    def test_phase2_is_skipped_without_explicit_approval(self) -> None:
        repo_path = self._write_demo_repo()
        report = run_sandbox(
            repo_path,
            run_phase2=True,
            docker_image="python:3.12-slim-bookworm@sha256:0123456789abcdef",
        )

        phase2 = report["sandbox"]["phase2_install_probes"]
        self.assertTrue(phase2["requested"])
        self.assertFalse(phase2["performed"])
        self.assertEqual(phase2["status"], "skipped")

    def test_python_phase2_and_phase3_do_not_execute_without_approval_after_prior_gates_pass(self) -> None:
        repo_path = self._write_python_build_repo()
        (repo_path / "setup.py").write_text("from setuptools import setup\n", encoding="utf-8")
        (repo_path / "requirements.txt").write_text("pytest==8.0.0\n", encoding="utf-8")

        with mock.patch(
            "repo_health_doctor.sandbox.command.run_docker_preflight",
            return_value=self._successful_preflight_result(),
        ), mock.patch(
            "repo_health_doctor.sandbox.command.run_phase1_fetch",
            return_value=self._successful_phase1_result(),
        ), mock.patch(
            "repo_health_doctor.sandbox.command.run_phase1_rescan",
            return_value=self._successful_rescan_result(),
        ), mock.patch(
            "repo_health_doctor.sandbox.command.build_observer_plan",
            return_value=self._fully_ready_observer(),
        ), mock.patch("repo_health_doctor.sandbox.command.run_dynamic_phase") as mocked_dynamic_run:
            report = run_sandbox(
                repo_path,
                docker_image="python:3.12-slim-bookworm@sha256:0123456789abcdef",
                run_preflight=True,
                run_phase1=True,
                run_phase2=True,
                run_phase3=True,
            )

        commands = report["execution_plan"]["commands"]
        phase2 = report["sandbox"]["phase2_install_probes"]
        phase3 = report["sandbox"]["phase3_runtime_probes"]
        skipped = report["execution_plan"]["skipped_commands"]

        self.assertFalse(mocked_dynamic_run.called)
        self.assertEqual(report["execution_plan"]["approval"]["status"], "not_provided")
        self.assertFalse(phase2["performed"])
        self.assertFalse(phase3["performed"])
        self.assertEqual(phase2["status"], "skipped")
        self.assertEqual(phase3["status"], "skipped")
        self.assertEqual(phase2["approved_command_count"], 0)
        self.assertEqual(phase3["approved_command_count"], 0)
        self.assertIn(
            ["python", "-m", "pip", "install", "--no-deps", "--no-build-isolation", "."],
            [command["argv"] for command in commands],
        )
        self.assertIn(
            ["python", "-m", "pip", "install", "--no-deps", "--no-build-isolation", "-e", "."],
            [command["argv"] for command in commands],
        )
        self.assertIn(["python", "-m", "pytest"], [command["argv"] for command in commands])
        self.assertIn(["demo-cli"], [command["argv"] for command in commands])
        self.assertTrue(all(not command["approved"] for command in commands))
        self.assertIn("not_explicitly_approved", {item["reason"] for item in skipped})

    def test_phase1_5_blocked_prevents_phase2_and_phase3_execution(self) -> None:
        repo_path = self._write_python_build_repo()
        (repo_path / "setup.py").write_text("from setuptools import setup\n", encoding="utf-8")
        (repo_path / "requirements.txt").write_text("pytest==8.0.0\n", encoding="utf-8")
        baseline = run_sandbox(repo_path)
        approved_commands = [
            command
            for command in baseline["execution_plan"]["commands"]
            if command["phase"] in {"phase2_install_probe", "phase3_runtime_probe"}
        ]
        approval_path = self.tmp_path / "approved-phase2-phase3.json"
        approval_path.write_text(json.dumps({"commands": approved_commands}), encoding="utf-8")

        blocked_finding = {
            "category": "source_distribution_present",
            "classification": "dependency_source_risk",
            "severity": "block",
            "path": "<workspace>/demo_pkg-0.0.1.tar.gz",
            "summary": "Fetched Python source archive would require install-time build execution and remains blocked.",
            "artifact_kind": "python_archive",
        }
        blocked_rescan = {
            **self._successful_rescan_result(),
            "status": "blocked",
            "finding_summary": {
                "blocked_count": 1,
                "warn_count": 0,
                "info_count": 0,
                "unknown_count": 0,
            },
            "findings": [blocked_finding],
            "blocked_findings": [blocked_finding],
            "dependency_source_risks": [blocked_finding],
            "residual_risks": ["phase1_5_blocked_findings_present"],
        }

        with mock.patch(
            "repo_health_doctor.sandbox.command.run_docker_preflight",
            return_value=self._successful_preflight_result(),
        ), mock.patch(
            "repo_health_doctor.sandbox.command.run_phase1_fetch",
            return_value=self._successful_phase1_result(),
        ), mock.patch(
            "repo_health_doctor.sandbox.command.run_phase1_rescan",
            return_value=blocked_rescan,
        ), mock.patch(
            "repo_health_doctor.sandbox.command.build_observer_plan",
            return_value=self._fully_ready_observer(),
        ), mock.patch("repo_health_doctor.sandbox.command.run_dynamic_phase") as mocked_dynamic_run:
            report = run_sandbox(
                repo_path,
                approval_file=approval_path,
                docker_image="python:3.12-slim-bookworm@sha256:0123456789abcdef",
                run_preflight=True,
                run_phase1=True,
                run_phase2=True,
                run_phase3=True,
            )

        self.assertFalse(mocked_dynamic_run.called)
        self.assertEqual(report["sandbox"]["phase2_install_probes"]["status"], "skipped")
        self.assertEqual(report["sandbox"]["phase3_runtime_probes"]["status"], "skipped")
        self.assertIn("without blocked findings", " ".join(report["sandbox"]["phase2_install_probes"]["limitations"]))
        self.assertIn("without blocked findings", " ".join(report["sandbox"]["phase3_runtime_probes"]["limitations"]))

    def test_phase1_does_not_fetch_vcs_or_local_python_dependencies(self) -> None:
        repo_path = self.tmp_path / "unsupported-python-sources"
        repo_path.mkdir()
        (repo_path / "pyproject.toml").write_text(
            "[project]\nname = 'unsupported-python-sources'\nversion = '0.0.1'\n",
            encoding="utf-8",
        )
        (repo_path / "requirements.txt").write_text(
            "-e .\ngit+https://example.test/demo.git\n../local-demo\n",
            encoding="utf-8",
        )

        with mock.patch(
            "repo_health_doctor.sandbox.command.run_docker_preflight",
            return_value=self._successful_preflight_result(),
        ), mock.patch("repo_health_doctor.sandbox.fetch_plan.subprocess.run") as mocked_fetch_run:
            report = run_sandbox(
                repo_path,
                docker_image="python:3.12-slim-bookworm@sha256:0123456789abcdef",
                run_preflight=True,
                run_phase1=True,
            )

        phase1 = report["sandbox"]["phase1_fetch"]
        planned = next(item for item in report["phase_plan"] if item["phase"] == "phase1_fetch")

        self.assertFalse(mocked_fetch_run.called)
        self.assertEqual(phase1["status"], "skipped")
        self.assertEqual(phase1["results"], [])
        self.assertEqual(planned["commands"], [])
        self.assertIn("unsupported_python_dependency_source", {item["reason"] for item in planned["skipped_commands"]})

    def test_phase1_generates_build_system_requires_fetch_plan(self) -> None:
        repo_path = self._write_python_build_repo()

        fetch_plan = build_fetch_plan(repo_path)

        self.assertEqual(len(fetch_plan["commands"]), 1)
        self.assertEqual(fetch_plan["skipped_commands"], [])
        self.assertEqual(fetch_plan["limitations"], [])
        self.assertEqual(
            fetch_plan["commands"][0],
            {
                "phase": "phase1_fetch",
                "kind": "dependency_fetch",
                "cwd": ".",
                "argv": ["python", "-m", "pip", "download", "--only-binary=:all:", "setuptools>=68"],
                "env_allowlist": ["HOME", "PIP_CACHE_DIR", "TMPDIR", "XDG_CACHE_HOME"],
                "shell": False,
                "approved": False,
                "evidence": {
                    "manifest": "pyproject.toml",
                    "source": "build-system.requires",
                    "binary_only": "required",
                },
            },
        )

    def test_phase1_executes_build_system_requires_fetch_candidates(self) -> None:
        repo_path = self._write_python_build_repo()
        completed = subprocess.CompletedProcess(args=["docker"], returncode=0, stdout="", stderr="")

        with mock.patch(
            "repo_health_doctor.sandbox.command.run_docker_preflight",
            return_value=self._successful_preflight_result(),
        ), mock.patch(
            "repo_health_doctor.sandbox.fetch_plan.subprocess.run",
            return_value=completed,
        ) as mocked_fetch_run:
            report = run_sandbox(
                repo_path,
                docker_image="python:3.12-slim-bookworm@sha256:0123456789abcdef",
                run_preflight=True,
                run_phase1=True,
                phase1_timeout_seconds=13,
            )

        phase1 = report["sandbox"]["phase1_fetch"]
        self.assertEqual(phase1["status"], "passed")
        self.assertTrue(phase1["performed"])
        self.assertEqual(phase1["timeout_seconds"], 13)
        self.assertEqual(len(phase1["results"]), 1)
        self.assertEqual(mocked_fetch_run.call_count, 1)

        fetch_argv = mocked_fetch_run.call_args.args[0]
        self.assertFalse(mocked_fetch_run.call_args.kwargs["shell"])
        self.assertIn("--network", fetch_argv)
        self.assertIn("bridge", fetch_argv)
        self.assertIn("--entrypoint", fetch_argv)
        self.assertEqual(fetch_argv[fetch_argv.index("--entrypoint") + 1], "python")
        self.assertEqual(
            fetch_argv[-5:],
            ["-m", "pip", "download", "--only-binary=:all:", "setuptools>=68"],
        )

    def test_phase2_runs_only_approved_install_probe_when_all_gates_are_ready(self) -> None:
        repo_path = self._write_demo_repo()
        baseline = run_sandbox(repo_path)
        approved_install = next(
            command
            for command in baseline["execution_plan"]["commands"]
            if command["phase"] == "phase2_install_probe" and command["kind"] == "install_script_probe"
        )
        approval_path = self.tmp_path / "approved-install.json"
        approval_path.write_text(json.dumps({"commands": [approved_install]}), encoding="utf-8")

        ready_observer = {
            "mode": "strace",
            "status": "ready",
            "languages": ["node", "python"],
            "syscall_observer": {
                "kind": "strace",
                "available": True,
                "active": True,
                "binary_name": "strace",
                "limitations": [],
            },
            "runtime_hooks": [
                {
                    "language": "python",
                    "implemented": True,
                    "activation": "PYTHONPATH preload via sitecustomize.py",
                    "logical_path": "/workspace/src/repo_health_doctor/sandbox_hooks/python/sitecustomize.py",
                    "logical_directory": "/workspace/src/repo_health_doctor/sandbox_hooks/python",
                    "event_sink": "/tmp/tmp/rhd-observer-events.jsonl",
                    "coverage": ["dns_lookup", "socket_connect", "subprocess_spawn", "secret_file_open"],
                    "limitations": [],
                },
                {
                    "language": "node",
                    "implemented": True,
                    "activation": "NODE_OPTIONS=--require <node-hook>",
                    "logical_path": "/workspace/src/repo_health_doctor/sandbox_hooks/node/node-hook.js",
                    "logical_directory": "/workspace/src/repo_health_doctor/sandbox_hooks/node",
                    "event_sink": "/tmp/tmp/rhd-observer-events.jsonl",
                    "coverage": ["dns_lookup", "socket_connect", "child_process_spawn", "secret_file_open"],
                    "limitations": [],
                },
            ],
            "runtime_hook_active_languages": ["node", "python"],
            "pass_possible": True,
            "event_sink": "/tmp/tmp/rhd-observer-events.jsonl",
            "phase2_ready": True,
            "phase3_ready": True,
            "limitations": [],
        }

        def _write_empty_strace_log(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            tmp_mount = next(
                token for token in argv if isinstance(token, str) and "type=bind,src=" in token and "dst=/tmp/tmp" in token
            )
            src_path = tmp_mount.split("src=", 1)[1].split(",dst=", 1)[0]
            Path(src_path, "rhd-strace.phase2").write_text("", encoding="utf-8")
            return subprocess.CompletedProcess(args=argv, returncode=0, stdout="", stderr="")

        with mock.patch(
            "repo_health_doctor.sandbox.command.run_docker_preflight",
            return_value={
                "requested": True,
                "performed": True,
                "status": "passed",
                "timeout_seconds": 7,
                "commands": [],
                "results": [],
                "limitations": [],
                "phase_gate_limitations": [],
            },
        ), mock.patch(
            "repo_health_doctor.sandbox.command.run_phase1_fetch",
            return_value={
                "requested": True,
                "performed": True,
                "status": "passed",
                "network_mode": "bridge",
                "timeout_seconds": 11,
                "results": [],
                "limitations": [],
                "phase_gate_limitations": [],
            },
        ), mock.patch(
            "repo_health_doctor.sandbox.command.run_phase1_rescan",
            return_value={
                "requested": True,
                "performed": True,
                "status": "passed",
                "artifact_summary": {
                    "scanned_file_count": 1,
                    "artifact_candidate_count": 1,
                    "read_error_count": 0,
                    "artifact_kind_counts": {
                        "node_package_manifest": 1,
                        "python_archive": 0,
                        "plain_text_artifact": 0,
                    },
                },
                "findings": [],
                "limitations": [],
            },
        ), mock.patch(
            "repo_health_doctor.sandbox.command.build_observer_plan",
            return_value=ready_observer,
        ), mock.patch(
            "repo_health_doctor.sandbox.dynamic.subprocess.run",
            side_effect=_write_empty_strace_log,
        ) as mocked_dynamic_run:
            report = run_sandbox(
                repo_path,
                approval_file=approval_path,
                docker_image="python:3.12-slim-bookworm@sha256:0123456789abcdef",
                run_preflight=True,
                run_phase1=True,
                run_phase2=True,
                dynamic_timeout_seconds=19,
            )

        phase2 = report["sandbox"]["phase2_install_probes"]
        self.assertEqual(phase2["status"], "passed")
        self.assertTrue(phase2["performed"])
        self.assertEqual(phase2["approved_command_count"], 1)
        self.assertEqual(phase2["timeout_seconds"], 19)
        self.assertEqual(mocked_dynamic_run.call_count, 1)
        dynamic_argv = mocked_dynamic_run.call_args.args[0]
        self.assertIn("strace", dynamic_argv)
        self.assertIn("--entrypoint", dynamic_argv)
        self.assertEqual(dynamic_argv[dynamic_argv.index("--entrypoint") + 1], "strace")
        self.assertEqual(dynamic_argv[-2:], ["run", "preinstall"])

    def test_phase2_syscall_trace_blocks_install_probe_network_activity(self) -> None:
        repo_path = self._write_demo_repo()
        baseline = run_sandbox(repo_path)
        approved_install = next(
            command
            for command in baseline["execution_plan"]["commands"]
            if command["phase"] == "phase2_install_probe" and command["kind"] == "install_script_probe"
        )
        approval_path = self.tmp_path / "approved-install-block.json"
        approval_path.write_text(json.dumps({"commands": [approved_install]}), encoding="utf-8")

        def _write_strace_log(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            tmp_mount = next(
                token for token in argv if isinstance(token, str) and "type=bind,src=" in token and "dst=/tmp/tmp" in token
            )
            src_path = tmp_mount.split("src=", 1)[1].split(",dst=", 1)[0]
            Path(src_path, "rhd-strace.phase2.123").write_text(
                '123 connect(3, {sa_family=AF_INET, sin_port=htons(443)}, 16) = -1 EINPROGRESS\n',
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(args=argv, returncode=0, stdout="", stderr="")

        with mock.patch(
            "repo_health_doctor.sandbox.command.run_docker_preflight",
            return_value={
                "requested": True,
                "performed": True,
                "status": "passed",
                "timeout_seconds": 7,
                "commands": [],
                "results": [
                    {
                        "command_kind": "syscall_observer_preflight",
                        "argv": ["docker", "run", "strace", "-V"],
                        "return_code": 0,
                        "status": "passed",
                        "timed_out": False,
                        "stdout_summary": "strace 6.0",
                        "stderr_summary": "",
                    }
                ],
                "limitations": [],
                "phase_gate_limitations": [],
            },
        ), mock.patch(
            "repo_health_doctor.sandbox.command.run_phase1_fetch",
            return_value={
                "requested": True,
                "performed": True,
                "status": "passed",
                "network_mode": "bridge",
                "timeout_seconds": 11,
                "results": [],
                "limitations": [],
                "phase_gate_limitations": [],
            },
        ), mock.patch(
            "repo_health_doctor.sandbox.command.run_phase1_rescan",
            return_value={
                "requested": True,
                "performed": True,
                "status": "passed",
                "artifact_summary": {
                    "scanned_file_count": 1,
                    "artifact_candidate_count": 1,
                    "read_error_count": 0,
                    "artifact_kind_counts": {
                        "node_package_manifest": 1,
                        "python_archive": 0,
                        "plain_text_artifact": 0,
                    },
                },
                "findings": [],
                "limitations": [],
            },
        ), mock.patch(
            "repo_health_doctor.sandbox.dynamic.subprocess.run",
            side_effect=_write_strace_log,
        ):
            report = run_sandbox(
                repo_path,
                approval_file=approval_path,
                docker_image="python:3.12-slim-bookworm@sha256:0123456789abcdef",
                run_preflight=True,
                run_phase1=True,
                run_phase2=True,
            )

        phase2 = report["sandbox"]["phase2_install_probes"]
        external_check = next(item for item in report["checks"] if item["id"] == "sandbox.dynamic_external_communication")
        dynamic_check = next(item for item in report["checks"] if item["id"] == "sandbox.dynamic_execution")
        self.assertEqual(phase2["status"], "blocked")
        self.assertEqual(external_check["status"], "block")
        self.assertGreater(phase2["results"][0]["observer_summary"]["network_event_count"], 0)
        self.assertGreater(dynamic_check["evidence"]["dynamic_observation_summary"]["syscall_log_file_count"], 0)
        self.assertGreater(external_check["evidence"]["syscall_trace"]["log_file_count"], 0)
        self.assertEqual(external_check["evidence"]["phase_statuses"]["phase2"]["status"], "blocked")
        self.assertEqual(external_check["evidence"]["result_status_counts"]["observer_blocked"], 1)
        self.assertGreater(dynamic_check["evidence"]["dynamic_observation"]["event_counts"]["network_event_count"], 0)

    def test_phase3_is_skipped_when_observer_is_not_ready(self) -> None:
        repo_path = self._write_demo_repo()
        baseline = run_sandbox(repo_path)
        approved_runtime = next(
            command
            for command in baseline["execution_plan"]["commands"]
            if command["phase"] == "phase3_runtime_probe" and command["kind"] == "test_probe"
        )
        approval_path = self.tmp_path / "approved-runtime.json"
        approval_path.write_text(json.dumps({"commands": [approved_runtime]}), encoding="utf-8")

        not_ready_observer = {
            "mode": "degraded",
            "status": "degraded",
            "languages": ["node", "python"],
            "syscall_observer": {
                "kind": "strace",
                "available": False,
                "active": False,
                "binary_name": "strace",
                "limitations": ["observer unavailable"],
            },
            "runtime_hooks": [],
            "runtime_hook_active_languages": [],
            "pass_possible": False,
            "event_sink": "/tmp/tmp/rhd-observer-events.jsonl",
            "phase2_ready": False,
            "phase3_ready": False,
            "limitations": ["observer unavailable"],
        }

        def _write_empty_strace_log(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            tmp_mount = next(
                token for token in argv if isinstance(token, str) and "type=bind,src=" in token and "dst=/tmp/tmp" in token
            )
            src_path = tmp_mount.split("src=", 1)[1].split(",dst=", 1)[0]
            Path(src_path, "rhd-strace.000").write_text("", encoding="utf-8")
            return subprocess.CompletedProcess(args=argv, returncode=0, stdout="", stderr="")

        with mock.patch(
            "repo_health_doctor.sandbox.command.run_docker_preflight",
            return_value={
                "requested": True,
                "performed": True,
                "status": "passed",
                "timeout_seconds": 7,
                "commands": [],
                "results": [],
                "limitations": [],
                "phase_gate_limitations": [],
            },
        ), mock.patch(
            "repo_health_doctor.sandbox.command.run_phase1_fetch",
            return_value={
                "requested": True,
                "performed": True,
                "status": "passed",
                "network_mode": "bridge",
                "timeout_seconds": 11,
                "results": [],
                "limitations": [],
                "phase_gate_limitations": [],
            },
        ), mock.patch(
            "repo_health_doctor.sandbox.command.run_phase1_rescan",
            return_value={
                "requested": True,
                "performed": True,
                "status": "passed",
                "artifact_summary": {
                    "scanned_file_count": 1,
                    "artifact_candidate_count": 1,
                    "read_error_count": 0,
                    "artifact_kind_counts": {
                        "node_package_manifest": 1,
                        "python_archive": 0,
                        "plain_text_artifact": 0,
                    },
                },
                "findings": [],
                "limitations": [],
            },
        ), mock.patch(
            "repo_health_doctor.sandbox.command.build_observer_plan",
            return_value=not_ready_observer,
        ):
            report = run_sandbox(
                repo_path,
                approval_file=approval_path,
                docker_image="python:3.12-slim-bookworm@sha256:0123456789abcdef",
                run_preflight=True,
                run_phase1=True,
                run_phase3=True,
            )

        phase3 = report["sandbox"]["phase3_runtime_probes"]
        self.assertTrue(phase3["requested"])
        self.assertFalse(phase3["performed"])
        self.assertEqual(phase3["status"], "skipped")
        self.assertIn("observer", " ".join(phase3["limitations"]).lower())

    def test_phase1_runs_only_tool_generated_fetch_commands_after_preflight(self) -> None:
        repo_path = self._write_demo_repo()
        completed = subprocess.CompletedProcess(args=["docker"], returncode=0, stdout="", stderr="")
        with mock.patch(
            "repo_health_doctor.sandbox.command.run_docker_preflight",
            return_value={
                "requested": True,
                "performed": True,
                "status": "passed",
                "timeout_seconds": 7,
                "commands": [],
                "results": [],
                "limitations": [],
                "phase_gate_limitations": [],
            },
        ) as mocked_preflight_run:
            with mock.patch(
                "repo_health_doctor.sandbox.fetch_plan.subprocess.run",
                return_value=completed,
            ) as mocked_fetch_run:
                report = run_sandbox(
                    repo_path,
                    run_preflight=True,
                    run_phase1=True,
                    docker_image="python:3.12-slim-bookworm@sha256:0123456789abcdef",
                    preflight_timeout_seconds=7,
                    phase1_timeout_seconds=11,
                )

        preflight = report["sandbox"]["preflight"]
        phase1 = report["sandbox"]["phase1_fetch"]
        self.assertEqual(preflight["status"], "passed")
        self.assertEqual(phase1["status"], "passed")
        self.assertTrue(phase1["performed"])
        self.assertEqual(phase1["network_mode"], "bridge")
        self.assertEqual(phase1["timeout_seconds"], 11)
        self.assertEqual(len(phase1["results"]), 2)
        self.assertEqual(mocked_preflight_run.call_count, 1)
        self.assertEqual(mocked_fetch_run.call_count, 2)

        npm_call = mocked_fetch_run.call_args_list[0]
        pip_call = mocked_fetch_run.call_args_list[1]
        self.assertFalse(npm_call.kwargs["shell"])
        self.assertFalse(pip_call.kwargs["shell"])
        self.assertIn("--network", npm_call.args[0])
        self.assertIn("bridge", npm_call.args[0])
        self.assertIn("--entrypoint", npm_call.args[0])
        self.assertEqual(npm_call.args[0][npm_call.args[0].index("--entrypoint") + 1], "npm")
        self.assertIn("--entrypoint", pip_call.args[0])
        self.assertEqual(pip_call.args[0][pip_call.args[0].index("--entrypoint") + 1], "python")
        self.assertEqual(
            npm_call.args[0][-4:],
            ["ci", "--ignore-scripts", "--audit=false", "--fund=false"],
        )
        self.assertEqual(
            pip_call.args[0][-6:],
            ["-m", "pip", "download", "--only-binary=:all:", "-r", "requirements.txt"],
        )

    def test_phase3_runs_only_approved_runtime_probe_when_all_gates_are_ready(self) -> None:
        repo_path = self._write_demo_repo()
        baseline = run_sandbox(repo_path)
        approved_runtime = next(
            command
            for command in baseline["execution_plan"]["commands"]
            if command["phase"] == "phase3_runtime_probe" and command["kind"] == "test_probe"
        )
        approval_path = self.tmp_path / "approved-runtime.json"
        approval_path.write_text(json.dumps({"commands": [approved_runtime]}), encoding="utf-8")
        completed = subprocess.CompletedProcess(args=["docker"], returncode=0, stdout="", stderr="")

        ready_observer = {
            "mode": "strace",
            "status": "ready",
            "languages": ["node", "python"],
            "syscall_observer": {
                "kind": "strace",
                "available": True,
                "active": True,
                "binary_name": "strace",
                "limitations": [],
            },
            "runtime_hooks": [
                {
                    "language": "python",
                    "implemented": True,
                    "activation": "PYTHONPATH preload via sitecustomize.py",
                    "logical_path": "/workspace/src/repo_health_doctor/sandbox_hooks/python/sitecustomize.py",
                    "logical_directory": "/workspace/src/repo_health_doctor/sandbox_hooks/python",
                    "event_sink": "/tmp/tmp/rhd-observer-events.jsonl",
                    "coverage": ["dns_lookup", "socket_connect", "subprocess_spawn", "secret_file_open"],
                    "limitations": [],
                },
                {
                    "language": "node",
                    "implemented": True,
                    "activation": "NODE_OPTIONS=--require <node-hook>",
                    "logical_path": "/workspace/src/repo_health_doctor/sandbox_hooks/node/node-hook.js",
                    "logical_directory": "/workspace/src/repo_health_doctor/sandbox_hooks/node",
                    "event_sink": "/tmp/tmp/rhd-observer-events.jsonl",
                    "coverage": ["dns_lookup", "socket_connect", "child_process_spawn", "secret_file_open"],
                    "limitations": [],
                },
            ],
            "runtime_hook_active_languages": ["node", "python"],
            "pass_possible": True,
            "event_sink": "/tmp/tmp/rhd-observer-events.jsonl",
            "phase2_ready": True,
            "phase3_ready": True,
            "limitations": [],
        }

        def _write_empty_strace_log(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            tmp_mount = next(
                token for token in argv if isinstance(token, str) and "type=bind,src=" in token and "dst=/tmp/tmp" in token
            )
            src_path = tmp_mount.split("src=", 1)[1].split(",dst=", 1)[0]
            Path(src_path, "rhd-strace.000").write_text("", encoding="utf-8")
            return subprocess.CompletedProcess(args=argv, returncode=0, stdout="", stderr="")

        with mock.patch(
            "repo_health_doctor.sandbox.command.run_docker_preflight",
            return_value={
                "requested": True,
                "performed": True,
                "status": "passed",
                "timeout_seconds": 7,
                "commands": [],
                "results": [],
                "limitations": [],
                "phase_gate_limitations": [],
            },
        ), mock.patch(
            "repo_health_doctor.sandbox.command.run_phase1_fetch",
            return_value={
                "requested": True,
                "performed": True,
                "status": "passed",
                "network_mode": "bridge",
                "timeout_seconds": 11,
                "results": [],
                "limitations": [],
                "phase_gate_limitations": [],
            },
        ), mock.patch(
            "repo_health_doctor.sandbox.command.run_phase1_rescan",
            return_value={
                "requested": True,
                "performed": True,
                "status": "passed",
                "artifact_summary": {
                    "scanned_file_count": 1,
                    "artifact_candidate_count": 1,
                    "read_error_count": 0,
                    "artifact_kind_counts": {
                        "node_package_manifest": 1,
                        "python_archive": 0,
                        "plain_text_artifact": 0,
                    },
                },
                "findings": [],
                "limitations": [],
            },
        ), mock.patch(
            "repo_health_doctor.sandbox.command.build_observer_plan",
            return_value=ready_observer,
        ), mock.patch(
            "repo_health_doctor.sandbox.dynamic.subprocess.run",
            side_effect=_write_empty_strace_log,
        ) as mocked_dynamic_run:
            report = run_sandbox(
                repo_path,
                approval_file=approval_path,
                docker_image="python:3.12-slim-bookworm@sha256:0123456789abcdef",
                run_preflight=True,
                run_phase1=True,
                run_phase3=True,
                dynamic_timeout_seconds=17,
            )

        phase3 = report["sandbox"]["phase3_runtime_probes"]
        self.assertEqual(phase3["status"], "passed")
        self.assertTrue(phase3["performed"])
        self.assertEqual(phase3["approved_command_count"], 1)
        self.assertEqual(phase3["timeout_seconds"], 17)
        self.assertEqual(mocked_dynamic_run.call_count, 1)
        dynamic_argv = mocked_dynamic_run.call_args.args[0]
        self.assertFalse(mocked_dynamic_run.call_args.kwargs["shell"])
        self.assertIn("--network", dynamic_argv)
        self.assertIn("none", dynamic_argv)
        self.assertIn("--entrypoint", dynamic_argv)
        self.assertEqual(dynamic_argv[dynamic_argv.index("--entrypoint") + 1], "strace")
        self.assertIn("RHD_OBSERVER_EVENT_FILE=/tmp/tmp/rhd-observer-events.jsonl", dynamic_argv)
        self.assertIn("NODE_OPTIONS=--require=/workspace/src/repo_health_doctor/sandbox_hooks/node/node-hook.js", dynamic_argv)
        self.assertEqual(dynamic_argv[-1], "test")

    def test_phase3_degraded_runtime_hook_result_does_not_pass(self) -> None:
        repo_path = self._write_demo_repo()
        baseline = run_sandbox(repo_path)
        approved_runtime = next(
            command
            for command in baseline["execution_plan"]["commands"]
            if command["phase"] == "phase3_runtime_probe" and command["kind"] == "test_probe"
        )
        approval_path = self.tmp_path / "approved-runtime-degraded.json"
        approval_path.write_text(json.dumps({"commands": [approved_runtime]}), encoding="utf-8")
        completed = subprocess.CompletedProcess(args=["docker"], returncode=0, stdout="", stderr="")

        degraded_ready_observer = {
            "mode": "runtime_hook",
            "status": "ready",
            "languages": ["node", "python"],
            "syscall_observer": {
                "kind": "strace",
                "available": False,
                "active": False,
                "binary_name": "strace",
                "limitations": ["syscall tracing unavailable"],
            },
            "runtime_hooks": [
                {
                    "language": "python",
                    "implemented": True,
                    "activation": "PYTHONPATH preload via sitecustomize.py",
                    "logical_path": "/workspace/src/repo_health_doctor/sandbox_hooks/python/sitecustomize.py",
                    "logical_directory": "/workspace/src/repo_health_doctor/sandbox_hooks/python",
                    "event_sink": "/tmp/tmp/rhd-observer-events.jsonl",
                    "coverage": [
                        "dns_lookup",
                        "socket_connect",
                        "subprocess_spawn",
                        "secret_file_open",
                        "secret_env_access",
                        "env_sweep",
                        "file_delete_attempt",
                    ],
                    "limitations": [],
                }
            ],
            "runtime_hook_active_languages": ["python"],
            "pass_possible": False,
            "event_sink": "/tmp/tmp/rhd-observer-events.jsonl",
            "phase2_ready": True,
            "phase3_ready": True,
            "limitations": ["runtime-hook-only observation cannot PASS"],
        }

        with mock.patch(
            "repo_health_doctor.sandbox.command.run_docker_preflight",
            return_value={
                "requested": True,
                "performed": True,
                "status": "passed",
                "timeout_seconds": 7,
                "commands": [],
                "results": [],
                "limitations": [],
                "phase_gate_limitations": [],
            },
        ), mock.patch(
            "repo_health_doctor.sandbox.command.run_phase1_fetch",
            return_value={
                "requested": True,
                "performed": True,
                "status": "passed",
                "network_mode": "bridge",
                "timeout_seconds": 11,
                "results": [],
                "limitations": [],
                "phase_gate_limitations": [],
            },
        ), mock.patch(
            "repo_health_doctor.sandbox.command.run_phase1_rescan",
            return_value={
                "requested": True,
                "performed": True,
                "status": "passed",
                "artifact_summary": {
                    "scanned_file_count": 1,
                    "artifact_candidate_count": 1,
                    "read_error_count": 0,
                    "artifact_kind_counts": {
                        "node_package_manifest": 1,
                        "python_archive": 0,
                        "plain_text_artifact": 0,
                    },
                },
                "findings": [],
                "limitations": [],
            },
        ), mock.patch(
            "repo_health_doctor.sandbox.command.build_observer_plan",
            return_value=degraded_ready_observer,
        ), mock.patch(
            "repo_health_doctor.sandbox.dynamic.subprocess.run",
            return_value=completed,
        ):
            report = run_sandbox(
                repo_path,
                approval_file=approval_path,
                docker_image="python:3.12-slim-bookworm@sha256:0123456789abcdef",
                run_preflight=True,
                run_phase1=True,
                run_phase3=True,
            )

        phase3 = report["sandbox"]["phase3_runtime_probes"]
        secret_check = next(item for item in report["checks"] if item["id"] == "sandbox.dynamic_secret_access")
        self.assertEqual(phase3["status"], "degraded")
        self.assertTrue(phase3["performed"])
        self.assertEqual(secret_check["status"], "warn")
        self.assertEqual(secret_check["evidence"]["phase_statuses"]["phase3"]["status"], "degraded")
        self.assertIn("observer_degraded", secret_check["evidence"]["result_status_counts"])
        self.assertIn("syscall_trace", secret_check["evidence"])

    def test_slice3_remains_plan_only_even_with_approval_file(self) -> None:
        repo_path = self._write_demo_repo()
        baseline = run_sandbox(repo_path)
        approval_path = self.tmp_path / "approved.json"
        approval_path.write_text(
            json.dumps({"commands": [baseline["execution_plan"]["commands"][0]]}),
            encoding="utf-8",
        )

        report = run_sandbox(repo_path, approval_file=approval_path)

        self.assertFalse(report["sandbox"]["docker_spec"]["execution_enabled"])
        self.assertFalse(report["sandbox"]["disposable_workspace"]["execution_enabled"])
        phase1 = next(item for item in report["phase_plan"] if item["phase"] == "phase1_fetch")
        dynamic_check = next(item for item in report["checks"] if item["id"] == "sandbox.dynamic_execution")
        self.assertFalse(phase1["execution_enabled"])
        self.assertEqual(report["execution_plan"]["approval"]["matched_command_count"], 1)
        self.assertFalse(dynamic_check["evidence"]["dynamic_observation"]["observation"]["performed"])
        self.assertEqual(dynamic_check["evidence"]["dynamic_observation"]["phase_statuses"]["phase2"]["status"], "not_requested")
        self.assertEqual(dynamic_check["evidence"]["dynamic_observation"]["phase_statuses"]["phase3"]["status"], "not_requested")

    def test_docker_argv_resolution_uses_disposable_mounts_and_redacts_report_view(self) -> None:
        repo_path = self._write_demo_repo()
        workspace_plan = build_disposable_workspace_plan()
        materialized = materialize_disposable_workspace(repo_path, workspace_plan)
        try:
            docker_spec = build_docker_spec(detected_languages=["node", "python"], workspace_plan=workspace_plan)
            resolved = resolve_docker_argv(docker_spec, materialized)
            raw_argv = resolved["raw_argv"]
            redacted_argv = resolved["resolved_argv_redacted"]
            raw_text = "\n".join(raw_argv)
            redacted_text = "\n".join(redacted_argv)

            self.assertIsInstance(raw_argv, list)
            self.assertNotIn(" ".join(raw_argv), raw_argv)
            self.assertIn(str(materialized.host_paths["workspace"]), raw_text)
            self.assertNotIn(str(repo_path.resolve()), raw_text)
            self.assertNotIn("/var/run/docker.sock", raw_text)
            self.assertNotIn(str(Path.home()), raw_text)
            self.assertIn("<workspace>", redacted_text)
            self.assertNotIn(str(materialized.host_paths["workspace"]), redacted_text)
            self.assertNotIn(str(repo_path.resolve()), redacted_text)
        finally:
            materialized.cleanup()

    def test_preflight_is_skipped_without_digest_pinned_image(self) -> None:
        repo_path = self._write_demo_repo()
        with mock.patch("repo_health_doctor.sandbox.preflight.subprocess.run") as mocked_run:
            report = run_sandbox(
                repo_path,
                run_preflight=True,
                docker_image="python:3.12-slim-bookworm",
            )

        self.assertFalse(mocked_run.called)
        self.assertEqual(report["sandbox"]["preflight"]["status"], "skipped")
        image_policy_check = next(item for item in report["checks"] if item["id"] == "sandbox.image_policy")
        self.assertEqual(image_policy_check["status"], "warn")
        self.assertEqual(image_policy_check["evidence"]["image_reference_kind"], "tag_only_rejected")
        self.assertEqual(image_policy_check["evidence"]["decision"], "rejected")

    def test_registry_digest_image_policy_remains_accepted(self) -> None:
        repo_path = self._write_demo_repo()
        report = run_sandbox(
            repo_path,
            docker_image="python:3.12-slim-bookworm@sha256:0123456789abcdef",
        )

        image_policy_check = next(item for item in report["checks"] if item["id"] == "sandbox.image_policy")
        self.assertEqual(image_policy_check["status"], "pass")
        self.assertEqual(image_policy_check["evidence"]["image_reference_kind"], "registry_digest")
        self.assertTrue(image_policy_check["evidence"]["selected_image_digest_pinned"])
        self.assertEqual(image_policy_check["evidence"]["decision"], "accepted")

    def test_local_image_is_rejected_without_expected_full_image_id(self) -> None:
        repo_path = self._write_demo_repo()
        with mock.patch("repo_health_doctor.sandbox.docker.subprocess.run") as mocked_inspect:
            report = run_sandbox(
                repo_path,
                docker_image="rhd-python312-strace:local",
                allow_local_image=True,
            )

        self.assertFalse(mocked_inspect.called)
        image_policy_check = next(item for item in report["checks"] if item["id"] == "sandbox.image_policy")
        self.assertEqual(image_policy_check["status"], "warn")
        self.assertEqual(image_policy_check["evidence"]["image_reference_kind"], "tag_only_rejected")
        self.assertIsNone(image_policy_check["evidence"]["actual_image_id"])
        self.assertEqual(image_policy_check["evidence"]["decision"], "rejected")

    def test_local_image_is_rejected_with_short_expected_image_id(self) -> None:
        repo_path = self._write_demo_repo()
        with mock.patch("repo_health_doctor.sandbox.docker.subprocess.run") as mocked_inspect:
            report = run_sandbox(
                repo_path,
                docker_image="rhd-python312-strace:local",
                allow_local_image=True,
                expected_image_id="sha256:58513b66cedd",
            )

        self.assertFalse(mocked_inspect.called)
        image_policy_check = next(item for item in report["checks"] if item["id"] == "sandbox.image_policy")
        self.assertEqual(image_policy_check["status"], "warn")
        self.assertFalse(image_policy_check["evidence"]["image_id_match"])
        self.assertEqual(image_policy_check["evidence"]["decision"], "rejected")

    def test_local_image_is_accepted_when_expected_full_image_id_matches(self) -> None:
        repo_path = self._write_demo_repo()
        with mock.patch(
            "repo_health_doctor.sandbox.docker.subprocess.run",
            return_value=self._docker_inspect_result(self.LOCAL_IMAGE_ID),
        ) as mocked_inspect:
            report = run_sandbox(
                repo_path,
                docker_image="rhd-python312-strace:local",
                allow_local_image=True,
                expected_image_id=self.LOCAL_IMAGE_ID,
            )

        self.assertTrue(mocked_inspect.called)
        image_policy_check = next(item for item in report["checks"] if item["id"] == "sandbox.image_policy")
        payload = json.dumps(report)
        self.assertEqual(image_policy_check["status"], "pass")
        self.assertEqual(image_policy_check["evidence"]["image_reference_kind"], "local_sanctioned_image")
        self.assertEqual(image_policy_check["evidence"]["expected_image_id"], self.LOCAL_IMAGE_ID)
        self.assertEqual(image_policy_check["evidence"]["actual_image_id"], self.LOCAL_IMAGE_ID)
        self.assertTrue(image_policy_check["evidence"]["image_id_match"])
        self.assertTrue(image_policy_check["evidence"]["local_sanctioned"])
        self.assertEqual(image_policy_check["evidence"]["decision"], "accepted")
        self.assertIn(self.LOCAL_IMAGE_ID, payload)
        self.assertNotIn(str(repo_path.resolve()), payload)

    def test_local_image_is_rejected_when_expected_image_id_mismatches(self) -> None:
        repo_path = self._write_demo_repo()
        mismatch_id = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        with mock.patch(
            "repo_health_doctor.sandbox.docker.subprocess.run",
            return_value=self._docker_inspect_result(self.LOCAL_IMAGE_ID),
        ):
            report = run_sandbox(
                repo_path,
                docker_image="rhd-python312-strace:local",
                allow_local_image=True,
                expected_image_id=mismatch_id,
                run_preflight=True,
            )

        image_policy_check = next(item for item in report["checks"] if item["id"] == "sandbox.image_policy")
        self.assertEqual(image_policy_check["status"], "warn")
        self.assertEqual(image_policy_check["evidence"]["actual_image_id"], self.LOCAL_IMAGE_ID)
        self.assertFalse(image_policy_check["evidence"]["image_id_match"])
        self.assertEqual(image_policy_check["evidence"]["decision"], "rejected")
        self.assertEqual(report["sandbox"]["preflight"]["status"], "skipped")

    def test_strace_smoke_is_skipped_when_local_image_id_mismatches(self) -> None:
        repo_path = self._write_demo_repo()
        mismatch_id = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        with mock.patch(
            "repo_health_doctor.sandbox.docker.subprocess.run",
            return_value=self._docker_inspect_result(self.LOCAL_IMAGE_ID),
        ) as mocked_run:
            report = run_sandbox(
                repo_path,
                docker_image="rhd-python312-strace:local",
                allow_local_image=True,
                expected_image_id=mismatch_id,
                run_preflight=True,
                run_strace_smoke=True,
            )

        self.assertEqual(mocked_run.call_count, 1)
        self.assertEqual(report["sandbox"]["preflight"]["status"], "skipped")
        self.assertEqual(report["sandbox"]["strace_target_wrap_smoke"]["status"], "skipped")
        self.assertIn("image ID", " ".join(report["sandbox"]["strace_target_wrap_smoke"]["limitations"]))

    def test_preflight_runs_only_fixed_harmless_commands_with_pinned_image(self) -> None:
        repo_path = self._write_demo_repo()
        completed = subprocess.CompletedProcess(args=["docker"], returncode=0, stdout="", stderr="")
        with mock.patch(
            "repo_health_doctor.sandbox.preflight.subprocess.run",
            side_effect=[completed, completed, completed],
        ) as mocked_run:
            report = run_sandbox(
                repo_path,
                run_preflight=True,
                docker_image="python:3.12-slim-bookworm@sha256:0123456789abcdef",
                preflight_timeout_seconds=7,
            )

        preflight = report["sandbox"]["preflight"]
        self.assertEqual(preflight["status"], "passed")
        self.assertTrue(preflight["performed"])
        self.assertEqual(preflight["timeout_seconds"], 7)
        self.assertEqual(len(preflight["results"]), 3)
        first_call = mocked_run.call_args_list[0]
        second_call = mocked_run.call_args_list[1]
        third_call = mocked_run.call_args_list[2]
        self.assertIn("--entrypoint", first_call.args[0])
        self.assertEqual(first_call.args[0][first_call.args[0].index("--entrypoint") + 1], "true")
        self.assertIn("--entrypoint", second_call.args[0])
        self.assertEqual(second_call.args[0][second_call.args[0].index("--entrypoint") + 1], "id")
        self.assertIn("--entrypoint", third_call.args[0])
        self.assertEqual(third_call.args[0][third_call.args[0].index("--entrypoint") + 1], "strace")
        self.assertEqual(third_call.args[0][-1], "-V")
        self.assertFalse(first_call.kwargs["shell"])
        self.assertFalse(second_call.kwargs["shell"])
        self.assertFalse(third_call.kwargs["shell"])

    def test_preflight_runs_with_sanctioned_local_image_and_does_not_enter_phase2_or_phase3(self) -> None:
        repo_path = self._write_demo_repo()
        completed = subprocess.CompletedProcess(args=["docker"], returncode=0, stdout="", stderr="")
        strace_completed = subprocess.CompletedProcess(args=["docker"], returncode=0, stdout="strace -- version 6.13", stderr="")

        def _run_side_effect(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            if argv[:3] == ["docker", "image", "inspect"]:
                return self._docker_inspect_result(self.LOCAL_IMAGE_ID)
            entrypoint = argv[argv.index("--entrypoint") + 1]
            if entrypoint == "strace":
                return strace_completed
            return completed

        with mock.patch(
            "repo_health_doctor.sandbox.docker.subprocess.run",
            side_effect=_run_side_effect,
        ) as mocked_run:
            report = run_sandbox(
                repo_path,
                docker_image="rhd-python312-strace:local",
                allow_local_image=True,
                expected_image_id=self.LOCAL_IMAGE_ID,
                run_preflight=True,
            )

        preflight = report["sandbox"]["preflight"]
        observer = report["sandbox"]["observer"]
        docker_spec = report["sandbox"]["docker_spec"]
        payload = json.dumps(report)
        self.assertEqual(preflight["status"], "passed")
        self.assertTrue(preflight["performed"])
        self.assertEqual(len(preflight["results"]), 3)
        self.assertTrue(observer["syscall_observer"]["available"])
        self.assertTrue(observer["syscall_observer"]["active"])
        self.assertTrue(observer["pass_possible"])
        self.assertIn("full syscall tracing", " ".join(observer["limitations"]))
        self.assertEqual(report["sandbox"]["phase2_install_probes"]["status"], "not_requested")
        self.assertEqual(report["sandbox"]["phase3_runtime_probes"]["status"], "not_requested")
        self.assertTrue(docker_spec["selected_image_execution_allowed"])
        self.assertEqual(docker_spec["image_reference_kind"], "local_sanctioned_image")
        first_preflight_call = mocked_run.call_args_list[1]
        strace_preflight_call = mocked_run.call_args_list[3]
        self.assertIn("--pull=never", first_preflight_call.args[0])
        self.assertIn("--network", first_preflight_call.args[0])
        self.assertIn("--entrypoint", strace_preflight_call.args[0])
        self.assertFalse(first_preflight_call.kwargs["shell"])
        self.assertEqual(report["sandbox"]["disposable_workspace"]["cleanup_status"], "completed")
        self.assertNotIn(str(repo_path.resolve()), payload)

    def test_strace_target_wrap_smoke_runs_with_sanctioned_local_image(self) -> None:
        repo_path = self._write_demo_repo()
        completed = subprocess.CompletedProcess(args=["docker"], returncode=0, stdout="", stderr="")
        strace_completed = subprocess.CompletedProcess(args=["docker"], returncode=0, stdout="strace -- version 6.13", stderr="")
        smoke_completed = subprocess.CompletedProcess(args=["docker"], returncode=0, stdout="12345\n", stderr="")

        def _run_side_effect(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            if argv[:3] == ["docker", "image", "inspect"]:
                return self._docker_inspect_result(self.LOCAL_IMAGE_ID)
            entrypoint = argv[argv.index("--entrypoint") + 1]
            if entrypoint == "strace" and "-V" not in argv:
                tmp_mount = next(
                    token for token in argv if isinstance(token, str) and "type=bind,src=" in token and "dst=/tmp/tmp" in token
                )
                src_path = tmp_mount.split("src=", 1)[1].split(",dst=", 1)[0]
                Path(src_path, "rhd-strace.smoke.12345").write_text(
                    "\n".join(
                        [
                            'execve("/usr/local/bin/python", ["python", "-c", "..."], 0x0) = 0',
                            'openat(AT_FDCWD, "/tmp/tmp/rhd-strace-smoke.txt", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3',
                            'write(3, "ok", 2) = 2',
                            'exit_group(0) = ?',
                        ]
                    )
                    + "\n",
                    encoding="utf-8",
                )
                return smoke_completed
            if entrypoint == "strace":
                return strace_completed
            return completed

        with mock.patch(
            "repo_health_doctor.sandbox.docker.subprocess.run",
            side_effect=_run_side_effect,
        ) as mocked_run:
            report = run_sandbox(
                repo_path,
                docker_image="rhd-python312-strace:local",
                allow_local_image=True,
                expected_image_id=self.LOCAL_IMAGE_ID,
                run_preflight=True,
                run_strace_smoke=True,
            )

        smoke = report["sandbox"]["strace_target_wrap_smoke"]
        smoke_check = next(item for item in report["checks"] if item["id"] == "sandbox.strace_target_wrap_smoke")
        observer_summary = smoke["results"][0]["observer_summary"]
        payload = json.dumps(report)
        self.assertEqual(smoke["status"], "passed")
        self.assertTrue(smoke["performed"])
        self.assertEqual(smoke["target_argv"][0], "python")
        self.assertIsInstance(smoke["wrapper_argv"], list)
        self.assertIn("--entrypoint", smoke["wrapper_argv"])
        self.assertEqual(smoke["wrapper_argv"][smoke["wrapper_argv"].index("--entrypoint") + 1], "strace")
        self.assertEqual(smoke_check["status"], "pass")
        self.assertEqual(observer_summary["syscall_event_type_counts"]["execve"], 1)
        self.assertEqual(observer_summary["syscall_event_type_counts"]["openat"], 1)
        self.assertEqual(observer_summary["syscall_event_type_counts"]["write"], 1)
        self.assertEqual(observer_summary["syscall_event_type_counts"]["exit_group"], 1)
        self.assertEqual(observer_summary["network_event_count"], 0)
        self.assertGreater(observer_summary["syscall_log_file_count"], 0)
        self.assertIn("/tmp/tmp/rhd-strace.smoke.12345", observer_summary["syscall_log_handles"])
        self.assertIn("harmless target only", " ".join(smoke["limitations"]))
        self.assertEqual(report["sandbox"]["phase2_install_probes"]["status"], "not_requested")
        self.assertEqual(report["sandbox"]["phase3_runtime_probes"]["status"], "not_requested")
        smoke_call = mocked_run.call_args_list[4]
        self.assertFalse(smoke_call.kwargs["shell"])
        self.assertNotIn(str(repo_path.resolve()), payload)

    def test_preflight_optional_strace_probe_can_fail_without_failing_docker_gate(self) -> None:
        repo_path = self._write_demo_repo()
        completed = subprocess.CompletedProcess(args=["docker"], returncode=0, stdout="", stderr="")
        missing_probe = subprocess.CompletedProcess(args=["docker"], returncode=127, stdout="", stderr="strace missing")
        with mock.patch(
            "repo_health_doctor.sandbox.preflight.subprocess.run",
            side_effect=[completed, completed, missing_probe],
        ):
            report = run_sandbox(
                repo_path,
                run_preflight=True,
                docker_image="python:3.12-slim-bookworm@sha256:0123456789abcdef",
            )

        preflight = report["sandbox"]["preflight"]
        observer = report["sandbox"]["observer"]
        self.assertEqual(preflight["status"], "passed")
        self.assertEqual(preflight["results"][-1]["command_kind"], "syscall_observer_preflight")
        self.assertEqual(preflight["results"][-1]["status"], "probe_unavailable")
        self.assertFalse(observer["syscall_observer"]["active"])
        self.assertFalse(observer["pass_possible"])
        self.assertIn("strace", " ".join(preflight["limitations"]))

    def test_preflight_failure_blocks_when_docker_is_unavailable(self) -> None:
        repo_path = self._write_demo_repo()
        with mock.patch(
            "repo_health_doctor.sandbox.preflight.subprocess.run",
            side_effect=FileNotFoundError("docker missing"),
        ):
            report = run_sandbox(
                repo_path,
                run_preflight=True,
                docker_image="python:3.12-slim-bookworm@sha256:0123456789abcdef",
            )

        preflight = report["sandbox"]["preflight"]
        preflight_check = next(item for item in report["checks"] if item["id"] == "sandbox.docker_preflight")
        self.assertEqual(preflight["status"], "failed")
        self.assertEqual(preflight_check["status"], "block")
        self.assertTrue(preflight["results"])

    def test_phase3_activates_syscall_observer_when_preflight_confirms_strace(self) -> None:
        repo_path = self._write_demo_repo()
        baseline = run_sandbox(repo_path)
        approved_runtime = next(
            command
            for command in baseline["execution_plan"]["commands"]
            if command["phase"] == "phase3_runtime_probe" and command["kind"] == "test_probe"
        )
        approval_path = self.tmp_path / "approved-runtime-strace.json"
        approval_path.write_text(json.dumps({"commands": [approved_runtime]}), encoding="utf-8")
        completed = subprocess.CompletedProcess(args=["docker"], returncode=0, stdout="", stderr="")

        with mock.patch(
            "repo_health_doctor.sandbox.command.run_docker_preflight",
            return_value={
                "requested": True,
                "performed": True,
                "status": "passed",
                "timeout_seconds": 7,
                "commands": [],
                "results": [
                    {
                        "command_kind": "docker_preflight",
                        "argv": ["docker", "run", "true"],
                        "return_code": 0,
                        "status": "passed",
                        "timed_out": False,
                        "stdout_summary": "",
                        "stderr_summary": "",
                    },
                    {
                        "command_kind": "docker_preflight",
                        "argv": ["docker", "run", "id"],
                        "return_code": 0,
                        "status": "passed",
                        "timed_out": False,
                        "stdout_summary": "",
                        "stderr_summary": "",
                    },
                    {
                        "command_kind": "syscall_observer_preflight",
                        "argv": ["docker", "run", "strace", "-V"],
                        "return_code": 0,
                        "status": "passed",
                        "timed_out": False,
                        "stdout_summary": "strace 6.0",
                        "stderr_summary": "",
                    },
                ],
                "limitations": [],
                "phase_gate_limitations": [],
            },
        ), mock.patch(
            "repo_health_doctor.sandbox.command.run_phase1_fetch",
            return_value={
                "requested": True,
                "performed": True,
                "status": "passed",
                "network_mode": "bridge",
                "timeout_seconds": 11,
                "results": [],
                "limitations": [],
                "phase_gate_limitations": [],
            },
        ), mock.patch(
            "repo_health_doctor.sandbox.command.run_phase1_rescan",
            return_value={
                "requested": True,
                "performed": True,
                "status": "passed",
                "artifact_summary": {
                    "scanned_file_count": 1,
                    "artifact_candidate_count": 1,
                    "read_error_count": 0,
                    "artifact_kind_counts": {
                        "node_package_manifest": 1,
                        "python_archive": 0,
                        "plain_text_artifact": 0,
                    },
                },
                "findings": [],
                "limitations": [],
            },
        ), mock.patch(
            "repo_health_doctor.sandbox.dynamic.subprocess.run",
            return_value=completed,
        ) as mocked_dynamic_run:
            report = run_sandbox(
                repo_path,
                approval_file=approval_path,
                docker_image="python:3.12-slim-bookworm@sha256:0123456789abcdef",
                run_preflight=True,
                run_phase1=True,
                run_phase3=True,
            )

        self.assertTrue(report["sandbox"]["observer"]["syscall_observer"]["active"])
        self.assertTrue(report["sandbox"]["observer"]["pass_possible"])
        dynamic_argv = mocked_dynamic_run.call_args.args[0]
        self.assertIn("strace", dynamic_argv)
        self.assertIn(
            "trace=execve,execveat,open,openat,write,writev,exit_group,connect,sendto,sendmsg,clone,clone3,fork,vfork,unlink,unlinkat,rmdir",
            dynamic_argv,
        )
        self.assertIn("PIP_DISABLE_PIP_VERSION_CHECK=1", dynamic_argv)
        self.assertIn("PIP_NO_INDEX=1", dynamic_argv)

    def test_phase3_syscall_trace_blocks_network_activity_when_probe_active(self) -> None:
        repo_path = self._write_demo_repo()
        baseline = run_sandbox(repo_path)
        approved_runtime = next(
            command
            for command in baseline["execution_plan"]["commands"]
            if command["phase"] == "phase3_runtime_probe" and command["kind"] == "test_probe"
        )
        approval_path = self.tmp_path / "approved-runtime-strace-block.json"
        approval_path.write_text(json.dumps({"commands": [approved_runtime]}), encoding="utf-8")

        def _write_strace_log(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            tmp_mount = next(
                token for token in argv if isinstance(token, str) and "type=bind,src=" in token and "dst=/tmp/tmp" in token
            )
            src_path = tmp_mount.split("src=", 1)[1].split(",dst=", 1)[0]
            Path(src_path, "rhd-strace.123").write_text(
                '123 connect(3, {sa_family=AF_INET, sin_port=htons(443)}, 16) = -1 EINPROGRESS\n',
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(args=argv, returncode=0, stdout="", stderr="")

        with mock.patch(
            "repo_health_doctor.sandbox.command.run_docker_preflight",
            return_value={
                "requested": True,
                "performed": True,
                "status": "passed",
                "timeout_seconds": 7,
                "commands": [],
                "results": [
                    {
                        "command_kind": "syscall_observer_preflight",
                        "argv": ["docker", "run", "strace", "-V"],
                        "return_code": 0,
                        "status": "passed",
                        "timed_out": False,
                        "stdout_summary": "strace 6.0",
                        "stderr_summary": "",
                    }
                ],
                "limitations": [],
                "phase_gate_limitations": [],
            },
        ), mock.patch(
            "repo_health_doctor.sandbox.command.run_phase1_fetch",
            return_value={
                "requested": True,
                "performed": True,
                "status": "passed",
                "network_mode": "bridge",
                "timeout_seconds": 11,
                "results": [],
                "limitations": [],
                "phase_gate_limitations": [],
            },
        ), mock.patch(
            "repo_health_doctor.sandbox.command.run_phase1_rescan",
            return_value={
                "requested": True,
                "performed": True,
                "status": "passed",
                "artifact_summary": {
                    "scanned_file_count": 1,
                    "artifact_candidate_count": 1,
                    "read_error_count": 0,
                    "artifact_kind_counts": {
                        "node_package_manifest": 1,
                        "python_archive": 0,
                        "plain_text_artifact": 0,
                    },
                },
                "findings": [],
                "limitations": [],
            },
        ), mock.patch(
            "repo_health_doctor.sandbox.dynamic.subprocess.run",
            side_effect=_write_strace_log,
        ):
            report = run_sandbox(
                repo_path,
                approval_file=approval_path,
                docker_image="python:3.12-slim-bookworm@sha256:0123456789abcdef",
                run_preflight=True,
                run_phase1=True,
                run_phase3=True,
            )

        phase3 = report["sandbox"]["phase3_runtime_probes"]
        external_check = next(item for item in report["checks"] if item["id"] == "sandbox.dynamic_external_communication")
        self.assertEqual(phase3["status"], "blocked")
        self.assertEqual(external_check["status"], "block")
        self.assertGreater(phase3["results"][0]["observer_summary"]["network_event_count"], 0)

    def test_parse_strace_events_ignores_relative_unlinkat_for_outside_delete_count(self) -> None:
        repo_path = self._write_demo_repo()
        materialized = materialize_disposable_workspace(repo_path, build_disposable_workspace_plan())
        try:
            strace_path = materialized.host_paths["tmp"] / "rhd-strace.123"
            strace_path.write_text(
                "\n".join(
                    [
                        'unlink("/tmp/tmp/pip-build-tracker-demo/item") = 0',
                        'unlinkat(3, "input.json", 0) = 0',
                        'rmdir("/tmp/tmp/pip-modern-metadata-demo") = 0',
                        'unlink("/etc/passwd") = -1 EACCES (Permission denied)',
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            summary = sandbox_dynamic._parse_strace_events(materialized)

            self.assertEqual(summary["delete_inside_writable_count"], 2)
            self.assertEqual(summary["delete_outside_writable_count"], 1)
        finally:
            materialized.cleanup()

    def test_report_includes_materialization_and_redacted_docker_resolution(self) -> None:
        repo_path = self._write_demo_repo()
        report = run_sandbox(repo_path)
        payload = json.dumps(report)
        docker_spec = report["sandbox"]["docker_spec"]
        workspace_report = report["sandbox"]["disposable_workspace"]

        self.assertEqual(workspace_report["materialization_status"], "completed")
        self.assertEqual(workspace_report["cleanup_status"], "completed")
        self.assertEqual(docker_spec["path_resolution_status"], "completed")
        self.assertTrue(docker_spec["resolved_argv_redacted"])
        self.assertIn("<workspace>", "\n".join(docker_spec["resolved_argv_redacted"]))
        self.assertNotIn(str(repo_path.resolve()), payload)
        self.assertIn("<sandbox-root>", payload)

    def test_sandbox_report_matches_schema(self) -> None:
        repo_path = self._write_demo_repo()
        report = json.loads(format_sandbox_json(run_sandbox(repo_path)))
        schema = json.loads(SANDBOX_SCHEMA_PATH.read_text(encoding="utf-8"))

        _assert_matches_schema(self, report, schema)

    def test_sandbox_cli_outputs_json(self) -> None:
        repo_path = self._write_demo_repo()
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor",
                "sandbox",
                str(repo_path),
                "--format",
                "json",
            ],
            check=True,
            capture_output=True,
            text=True,
            env=self._cli_env(),
        )

        payload = json.loads(result.stdout)
        self.assertEqual(payload["report_kind"], REPORT_KIND_SANDBOX)
        self.assertEqual(payload["execution_plan"]["mode"], "plan_only")
        self.assertIn("phase_plan", payload)
        self.assertIn("preflight", payload["sandbox"])
        self.assertIn("phase1_5_rescan", payload["sandbox"])
        self.assertIn("observer", payload["sandbox"])
        self.assertIn("phase2_install_probes", payload["sandbox"])
        self.assertIn("phase3_runtime_probes", payload["sandbox"])

    def test_sandbox_help_is_sandbox_focused(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "repo_health_doctor",
                "sandbox",
                "--help",
            ],
            check=True,
            capture_output=True,
            text=True,
            env=self._cli_env(),
        )

        self.assertIn("sandbox", result.stdout)
        self.assertIn("--approval-file", result.stdout)
        self.assertIn("--run-preflight", result.stdout)
        self.assertIn("--run-phase1", result.stdout)
        self.assertIn("--run-phase2", result.stdout)
        self.assertIn("--run-phase3", result.stdout)
        self.assertIn("--docker-image", result.stdout)
        self.assertNotIn("--public-safety", result.stdout)
        self.assertNotIn("--config", result.stdout)

    def test_existing_commands_still_parse_after_sandbox_addition(self) -> None:
        validate_parser = build_parser("validate-policy")
        release_parser = build_parser("release-check")

        validate_args = validate_parser.parse_args(["."])
        release_args = release_parser.parse_args(["."])

        self.assertEqual(validate_args.path, ".")
        self.assertEqual(release_args.path, ".")
