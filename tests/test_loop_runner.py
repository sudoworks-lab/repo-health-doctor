from __future__ import annotations

import json
import os
import signal
import shutil
import subprocess
import tempfile
import textwrap
import time
import unittest
from datetime import datetime
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
LOOP_SCRIPT = REPO_ROOT / "scripts" / "loop.sh"
FALLBACK_SCRIPT = REPO_ROOT / "scripts" / "goal_loop_fallback.sh"
METADATA_KEYS = {
    "run_id",
    "start_time",
    "end_time",
    "agent",
    "max_iterations",
    "iteration",
    "completion_state",
    "feature_completion_state",
    "agent_exit_code",
    "host_commit_exit_code",
    "runner_exit_code",
    "git_head_before",
    "git_head_after",
    "git_status_before",
    "git_status_after",
    "log_paths",
    "signal",
    "interruption_reason",
    "codex_thread_id",
    "feature_id",
    "feature_title",
    "attempt",
    "max_attempts_per_feature",
    "timeout_limit_seconds",
    "timeout_at",
    "elapsed_seconds",
    "termination_method",
    "feature_state",
    "tests_started",
    "tests_completed",
    "retryable",
    "human_action",
}
CODEX_EVENT_LINES = [
    '{"type":"thread.started","thread_id":"thread-safe-123"}',
    '{"type":"command","command":"true"}',
    '{"type":"file_change","path":"example.txt"}',
    '{"type":"agent_message","text":"working"}',
    '{"type":"turn.completed","usage":{"input_tokens":1}}',
    '{"type":"error","message":"retained diagnostic event"}',
]

CODEX_FAKE = textwrap.dedent(
    r"""
    #!/usr/bin/env python3
    import os
    import sys
    import time
    from pathlib import Path

    args = sys.argv[1:]
    expected_prefix = ["exec", "--json", "--output-last-message"]
    expected_suffix = ["--sandbox", "workspace-write", "-"]
    if args[:3] != expected_prefix or args[4:] != expected_suffix:
        print(f"unexpected arguments: {args!r}", file=sys.stderr)
        raise SystemExit(64)
    prompt = sys.stdin.read()
    if "feature ID: F001" not in prompt or "Run one iteration.\n" not in prompt:
        print("unexpected prompt", file=sys.stderr)
        raise SystemExit(65)
    if os.environ.get("FAKE_PID_FILE"):
        Path(os.environ["FAKE_PID_FILE"]).write_text(str(os.getpid()), encoding="utf-8")
    if os.environ.get("FAKE_SLEEP"):
        time.sleep(float(os.environ["FAKE_SLEEP"]))

    if os.environ.get("FAKE_MARK_PASS") == "1":
        features_path = Path("docs/features.json")
        import json
        document = json.loads(features_path.read_text(encoding="utf-8"))
        document["features"][0]["passes"] = True
        document["features"][0]["verified_at"] = "2026-07-11T00:00:00+09:00"
        features_path.write_text(json.dumps(document) + "\n", encoding="utf-8")

    if os.environ.get("FAKE_MARK_BLOCKED") == "1":
        features_path = Path("docs/features.json")
        import json
        document = json.loads(features_path.read_text(encoding="utf-8"))
        document["features"][0]["blocked"] = True
        features_path.write_text(json.dumps(document) + "\n", encoding="utf-8")

    iteration_file = Path("iteration.txt")
    iteration_file.write_text(os.environ["GOAL_LOOP_COMMIT_REQUEST"] + "\n", encoding="utf-8")
    request_paths = ["iteration.txt"]
    if os.environ.get("FAKE_MARK_PASS") == "1" or os.environ.get("FAKE_MARK_BLOCKED") == "1":
        request_paths.append("docs/features.json")
    import json
    Path(os.environ["GOAL_LOOP_COMMIT_REQUEST"]).write_text(
        json.dumps({"message": "test: fake iteration", "paths": request_paths}) + "\n",
        encoding="utf-8",
    )

    lines = [
        '{"type":"thread.started","thread_id":"thread-safe-123"}',
        '{"type":"command","command":"true"}',
        '{"type":"file_change","path":"example.txt"}',
        '{"type":"agent_message","text":"working"}',
        '{"type":"turn.completed","usage":{"input_tokens":1}}',
        '{"type":"error","message":"retained diagnostic event"}',
    ]
    for line in lines:
        print(line)
    Path(args[3]).write_text(
        os.environ.get("FAKE_FINAL", "work remains\n"),
        encoding="utf-8",
    )
    if os.environ.get("FAKE_REMOVE_FINAL") == "1":
        Path(args[3]).unlink()
    sys.stderr.write(os.environ.get("FAKE_STDERR", "fake codex stderr\n"))
    raise SystemExit(int(os.environ.get("FAKE_EXIT", "0")))
    """
).lstrip()

CLAUDE_FAKE = textwrap.dedent(
    r"""
    #!/usr/bin/env python3
    import os
    import sys
    import time
    from pathlib import Path

    expected = ["-p", "--permission-mode", "acceptEdits"]
    if sys.argv[1:] != expected:
        print(f"unexpected arguments: {sys.argv[1:]!r}", file=sys.stderr)
        raise SystemExit(64)
    prompt = sys.stdin.read()
    if "feature ID: F001" not in prompt or "Run one iteration.\n" not in prompt:
        print("unexpected prompt", file=sys.stderr)
        raise SystemExit(65)
    if os.environ.get("FAKE_PID_FILE"):
        Path(os.environ["FAKE_PID_FILE"]).write_text(str(os.getpid()), encoding="utf-8")
    if os.environ.get("FAKE_SLEEP"):
        time.sleep(float(os.environ["FAKE_SLEEP"]))

    if os.environ.get("FAKE_MARK_PASS") == "1":
        features_path = Path("docs/features.json")
        import json
        document = json.loads(features_path.read_text(encoding="utf-8"))
        document["features"][0]["passes"] = True
        document["features"][0]["verified_at"] = "2026-07-11T00:00:00+09:00"
        features_path.write_text(json.dumps(document) + "\n", encoding="utf-8")

    if os.environ.get("FAKE_MARK_BLOCKED") == "1":
        features_path = Path("docs/features.json")
        import json
        document = json.loads(features_path.read_text(encoding="utf-8"))
        document["features"][0]["blocked"] = True
        features_path.write_text(json.dumps(document) + "\n", encoding="utf-8")

    iteration_file = Path("iteration.txt")
    iteration_file.write_text(os.environ["GOAL_LOOP_COMMIT_REQUEST"] + "\n", encoding="utf-8")
    request_paths = ["iteration.txt"]
    if os.environ.get("FAKE_MARK_PASS") == "1" or os.environ.get("FAKE_MARK_BLOCKED") == "1":
        request_paths.append("docs/features.json")
    import json
    Path(os.environ["GOAL_LOOP_COMMIT_REQUEST"]).write_text(
        json.dumps({"message": "test: fake iteration", "paths": request_paths}) + "\n",
        encoding="utf-8",
    )

    sys.stdout.write(os.environ.get("FAKE_FINAL", "work remains\n"))
    sys.stderr.write(os.environ.get("FAKE_STDERR", "fake claude stderr\n"))
    raise SystemExit(int(os.environ.get("FAKE_EXIT", "0")))
    """
).lstrip()


class LoopRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.workspace = Path(self.temporary_directory.name)
        (self.workspace / "PROMPT.md").write_text(
            "Run one iteration.\n",
            encoding="utf-8",
        )
        docs = self.workspace / "docs"
        docs.mkdir()
        (docs / "features.json").write_text(
            json.dumps(
                {
                    "features": [
                        {
                            "id": "F001",
                            "description": "bounded test feature",
                            "steps": ["run fake verification"],
                            "passes": False,
                            "verified_at": None,
                            "blocked": False,
                        }
                    ]
                }
            )
            + "\n",
            encoding="utf-8",
        )
        (self.workspace / ".gitignore").write_text(
            "logs/\nbin/\nfake-agent.pid\nfinalization-window\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "init", "-q"], cwd=self.workspace, check=True)
        subprocess.run(
            ["git", "add", "--", "PROMPT.md", "docs/features.json", ".gitignore"],
            cwd=self.workspace,
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=Goal Loop Test",
                "-c",
                "user.email=goal-loop@example.invalid",
                "commit",
                "-qm",
                "test baseline",
            ],
            cwd=self.workspace,
            check=True,
        )
        self.fake_bin = self.workspace / "bin"
        self.fake_bin.mkdir()
        self.write_executable("codex", CODEX_FAKE)
        self.write_executable("claude", CLAUDE_FAKE)

    def write_executable(self, name: str, contents: str) -> None:
        executable = self.fake_bin / name
        executable.write_text(contents, encoding="utf-8")
        executable.chmod(0o755)

    def replace_features(self, document: object) -> None:
        features_path = self.workspace / "docs" / "features.json"
        features_path.write_text(json.dumps(document) + "\n", encoding="utf-8")
        subprocess.run(
            ["git", "add", "--", "docs/features.json"],
            cwd=self.workspace,
            check=True,
        )
        subprocess.run(
            ["git", "commit", "-qm", "test feature state"],
            cwd=self.workspace,
            check=True,
        )

    def replace_features_text(self, contents: str) -> None:
        features_path = self.workspace / "docs" / "features.json"
        features_path.write_text(contents, encoding="utf-8")
        subprocess.run(
            ["git", "add", "--", "docs/features.json"],
            cwd=self.workspace,
            check=True,
        )
        subprocess.run(
            ["git", "commit", "-qm", "test invalid feature state"],
            cwd=self.workspace,
            check=True,
        )

    def install_degraded_fallback_fakes(self) -> None:
        self.write_executable("python", "#!/usr/bin/env bash\nexit 1\n")
        self.write_executable("python3", "#!/usr/bin/env bash\nexit 1\n")
        self.write_executable(
            "codex",
            textwrap.dedent(
                r"""
                #!/usr/bin/env bash
                set -u
                if [[ "$#" -ne 7 ||
                      "$1" != "exec" ||
                      "$2" != "--json" ||
                      "$3" != "--output-last-message" ||
                      "$5" != "--sandbox" ||
                      "$6" != "workspace-write" ||
                      "$7" != "-" ]]; then
                  printf 'unexpected arguments\n' >&2
                  exit 64
                fi
                IFS= read -r _prompt || true
                if [[ -v FAKE_FINAL ]]; then
                  printf '%s' "$FAKE_FINAL" > "$4"
                else
                  printf 'work remains\n' > "$4"
                fi
                printf '{"type":"turn.completed"}\n'
                printf 'fallback fake stderr\n' >&2
                exit_code=0
                [[ ! -v FAKE_EXIT ]] || exit_code="$FAKE_EXIT"
                exit "$exit_code"
                """
            ).lstrip(),
        )
        self.write_executable(
            "claude",
            textwrap.dedent(
                r"""
                #!/usr/bin/env bash
                set -u
                if [[ "$#" -ne 3 ||
                      "$1" != "-p" ||
                      "$2" != "--permission-mode" ||
                      "$3" != "acceptEdits" ]]; then
                  printf 'unexpected arguments\n' >&2
                  exit 64
                fi
                IFS= read -r _prompt || true
                if [[ -v FAKE_FINAL ]]; then
                  printf '%s' "$FAKE_FINAL"
                else
                  printf 'work remains\n'
                fi
                printf 'fallback claude stderr\n' >&2
                exit_code=0
                [[ ! -v FAKE_EXIT ]] || exit_code="$FAKE_EXIT"
                exit "$exit_code"
                """
            ).lstrip(),
        )

    def run_loop(
        self,
        agent: str = "codex",
        max_iterations: str = "1",
        **environment: str,
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["PATH"] = f"{self.fake_bin}{os.pathsep}{env['PATH']}"
        env.pop("GOAL_LOOP_STRICT_INCOMPLETE", None)
        env.update(environment)
        return subprocess.run(
            ["bash", str(LOOP_SCRIPT), agent, max_iterations],
            cwd=self.workspace,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def run_direct(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["PATH"] = f"{self.fake_bin}{os.pathsep}{env['PATH']}"
        env.pop("GOAL_LOOP_STRICT_INCOMPLETE", None)
        return subprocess.run(
            ["bash", str(LOOP_SCRIPT), *arguments],
            cwd=self.workspace,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def run_loop_with_signal(
        self,
        agent: str,
        signal_number: signal.Signals,
    ) -> subprocess.CompletedProcess[str]:
        pid_file = self.workspace / "fake-agent.pid"
        env = os.environ.copy()
        env["PATH"] = f"{self.fake_bin}{os.pathsep}{env['PATH']}"
        env["FAKE_PID_FILE"] = str(pid_file)
        env["FAKE_SLEEP"] = "30"
        env.pop("GOAL_LOOP_STRICT_INCOMPLETE", None)
        process = subprocess.Popen(
            ["bash", str(LOOP_SCRIPT), agent, "1"],
            cwd=self.workspace,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.monotonic() + 5
        while not pid_file.is_file():
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                self.fail(
                    f"runner exited before fake agent started: "
                    f"{process.returncode}\nstdout:\n{stdout}\nstderr:\n{stderr}"
                )
            if time.monotonic() >= deadline:
                process.kill()
                process.communicate()
                self.fail("fake agent did not start before timeout")
            time.sleep(0.01)

        os.kill(process.pid, signal_number)
        try:
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            child_pid = int(pid_file.read_text(encoding="utf-8"))
            try:
                os.kill(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
            self.fail("runner did not terminate after forwarded signal")
        return subprocess.CompletedProcess(
            process.args,
            process.returncode,
            stdout,
            stderr,
        )

    def only_run_dir(self) -> Path:
        run_dirs = sorted((self.workspace / "logs").glob("run-*"))
        self.assertEqual(len(run_dirs), 1)
        return run_dirs[0]

    def iteration_metadata(self, run_dir: Path) -> dict[str, object]:
        return json.loads(
            (run_dir / "iter-001" / "metadata.json").read_text(encoding="utf-8")
        )

    def assert_terminal_summary(
        self,
        completed: subprocess.CompletedProcess[str],
        run_dir: Path,
        *,
        state: str,
        agent_exit: int,
        runner_exit: int,
        iteration: int = 1,
    ) -> None:
        if state in {"manual_review", "blocked", "incomplete"}:
            status_line = f"[failure] iteration {iteration} stopped"
        elif agent_exit == 0:
            status_line = f"[success] iteration {iteration} completed"
        else:
            status_line = f"[failure] iteration {iteration} failed"
        iteration_dir = run_dir / f"iter-{iteration:03d}"
        summary = "\n".join(
            (
                status_line,
                f"[state] {state}",
                f"[agent-exit] {agent_exit}",
                f"[runner-exit] {runner_exit}",
                f"[logs] {iteration_dir}",
                "",
            )
        )
        self.assertEqual(
            (run_dir / "summary.txt").read_text(encoding="utf-8"),
            summary,
        )
        self.assertTrue(completed.stdout.endswith(summary), completed.stdout)

    def test_codex_default_attempt_limit_preserves_complete_artifact_set(self) -> None:
        completed = self.run_loop()

        self.assertEqual(completed.returncode, 2, completed.stderr)
        self.assertEqual(completed.stderr, "")
        run_dir = self.only_run_dir()
        self.assertRegex(
            run_dir.name,
            r"^run-\d{8}T\d{6}Z-\d+(?:-\d+)?$",
        )
        iteration_dir = run_dir / "iter-001"
        self.assertEqual(
            (iteration_dir / "events.jsonl").read_text(encoding="utf-8").splitlines(),
            CODEX_EVENT_LINES,
        )
        self.assertEqual(
            (iteration_dir / "final.md").read_text(encoding="utf-8"),
            "work remains\n",
        )
        self.assertEqual(
            (iteration_dir / "stderr.log").read_text(encoding="utf-8"),
            "fake codex stderr\n",
        )

        metadata = self.iteration_metadata(run_dir)
        self.assertEqual(set(metadata), METADATA_KEYS)
        self.assertEqual(metadata["run_id"], run_dir.name)
        self.assertEqual(metadata["agent"], "codex")
        self.assertEqual(metadata["max_iterations"], 1)
        self.assertEqual(metadata["iteration"], 1)
        self.assertEqual(metadata["completion_state"], "manual_review")
        self.assertEqual(metadata["agent_exit_code"], 0)
        self.assertEqual(metadata["runner_exit_code"], 2)
        self.assertEqual(metadata["codex_thread_id"], "thread-safe-123")
        self.assertIsNone(metadata["signal"])
        self.assertEqual(metadata["interruption_reason"], "attempt_limit")
        self.assertEqual(set(json.loads((run_dir / "metadata.json").read_text())), METADATA_KEYS)
        for name in ("git-before.txt", "git-after.txt", "summary.txt"):
            self.assertTrue((run_dir / name).is_file(), name)
        self.assertFalse((self.workspace / "logs" / "iter_001.log").exists())
        self.assertFalse((self.workspace / "logs" / "iter_001").exists())
        self.assertIn(
            "[start] iteration 1/1 feature=F001 attempt=1/1\n",
            completed.stdout,
        )
        self.assertIn(f"[logs] {iteration_dir}\n", completed.stdout)
        self.assert_terminal_summary(
            completed,
            run_dir,
            state="manual_review",
            agent_exit=0,
            runner_exit=2,
        )

    def test_incomplete_stops_with_one_without_strict_mode(self) -> None:
        completed = self.run_loop(
            GOAL_LOOP_MAX_ATTEMPTS_PER_FEATURE="2",
        )

        self.assertEqual(completed.returncode, 1)
        run_dir = self.only_run_dir()
        metadata = self.iteration_metadata(run_dir)
        self.assertEqual(metadata["completion_state"], "incomplete")
        self.assertEqual(metadata["runner_exit_code"], 1)
        self.assert_terminal_summary(
            completed,
            run_dir,
            state="incomplete",
            agent_exit=0,
            runner_exit=1,
        )

    def test_strict_incomplete_environment_does_not_change_exit_code(self) -> None:
        completed = self.run_loop(
            GOAL_LOOP_STRICT_INCOMPLETE="true",
            GOAL_LOOP_MAX_ATTEMPTS_PER_FEATURE="2",
        )
        self.assertEqual(completed.returncode, 1)

    def test_promise_does_not_complete_when_an_actionable_feature_remains(self) -> None:
        self.replace_features(
            {
                "features": [
                    {"id": "F001", "passes": False, "blocked": False},
                    {"id": "F002", "passes": False, "blocked": False},
                ]
            }
        )
        completed = self.run_loop(
            FAKE_FINAL="<promise>ALL_FEATURES_PASS</promise>\n",
            FAKE_MARK_PASS="1",
        )
        self.assertEqual(completed.returncode, 1)
        self.assertNotIn("[complete]", completed.stdout)
        metadata = self.iteration_metadata(self.only_run_dir())
        self.assertEqual(metadata["completion_state"], "incomplete")
        self.assertEqual(metadata["feature_completion_state"], "continue")

    def test_json_all_passed_completes_even_without_a_promise(self) -> None:
        completed = self.run_loop(
            FAKE_MARK_PASS="1",
        )
        self.assertEqual(completed.returncode, 0)
        metadata = self.iteration_metadata(self.only_run_dir())
        self.assertEqual(metadata["completion_state"], "complete")
        self.assertEqual(metadata["feature_completion_state"], "all_passed")
        self.assertEqual(metadata["runner_exit_code"], 0)

    def test_blocked_promise_does_not_stop_when_an_actionable_feature_remains(self) -> None:
        self.replace_features(
            {
                "features": [
                    {"id": "F001", "passes": False, "blocked": False},
                    {"id": "F002", "passes": False, "blocked": False},
                ]
            }
        )
        completed = self.run_loop(
            FAKE_FINAL="<promise>BLOCKED</promise>\n",
            FAKE_MARK_BLOCKED="1",
        )
        self.assertEqual(completed.returncode, 1)
        metadata = self.iteration_metadata(self.only_run_dir())
        self.assertEqual(metadata["completion_state"], "incomplete")
        self.assertEqual(metadata["feature_completion_state"], "continue")

    def test_all_remaining_blocked_stops_with_two(self) -> None:
        self.replace_features(
            {
                "features": [
                    {"id": "F001", "passes": True, "blocked": False},
                    {"id": "F002", "passes": False, "blocked": True},
                ]
            }
        )
        completed = self.run_loop()
        self.assertEqual(completed.returncode, 2)
        self.assertIn("all remaining features are blocked", completed.stderr)
        self.assertFalse((self.workspace / "logs").exists())

    def test_invalid_features_document_fails_closed(self) -> None:
        invalid_documents = (
            "{not json}\n",
            json.dumps({"not_features": []}) + "\n",
            json.dumps({"features": [{"id": "F001", "passes": "true", "blocked": False}]}) + "\n",
            json.dumps({"features": [{"id": "F001", "passes": False, "blocked": None}]}) + "\n",
        )
        for contents in invalid_documents:
            with self.subTest(contents=contents):
                self.replace_features_text(contents)
                completed = self.run_direct("codex", "1", "--status")
                self.assertEqual(completed.returncode, 3)
                self.assertNotIn("[complete]", completed.stdout)
                self.assertNotIn("[blocked]", completed.stderr)

    def test_codex_agent_failure_maps_to_runner_three(self) -> None:
        completed = self.run_loop(FAKE_EXIT="7")

        self.assertEqual(completed.returncode, 3)
        run_dir = self.only_run_dir()
        metadata = self.iteration_metadata(run_dir)
        self.assertEqual(metadata["completion_state"], "failed")
        self.assertEqual(metadata["agent_exit_code"], 7)
        self.assertEqual(metadata["runner_exit_code"], 3)
        self.assertEqual(metadata["interruption_reason"], "agent_error")
        self.assert_terminal_summary(
            completed,
            run_dir,
            state="failed",
            agent_exit=7,
            runner_exit=3,
        )

    def test_two_consecutive_runs_are_unique_and_do_not_overwrite(self) -> None:
        first = self.run_loop()
        self.assertEqual(first.returncode, 2)
        first_dir = self.only_run_dir()
        original_metadata = (first_dir / "metadata.json").read_bytes()
        original_events = (first_dir / "iter-001" / "events.jsonl").read_bytes()

        second = self.run_loop(
            FAKE_FINAL="<promise>ALL_FEATURES_PASS</promise>\n",
            FAKE_MARK_PASS="1",
        )
        self.assertEqual(second.returncode, 0)
        run_dirs = sorted((self.workspace / "logs").glob("run-*"))
        self.assertEqual(len(run_dirs), 2)
        self.assertEqual((first_dir / "metadata.json").read_bytes(), original_metadata)
        self.assertEqual(
            (first_dir / "iter-001" / "events.jsonl").read_bytes(),
            original_events,
        )

    def assert_signal_outcome(
        self,
        completed: subprocess.CompletedProcess[str],
        *,
        expected_signal: str,
        expected_agent_exit: int,
        runner_exit: int,
    ) -> None:
        self.assertEqual(completed.returncode, runner_exit, completed.stderr)
        run_dir = self.only_run_dir()
        iteration_dir = run_dir / "iter-001"
        metadata = self.iteration_metadata(run_dir)
        root_metadata = json.loads(
            (run_dir / "metadata.json").read_text(encoding="utf-8")
        )
        for recorded in (metadata, root_metadata):
            self.assertEqual(recorded["completion_state"], "interrupted")
            self.assertEqual(recorded["signal"], expected_signal)
            self.assertEqual(recorded["interruption_reason"], "signal")
            self.assertEqual(recorded["runner_exit_code"], runner_exit)
            self.assertEqual(recorded["agent_exit_code"], expected_agent_exit)
            self.assertTrue(recorded["end_time"])
            self.assertEqual(recorded["iteration"], 1)
            self.assertEqual(recorded["log_paths"]["final"], str(iteration_dir / "final.md"))
        summary = (run_dir / "summary.txt").read_text(encoding="utf-8")
        self.assertIn(f"[signal] {expected_signal}", summary)
        self.assertIn(f"[runner-exit] {runner_exit}", summary)
        self.assertIn(f"[logs] {iteration_dir}", summary)

    def test_sigint_interrupts_codex_process_group_and_finalizes_artifacts(self) -> None:
        completed = self.run_loop_with_signal("codex", signal.SIGINT)
        self.assert_signal_outcome(
            completed,
            expected_signal="SIGINT",
            expected_agent_exit=-signal.SIGINT,
            runner_exit=130,
        )

    def test_sigterm_interrupts_claude_process_group_and_finalizes_artifacts(self) -> None:
        completed = self.run_loop_with_signal("claude", signal.SIGTERM)
        self.assert_signal_outcome(
            completed,
            expected_signal="SIGTERM",
            expected_agent_exit=-signal.SIGTERM,
            runner_exit=143,
        )

    def test_signal_during_finalization_overrides_ordinary_result(self) -> None:
        marker = self.workspace / "finalization-window"
        self.write_executable(
            "git",
            textwrap.dedent(
                r"""
                #!/usr/bin/env python3
                import os
                import sys
                import time
                from pathlib import Path

                if sys.argv[1:2] == ["commit"]:
                    Path(os.environ["FAKE_FINALIZATION_MARKER"]).write_text(
                        "ready\n",
                        encoding="utf-8",
                    )
                    time.sleep(0.3)
                os.execv(os.environ["REAL_GIT"], [os.environ["REAL_GIT"], *sys.argv[1:]])
                """
            ).lstrip(),
        )
        env = os.environ.copy()
        env["PATH"] = f"{self.fake_bin}{os.pathsep}{env['PATH']}"
        env["FAKE_FINALIZATION_MARKER"] = str(marker)
        env["REAL_GIT"] = shutil.which("git") or "/usr/bin/git"
        process = subprocess.Popen(
            ["bash", str(LOOP_SCRIPT), "codex", "1"],
            cwd=self.workspace,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.monotonic() + 5
        while not marker.exists():
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                self.fail(
                    f"runner exited before finalization window: "
                    f"{process.returncode}\nstdout:\n{stdout}\nstderr:\n{stderr}"
                )
            if time.monotonic() >= deadline:
                process.kill()
                process.communicate()
                self.fail("finalization window did not open")
            time.sleep(0.01)

        os.kill(process.pid, signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=5)

        self.assertEqual(process.returncode, 143, f"{stdout}\n{stderr}")
        run_dir = self.only_run_dir()
        for metadata_path in (
            run_dir / "iter-001" / "metadata.json",
            run_dir / "metadata.json",
        ):
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            self.assertEqual(metadata["completion_state"], "interrupted")
            self.assertEqual(metadata["agent_exit_code"], 0)
            self.assertEqual(metadata["runner_exit_code"], 143)
            self.assertEqual(metadata["signal"], "SIGTERM")
            self.assertEqual(metadata["interruption_reason"], "signal")
        summary = (run_dir / "summary.txt").read_text(encoding="utf-8")
        self.assertIn("[signal] SIGTERM", summary)
        self.assertIn("[runner-exit] 143", summary)

    def test_default_attempt_limit_stops_repeated_invocations(self) -> None:
        codex_completed = self.run_loop(agent="codex", max_iterations="10")
        self.assertEqual(codex_completed.returncode, 2)
        first_run = self.only_run_dir()
        self.assertEqual(len(list(first_run.glob("iter-*"))), 1)
        self.assert_terminal_summary(
            codex_completed,
            first_run,
            state="manual_review",
            agent_exit=0,
            runner_exit=2,
            iteration=1,
        )

        before = set((self.workspace / "logs").glob("run-*"))
        claude_completed = self.run_loop(agent="claude", max_iterations="3")
        self.assertEqual(claude_completed.returncode, 2)
        after = set((self.workspace / "logs").glob("run-*"))
        second_run = (after - before).pop()
        self.assertEqual(len(list(second_run.glob("iter-*"))), 1)
        self.assert_terminal_summary(
            claude_completed,
            second_run,
            state="manual_review",
            agent_exit=0,
            runner_exit=2,
            iteration=1,
        )

    def test_run_metadata_spans_all_iteration_times(self) -> None:
        completed = self.run_loop(
            max_iterations="3",
            FAKE_SLEEP="0.02",
            GOAL_LOOP_MAX_ATTEMPTS_PER_FEATURE="4",
        )
        self.assertEqual(completed.returncode, 1)
        run_dir = self.only_run_dir()
        root = json.loads((run_dir / "metadata.json").read_text(encoding="utf-8"))
        first = json.loads(
            (run_dir / "iter-001" / "metadata.json").read_text(encoding="utf-8")
        )
        last = json.loads(
            (run_dir / "iter-003" / "metadata.json").read_text(encoding="utf-8")
        )

        parse_time = lambda value: datetime.fromisoformat(value.replace("Z", "+00:00"))
        self.assertLessEqual(parse_time(root["start_time"]), parse_time(first["start_time"]))
        self.assertGreaterEqual(parse_time(root["end_time"]), parse_time(last["end_time"]))
        self.assertEqual(root["iteration"], 3)

    def test_git_read_failure_fails_closed_before_agent(self) -> None:
        self.write_executable(
            "git",
            "#!/usr/bin/env python3\nraise SystemExit(42)\n",
        )

        completed = self.run_loop()

        self.assertEqual(completed.returncode, 5)
        run_dir = self.only_run_dir()
        self.assertFalse((run_dir / "iter-001" / "metadata.json").exists())
        self.assertIn("[commit-request-error] git status failed", completed.stderr)

    def test_claude_incomplete_preserves_stdout_final_and_stderr(self) -> None:
        completed = self.run_loop(agent="claude")

        self.assertEqual(completed.returncode, 2)
        run_dir = self.only_run_dir()
        iteration_dir = run_dir / "iter-001"
        self.assertEqual(
            (iteration_dir / "stdout.log").read_text(encoding="utf-8"),
            "work remains\n",
        )
        self.assertEqual(
            (iteration_dir / "final.md").read_text(encoding="utf-8"),
            "work remains\n",
        )
        self.assertEqual(
            (iteration_dir / "stderr.log").read_text(encoding="utf-8"),
            "fake claude stderr\n",
        )
        metadata = self.iteration_metadata(run_dir)
        self.assertEqual(metadata["agent"], "claude")
        self.assertEqual(metadata["completion_state"], "manual_review")
        self.assertIsNone(metadata["codex_thread_id"])

    def test_claude_json_all_passed_returns_zero_without_a_promise(self) -> None:
        completed = self.run_loop(
            agent="claude",
            FAKE_MARK_PASS="1",
        )
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(
            self.iteration_metadata(self.only_run_dir())["completion_state"],
            "complete",
        )

    def test_claude_blocked_promise_is_ignored(self) -> None:
        completed = self.run_loop(
            agent="claude",
            FAKE_FINAL="<promise>BLOCKED</promise>\n",
        )
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(
            self.iteration_metadata(self.only_run_dir())["completion_state"],
            "manual_review",
        )

    def test_claude_agent_failure_maps_to_runner_three(self) -> None:
        completed = self.run_loop(agent="claude", FAKE_EXIT="7")
        self.assertEqual(completed.returncode, 3)
        metadata = self.iteration_metadata(self.only_run_dir())
        self.assertEqual(metadata["completion_state"], "failed")
        self.assertEqual(metadata["agent_exit_code"], 7)
        self.assertEqual(metadata["runner_exit_code"], 3)

    def test_invalid_agent_is_rejected_before_artifacts(self) -> None:
        completed = self.run_direct("other", "1")
        self.assertEqual(completed.returncode, 64)
        self.assertFalse((self.workspace / "logs").exists())

    def test_invalid_max_iterations_is_rejected_before_artifacts(self) -> None:
        for value in ("0", "not-a-number"):
            with self.subTest(value=value):
                completed = self.run_direct("codex", value)
                self.assertEqual(completed.returncode, 64)
        self.assertFalse((self.workspace / "logs").exists())

    def test_missing_prompt_returns_data_error_without_running_agent(self) -> None:
        (self.workspace / "PROMPT.md").unlink()
        completed = self.run_loop()
        self.assertEqual(completed.returncode, 66)
        self.assertIn("PROMPT.md", completed.stderr)
        self.assertFalse((self.workspace / "logs").exists())

    def test_artifact_creation_failure_returns_three(self) -> None:
        (self.workspace / "logs").write_text("not a directory\n", encoding="utf-8")
        completed = self.run_loop()
        self.assertEqual(completed.returncode, 3)
        self.assertIn("artifact", completed.stderr.lower())

    def test_missing_final_artifact_returns_three(self) -> None:
        completed = self.run_loop(FAKE_REMOVE_FINAL="1")
        self.assertEqual(completed.returncode, 3)
        self.assertIn("artifact", completed.stderr.lower())
        run_dir = self.only_run_dir()
        iteration_metadata = self.iteration_metadata(run_dir)
        run_metadata = json.loads(
            (run_dir / "metadata.json").read_text(encoding="utf-8")
        )
        for metadata in (iteration_metadata, run_metadata):
            self.assertEqual(metadata["completion_state"], "failed")
            self.assertEqual(metadata["agent_exit_code"], 0)
            self.assertEqual(metadata["runner_exit_code"], 3)
            self.assertEqual(metadata["interruption_reason"], "artifact_error")
        summary = (run_dir / "summary.txt").read_text(encoding="utf-8")
        self.assertIn("[failure] iteration 1 failed", summary)
        self.assertIn("[runner-exit] 3", summary)

    def test_wrapper_fails_closed_without_python_three(self) -> None:
        self.install_degraded_fallback_fakes()

        completed = self.run_loop()

        self.assertEqual(completed.returncode, 69, completed.stderr)
        self.assertIn("unsafe fallback execution is disabled", completed.stderr)
        self.assertTrue(FALLBACK_SCRIPT.is_file())
        self.assertFalse((self.workspace / "logs").exists())

    def test_direct_degraded_fallback_is_disabled(self) -> None:
        completed = subprocess.run(
            ["bash", str(FALLBACK_SCRIPT), "codex", "1"],
            cwd=self.workspace,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 69)
        self.assertIn("degraded Goal Loop execution is disabled", completed.stderr)
        self.assertFalse((self.workspace / "logs").exists())


if __name__ == "__main__":
    unittest.main()
