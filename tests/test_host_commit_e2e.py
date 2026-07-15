from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
LOOP_SCRIPT = REPO_ROOT / "scripts" / "loop.sh"
HOST_COMMIT = REPO_ROOT / "scripts" / "host_commit.py"
KICKOFF_SCRIPT = REPO_ROOT / "scripts" / "kickoff.sh"


FAKE_CODEX = textwrap.dedent(
    r"""
    #!/usr/bin/env python3
    import json
    import os
    import sys
    from pathlib import Path

    args = sys.argv[1:]
    if args == ["exec", "--sandbox", "workspace-write", "-"]:
        final_path = None
    elif (
        args[:3] == ["exec", "--json", "--output-last-message"]
        and args[4:] == ["--sandbox", "workspace-write", "-"]
    ):
        final_path = Path(args[3])
    else:
        raise SystemExit(64)
    sys.stdin.read()
    mode = os.environ.get("SMOKE_MODE", "normal")
    iteration = Path(os.environ["GOAL_LOOP_COMMIT_REQUEST"]).parent.name
    Path("target.txt").write_text(f"agent update {iteration}\n", encoding="utf-8")
    status = Path("docs/STATUS.md")
    status.write_text(status.read_text(encoding="utf-8") + "iteration complete\n", encoding="utf-8")
    features = Path("docs/features.json")
    document = json.loads(features.read_text(encoding="utf-8"))
    if mode == "invalid-features":
        features.write_text("{not-json}\n", encoding="utf-8")
    else:
        for feature in document["features"]:
            if not feature["passes"] and not feature["blocked"]:
                if mode == "block":
                    feature["blocked"] = True
                else:
                    feature["passes"] = True
                break
        features.write_text(json.dumps(document) + "\n", encoding="utf-8")
    paths = ["target.txt", "docs/STATUS.md", "docs/features.json"]

    if mode == "outside":
        Path("outside.txt").write_text("unexpected\n", encoding="utf-8")
    elif mode == "traversal":
        paths = ["../escape.txt"]
    elif mode == "absolute":
        paths = [str(Path("target.txt").resolve())]
    elif mode == "local-fixtures":
        fixture = Path("local-fixtures/sample.txt")
        fixture.parent.mkdir(parents=True, exist_ok=True)
        fixture.write_text("fixture\n", encoding="utf-8")
        paths = [str(fixture)]
    elif mode == "wav":
        Path("generated.wav").write_bytes(b"RIFF")
        paths = ["generated.wav"]
    elif mode == "logs":
        evidence = Path("logs/agent-evidence.txt")
        evidence.write_text("ignored\n", encoding="utf-8")
        paths = [str(evidence)]
    elif mode == "whitespace":
        Path("target.txt").write_text("trailing whitespace   \n", encoding="utf-8")
    elif mode == "tamper-snapshot":
        Path(os.environ["GOAL_LOOP_PREEXISTING_DIRTY"]).write_text("{}\n", encoding="utf-8")

    request = Path(os.environ["GOAL_LOOP_COMMIT_REQUEST"])
    if mode == "malformed":
        request.write_text("{not-json\n", encoding="utf-8")
    else:
        request.write_text(
            json.dumps({"message": "test: host commit", "paths": paths}) + "\n",
            encoding="utf-8",
        )
    print("<promise>ALL_FEATURES_PASS</promise>")
    if final_path is not None:
        final_path.write_text("fake feature finished\n", encoding="utf-8")
    if mode == "agent-failure":
        raise SystemExit(9)
    """
).lstrip()


class HostCommitLinkedWorktreeSmokeTests(unittest.TestCase):
    def make_worktree(
        self,
        *,
        failing_hook: bool = False,
        features: list[dict[str, object]] | None = None,
    ) -> tuple[Path, Path, dict[str, str]]:
        temporary = Path(tempfile.mkdtemp(prefix="goal-loop-host-commit-", dir="/tmp"))
        self.addCleanup(shutil.rmtree, temporary, True)
        primary = temporary / "primary"
        linked = temporary / "linked"
        primary.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=primary, check=True)
        subprocess.run(["git", "config", "user.name", "Goal Loop Smoke"], cwd=primary, check=True)
        subprocess.run(
            ["git", "config", "user.email", "goal-loop-smoke@example.invalid"],
            cwd=primary,
            check=True,
        )
        (primary / ".gitignore").write_text(
            "logs/\nlocal-fixtures/\n__pycache__/\n",
            encoding="utf-8",
        )
        (primary / "PROMPT.md").write_text("Run one fake iteration.\n", encoding="utf-8")
        prompts = primary / "prompts"
        prompts.mkdir()
        (prompts / "KICKOFF.md").write_text("Initialize without starting the loop.\n", encoding="utf-8")
        (primary / "target.txt").write_text("baseline\n", encoding="utf-8")
        (primary / "preexisting.txt").write_text("baseline\n", encoding="utf-8")
        docs = primary / "docs"
        docs.mkdir()
        (docs / "STATUS.md").write_text("status\n", encoding="utf-8")
        feature_document = features or [{"id": "F001", "passes": False, "blocked": False}]
        (docs / "features.json").write_text(
            json.dumps({"features": feature_document}) + "\n",
            encoding="utf-8",
        )
        scripts = primary / "scripts"
        scripts.mkdir()
        shutil.copy2(LOOP_SCRIPT, scripts / "loop.sh")
        shutil.copy2(HOST_COMMIT, scripts / "host_commit.py")
        shutil.copy2(REPO_ROOT / "scripts" / "goal_loop_runner.py", scripts / "goal_loop_runner.py")
        shutil.copy2(KICKOFF_SCRIPT, scripts / "kickoff.sh")
        subprocess.run(
            [
                "git",
                "add",
                "--",
                ".gitignore",
                "PROMPT.md",
                "prompts/KICKOFF.md",
                "target.txt",
                "preexisting.txt",
                "docs/STATUS.md",
                "docs/features.json",
                "scripts/loop.sh",
                "scripts/host_commit.py",
                "scripts/goal_loop_runner.py",
                "scripts/kickoff.sh",
            ],
            cwd=primary,
            check=True,
        )
        subprocess.run(["git", "commit", "-qm", "baseline"], cwd=primary, check=True)
        subprocess.run(
            ["git", "worktree", "add", "-q", "-b", "smoke", str(linked)],
            cwd=primary,
            check=True,
        )
        (linked / "preexisting.txt").write_text("human dirty\n", encoding="utf-8")
        fake_bin = temporary / "bin"
        fake_bin.mkdir()
        fake = fake_bin / "codex"
        fake.write_text(FAKE_CODEX, encoding="utf-8")
        fake.chmod(0o755)
        environment = os.environ.copy()
        environment["PATH"] = f"{fake_bin}{os.pathsep}{environment['PATH']}"
        if failing_hook:
            hooks = temporary / "hooks"
            hooks.mkdir()
            hook = hooks / "pre-commit"
            hook.write_text("#!/usr/bin/env sh\nexit 1\n", encoding="utf-8")
            hook.chmod(0o755)
            subprocess.run(
                ["git", "config", "core.hooksPath", str(hooks)],
                cwd=linked,
                check=True,
            )
        return primary, linked, environment

    def run_case(
        self,
        mode: str,
        *,
        expected_exit: int,
        failing_hook: bool = False,
        max_iterations: int = 1,
        features: list[dict[str, object]] | None = None,
        expected_commits: int | None = None,
    ) -> tuple[Path, subprocess.CompletedProcess[str]]:
        _primary, linked, environment = self.make_worktree(
            failing_hook=failing_hook,
            features=features,
        )
        environment["SMOKE_MODE"] = mode
        before = subprocess.run(
            ["git", "rev-list", "--count", "HEAD"],
            cwd=linked,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        completed = subprocess.run(
            ["bash", "scripts/loop.sh", "codex", str(max_iterations)],
            cwd=linked,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        after = subprocess.run(
            ["git", "rev-list", "--count", "HEAD"],
            cwd=linked,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        self.assertEqual(completed.returncode, expected_exit, completed.stderr)
        expected_delta = (
            expected_commits if expected_commits is not None else (1 if expected_exit == 0 else 0)
        )
        self.assertEqual(int(after) - int(before), expected_delta)
        staged = subprocess.run(
            ["git", "diff", "--cached", "--name-only"],
            cwd=linked,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        self.assertEqual(staged, "")
        self.assertEqual((linked / "preexisting.txt").read_text(encoding="utf-8"), "human dirty\n")
        self.assertEqual(
            subprocess.run(
                ["git", "show", "HEAD:preexisting.txt"],
                cwd=linked,
                check=True,
                capture_output=True,
                text=True,
            ).stdout,
            "baseline\n",
        )
        return linked, completed

    def test_normal_iteration_commits_once_in_linked_worktree(self) -> None:
        linked, _completed = self.run_case("normal", expected_exit=0)
        changed = subprocess.run(
            ["git", "show", "--pretty=format:", "--name-only", "HEAD"],
            cwd=linked,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.split()
        self.assertEqual(set(changed), {"target.txt", "docs/STATUS.md", "docs/features.json"})
        self.assertTrue(list((linked / "logs").glob("run-*/iter-001/commit-request.json")))

    def test_linked_worktree_partial_pass_ignores_promise_and_stops_incomplete(self) -> None:
        features = [
            {"id": "F001", "passes": False, "blocked": False},
            {"id": "F002", "passes": False, "blocked": False},
        ]
        linked, completed = self.run_case(
            "normal",
            expected_exit=1,
            features=features,
            expected_commits=1,
        )
        document = json.loads((linked / "docs/features.json").read_text(encoding="utf-8"))
        self.assertTrue(document["features"][0]["passes"])
        self.assertFalse(document["features"][1]["passes"])
        self.assertFalse(document["features"][1]["blocked"])
        metadata = json.loads(
            next((linked / "logs").glob("run-*/iter-001/metadata.json")).read_text(encoding="utf-8")
        )
        self.assertEqual(metadata["completion_state"], "incomplete")
        self.assertEqual(metadata["feature_completion_state"], "continue")
        self.assertNotIn("[complete] all features", completed.stdout)

    def test_linked_worktree_continues_to_next_feature_when_budget_remains(self) -> None:
        features = [
            {"id": "F001", "passes": False, "blocked": False},
            {"id": "F002", "passes": False, "blocked": False},
        ]
        linked, _completed = self.run_case(
            "normal",
            expected_exit=0,
            max_iterations=2,
            features=features,
            expected_commits=2,
        )
        document = json.loads((linked / "docs/features.json").read_text(encoding="utf-8"))
        self.assertTrue(all(feature["passes"] for feature in document["features"]))
        self.assertEqual(len(list((linked / "logs").glob("run-*/iter-*"))), 2)

    def test_linked_worktree_blocks_only_when_all_remaining_are_blocked(self) -> None:
        linked, completed = self.run_case(
            "block",
            expected_exit=2,
            expected_commits=1,
        )
        document = json.loads((linked / "docs/features.json").read_text(encoding="utf-8"))
        self.assertTrue(document["features"][0]["blocked"])
        self.assertIn("[state] blocked", completed.stdout)

    def test_legacy_host_runner_ignores_promise_when_actionable_feature_remains(self) -> None:
        features = [
            {"id": "F001", "passes": False, "blocked": False},
            {"id": "F002", "passes": False, "blocked": False},
        ]
        _primary, linked, environment = self.make_worktree(features=features)
        completed = subprocess.run(
            [sys.executable, "scripts/host_commit.py", "loop", "codex", "1"],
            cwd=linked,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertNotIn("completion promise accepted", completed.stdout)
        self.assertIn("maximum iterations reached", completed.stdout)

    def test_legacy_host_runner_fails_closed_after_committing_invalid_features(self) -> None:
        _primary, linked, environment = self.make_worktree()
        environment["SMOKE_MODE"] = "invalid-features"
        before = int(
            subprocess.run(
                ["git", "rev-list", "--count", "HEAD"],
                cwd=linked,
                check=True,
                capture_output=True,
                text=True,
            ).stdout
        )
        completed = subprocess.run(
            [sys.executable, "scripts/host_commit.py", "loop", "codex", "1"],
            cwd=linked,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        after = int(
            subprocess.run(
                ["git", "rev-list", "--count", "HEAD"],
                cwd=linked,
                check=True,
                capture_output=True,
                text=True,
            ).stdout
        )
        self.assertEqual(completed.returncode, 10)
        self.assertEqual(after - before, 1)
        self.assertNotIn("[done]", completed.stdout)
        self.assertNotIn("[blocked]", completed.stdout)

    def test_kickoff_commits_once_without_starting_loop(self) -> None:
        _primary, linked, environment = self.make_worktree()
        before = subprocess.run(
            ["git", "rev-list", "--count", "HEAD"],
            cwd=linked,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        completed = subprocess.run(
            ["bash", "scripts/kickoff.sh", "codex"],
            cwd=linked,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        after = subprocess.run(
            ["git", "rev-list", "--count", "HEAD"],
            cwd=linked,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(int(after) - int(before), 1)
        self.assertIn("implementation loop was not started", completed.stdout)
        self.assertEqual(list((linked / "logs").glob("run-*")), [])
        self.assertEqual(len(list((linked / "logs").glob("kickoff-*"))), 1)

    def test_request_and_dirty_failures_do_not_commit(self) -> None:
        for mode in (
            "outside",
            "traversal",
            "absolute",
            "local-fixtures",
            "wav",
            "logs",
            "malformed",
            "tamper-snapshot",
        ):
            with self.subTest(mode=mode):
                self.run_case(mode, expected_exit=5)

    def test_agent_stage_and_commit_failures_have_distinct_exit_codes(self) -> None:
        self.run_case("agent-failure", expected_exit=3)
        self.run_case("whitespace", expected_exit=6)
        self.run_case("normal", expected_exit=7, failing_hook=True)


if __name__ == "__main__":
    unittest.main()
