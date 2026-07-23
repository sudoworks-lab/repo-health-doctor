from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from repo_health_doctor.sandbox import run_workspace
from repo_health_doctor.sandbox.run_workspace import (
    GIT_ALLOWED_SUBCOMMANDS,
    create_verified_snapshot,
    inspect_git_worktree,
)


def _git(repo: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


class VerifiedSnapshotGitSentinelTests(unittest.TestCase):
    def test_intake_never_invokes_repository_fsmonitor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            _git(repo, "init", "-q")
            _git(repo, "-c", "user.email=test@example.invalid", "-c", "user.name=test", "commit", "--allow-empty", "-qm", "initial")

            sentinel = root / "fsmonitor-invoked"
            hook = root / "malicious-fsmonitor"
            hook.write_text(
                "#!/bin/sh\n"
                ': > "$RHD_TEST_FSMONITOR_SENTINEL"\n'
                "printf '\\n'\n",
                encoding="utf-8",
            )
            hook.chmod(hook.stat().st_mode | stat.S_IXUSR)
            _git(repo, "config", "core.fsmonitor", str(hook))

            with patch.dict(
                os.environ,
                {"RHD_TEST_FSMONITOR_SENTINEL": str(sentinel)},
                clear=False,
            ):
                observed = inspect_git_worktree(repo)

            self.assertTrue(observed["git_available"])
            self.assertFalse(
                sentinel.exists(),
                "untrusted repository core.fsmonitor code ran on the host",
            )

    def test_intake_ignores_untrusted_path_and_uses_only_allowlisted_git_argv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            _git(repo, "init", "-q")
            (repo / "README.md").write_text("trusted git executable\n", encoding="utf-8")
            _git(repo, "add", "README.md")
            _git(
                repo,
                "-c",
                "user.email=test@example.invalid",
                "-c",
                "user.name=test",
                "commit",
                "-qm",
                "initial",
            )

            sentinel = root / "path-git-invoked"
            hostile_bin = root / "hostile-bin"
            hostile_bin.mkdir()
            hostile_git = hostile_bin / "git"
            hostile_git.write_text(
                "#!/bin/sh\n"
                ': > "$RHD_TEST_PATH_GIT_SENTINEL"\n'
                "exit 99\n",
                encoding="utf-8",
            )
            hostile_git.chmod(hostile_git.stat().st_mode | stat.S_IXUSR)
            observed_argv: list[tuple[str, ...]] = []
            real_popen = subprocess.Popen

            def audited_popen(argv, *args, **kwargs):  # type: ignore[no-untyped-def]
                observed_argv.append(tuple(str(item) for item in argv))
                return real_popen(argv, *args, **kwargs)

            with patch.dict(
                os.environ,
                {
                    "PATH": str(hostile_bin),
                    "RHD_TEST_PATH_GIT_SENTINEL": str(sentinel),
                },
                clear=False,
            ), patch.object(
                run_workspace.subprocess,
                "Popen",
                side_effect=audited_popen,
            ):
                workspace = create_verified_snapshot(repo)
            try:
                self.assertTrue(workspace.copy_safety_ok)
                self.assertFalse(sentinel.exists())
                self.assertTrue(observed_argv)
                for argv in observed_argv:
                    self.assertTrue(Path(argv[0]).is_absolute())
                    if argv[1:] == ("--version",):
                        continue
                    self.assertTrue(
                        any(token in GIT_ALLOWED_SUBCOMMANDS for token in argv),
                        argv,
                    )
                    self.assertNotIn("status", argv)
                    self.assertNotIn("ls-files", argv)
            finally:
                workspace.cleanup()


if __name__ == "__main__":
    unittest.main()
