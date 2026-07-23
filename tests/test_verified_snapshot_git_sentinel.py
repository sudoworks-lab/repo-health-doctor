from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from repo_health_doctor.sandbox.run_workspace import inspect_git_worktree


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


if __name__ == "__main__":
    unittest.main()
