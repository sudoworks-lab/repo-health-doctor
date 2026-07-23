from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from repo_health_doctor.gate import authorization_discovery
from repo_health_doctor.gate.authorization_discovery import (
    AUTHORIZATION_DISCOVERY_FILENAME,
    AUTHORIZATION_DISCOVERY_MAX_BYTES,
    FILE_CHANGED,
    GIT_ERROR,
    NOT_A_GIT_REPO,
    NOT_FOUND,
    PARSE_FAILED,
    SYMLINK_REFUSED,
    TOO_LARGE,
    TRACKED_REFUSED,
    discover_execution_authorization,
)


class AuthorizationDiscoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary_directory.name)
        subprocess.run(
            ["git", "init", "-q"],
            cwd=self.repo,
            check=True,
            capture_output=True,
        )
        self.candidate = self.repo / AUTHORIZATION_DISCOVERY_FILENAME

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _write_candidate(self, value: object | None = None) -> None:
        payload = {"approved": True} if value is None else value
        self.candidate.write_text(json.dumps(payload), encoding="utf-8")

    def _discover(self, **kwargs: object):  # type: ignore[no-untyped-def]
        return discover_execution_authorization(
            self.repo,
            tracked_relative_paths=(),
            **kwargs,
        )

    def test_untracked_regular_file_is_read_with_nofollow_and_fstat(self) -> None:
        self._write_candidate()
        real_open = os.open
        real_fstat = os.fstat
        open_flags: list[int] = []
        fstat_calls: list[int] = []

        def recording_open(path: os.PathLike[str], flags: int) -> int:
            if Path(path) == self.candidate:
                open_flags.append(flags)
            return real_open(path, flags)

        def recording_fstat(descriptor: int) -> os.stat_result:
            fstat_calls.append(descriptor)
            return real_fstat(descriptor)

        with mock.patch.object(authorization_discovery.os, "open", side_effect=recording_open), mock.patch.object(
            authorization_discovery.os, "fstat", side_effect=recording_fstat
        ):
            result = self._discover()

        self.assertTrue(result.discovered)
        self.assertEqual(result.authorization, {"approved": True})
        self.assertIsNone(result.reason)
        self.assertGreaterEqual(len(fstat_calls), 2)
        if hasattr(os, "O_NOFOLLOW"):
            self.assertTrue(open_flags[0] & os.O_NOFOLLOW)

    def test_tracked_candidate_is_refused(self) -> None:
        self._write_candidate()
        subprocess.run(
            ["git", "add", "--", AUTHORIZATION_DISCOVERY_FILENAME],
            cwd=self.repo,
            check=True,
            capture_output=True,
        )

        result = discover_execution_authorization(
            self.repo,
            tracked_relative_paths=(AUTHORIZATION_DISCOVERY_FILENAME,),
        )

        self.assertEqual(result.reason, TRACKED_REFUSED)
        self.assertFalse(result.discovered)

    def test_non_git_directory_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as non_git:
            result = discover_execution_authorization(non_git)

        self.assertEqual(result.reason, NOT_A_GIT_REPO)

    def test_symlink_and_broken_symlink_are_refused(self) -> None:
        target = self.repo / "authorization-target.json"
        target.write_text("{}", encoding="utf-8")
        for broken in (False, True):
            with self.subTest(broken=broken):
                self.candidate.unlink(missing_ok=True)
                self.candidate.symlink_to(self.repo / "missing.json" if broken else target)
                result = self._discover()
                self.assertEqual(result.reason, SYMLINK_REFUSED)

    def test_oversize_candidate_is_refused_before_read(self) -> None:
        self.candidate.write_bytes(b"x" * (AUTHORIZATION_DISCOVERY_MAX_BYTES + 1))
        with mock.patch.object(authorization_discovery, "_read_descriptor") as read:
            result = self._discover()

        self.assertEqual(result.reason, TOO_LARGE)
        read.assert_not_called()

    def test_git_error_is_refused(self) -> None:
        with mock.patch.object(
            authorization_discovery,
            "create_verified_snapshot",
            side_effect=OSError("git unavailable"),
        ):
            result = discover_execution_authorization(self.repo)

        self.assertEqual(result.reason, GIT_ERROR)

    def test_file_change_during_bounded_read_is_refused(self) -> None:
        self._write_candidate()
        real_read = authorization_discovery._read_descriptor
        changed = False

        def changing_read(descriptor: int, size: int) -> bytes:
            nonlocal changed
            content = real_read(descriptor, size)
            if not changed:
                changed = True
                with self.candidate.open("ab") as handle:
                    handle.write(b" ")
            return content

        with mock.patch.object(authorization_discovery, "_read_descriptor", side_effect=changing_read):
            result = self._discover()

        self.assertEqual(result.reason, FILE_CHANGED)

    def test_file_replacement_between_lstat_and_open_is_refused(self) -> None:
        self._write_candidate()
        real_open = os.open
        replaced = False

        def replacing_open(path: os.PathLike[str], flags: int) -> int:
            nonlocal replaced
            if Path(path) == self.candidate and not replaced:
                replaced = True
                self.candidate.unlink()
                self._write_candidate({"replacement": True})
            return real_open(path, flags)

        with mock.patch.object(authorization_discovery.os, "open", side_effect=replacing_open):
            result = self._discover()

        self.assertEqual(result.reason, FILE_CHANGED)

    def test_bounded_read_refuses_growth_past_limit(self) -> None:
        self.candidate.write_bytes(b"{}")
        with mock.patch.object(
            authorization_discovery,
            "_read_descriptor",
            return_value=b"x" * 9,
        ) as read:
            result = self._discover(max_bytes=8)

        self.assertEqual(result.reason, TOO_LARGE)
        read.assert_called_once_with(mock.ANY, 9)

    def test_not_found_is_refused(self) -> None:
        result = self._discover()

        self.assertEqual(result.reason, NOT_FOUND)

    def test_invalid_json_and_non_object_are_refused(self) -> None:
        for content in (b"{", b"[]"):
            with self.subTest(content=content):
                self.candidate.write_bytes(content)
                result = self._discover()
                self.assertEqual(result.reason, PARSE_FAILED)

    def test_repo_subdirectory_is_not_accepted_as_top_level(self) -> None:
        child = self.repo / "child"
        child.mkdir()
        self._write_candidate()

        result = discover_execution_authorization(child)

        self.assertEqual(result.reason, NOT_A_GIT_REPO)


if __name__ == "__main__":
    unittest.main()
