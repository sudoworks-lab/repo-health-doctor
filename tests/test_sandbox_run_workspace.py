from __future__ import annotations

from pathlib import Path

from repo_health_doctor.sandbox.run_workspace import (
    create_disposable_workspace,
    snapshot_workspace,
    summarize_workspace_diff,
)


def test_workspace_copy_excludes_git_env_and_caches(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "README.md").write_text("demo\n", encoding="utf-8")
    (repo / ".env").write_text("TOKEN=not-copied\n", encoding="utf-8")
    (repo / ".git").mkdir()
    (repo / ".git" / "config").write_text("[core]\n", encoding="utf-8")
    (repo / "__pycache__").mkdir()
    (repo / "__pycache__" / "x.pyc").write_bytes(b"cached")

    workspace = create_disposable_workspace(repo)
    try:
        assert workspace.copy_safety_ok is True
        assert (workspace.workspace / "README.md").is_file()
        assert not (workspace.workspace / ".env").exists()
        assert not (workspace.workspace / ".git").exists()
        assert not (workspace.workspace / "__pycache__").exists()
        categories = {item["category"] for item in workspace.to_report()["excluded_path_categories"]}
        assert "credential_like" in categories
        assert "vcs_metadata" in categories
        assert "cache" in categories
    finally:
        workspace.cleanup()


def test_workspace_copy_detects_symlink_escape(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside\n", encoding="utf-8")
    (repo / "escape").symlink_to(outside)

    workspace = create_disposable_workspace(repo)
    try:
        assert workspace.copy_safety_ok is False
        assert workspace.unsafe_symlinks == ["escape"]
        assert not (workspace.workspace / "escape").exists()
    finally:
        workspace.cleanup()


def test_workspace_diff_reports_created_modified_deleted_without_raw_contents(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "keep.txt").write_text("before\n", encoding="utf-8")
    (workspace / "delete.txt").write_text("delete\n", encoding="utf-8")
    before = snapshot_workspace(workspace)

    (workspace / "keep.txt").write_text("after\n", encoding="utf-8")
    (workspace / "delete.txt").unlink()
    (workspace / "created.txt").write_text("created\n", encoding="utf-8")
    after = snapshot_workspace(workspace)
    diff = summarize_workspace_diff(before, after)

    assert diff["available"] is True
    assert diff["created_count"] == 1
    assert diff["modified_count"] == 1
    assert diff["deleted_count"] == 1
    assert diff["raw_contents_persisted"] is False
    assert "<workspace>/created.txt" in diff["interesting_paths_redacted"]
