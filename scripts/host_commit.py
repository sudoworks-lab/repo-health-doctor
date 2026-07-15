#!/usr/bin/env python3
"""Validate Goal Loop commit requests and commit them from the host runner."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any


REQUEST_ERROR = 10
STAGE_ERROR = 11
COMMIT_ERROR = 12
AGENT_ERROR = 3
RUNNER_REQUEST_ERROR = 5
RUNNER_STAGE_ERROR = 6
RUNNER_COMMIT_ERROR = 7
FEATURE_STATE_ALL_PASSED = "all_passed"
FEATURE_STATE_ALL_REMAINING_BLOCKED = "all_remaining_blocked"
FEATURE_STATE_CONTINUE = "continue"
FEATURE_STATE_INVALID = "invalid"
FORBIDDEN_DIRS = {
    ".git",
    ".ssh",
    "artifacts",
    "cache",
    "diagnostics",
    "history",
    "local-fixtures",
    "logs",
}
FORBIDDEN_AUDIO_SUFFIXES = {
    ".aac",
    ".aif",
    ".aiff",
    ".alac",
    ".caf",
    ".flac",
    ".m4a",
    ".mp3",
    ".ogg",
    ".opus",
    ".wav",
    ".wave",
    ".wma",
}
FORBIDDEN_PRIVATE_KEY_NAMES = {
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
}
FORBIDDEN_SECRET_SUFFIXES = {".key", ".p12", ".pem", ".pfx"}
FORBIDDEN_HISTORY_NAMES = {".bash_history", ".sh_history", ".zsh_history"}


class HostCommitError(Exception):
    def __init__(self, message: str, exit_code: int) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def run_git(
    repo: Path,
    arguments: list[str],
    *,
    check: bool = False,
    capture: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repo,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check and completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise HostCommitError(
            f"git {' '.join(arguments[:2])} failed: {detail or 'unknown error'}",
            STAGE_ERROR,
        )
    return completed


def repo_root(cwd: Path) -> Path:
    completed = run_git(cwd, ["rev-parse", "--show-toplevel"])
    if completed.returncode != 0:
        raise HostCommitError("current directory is not inside a Git repository", REQUEST_ERROR)
    return Path(os.fsdecode(completed.stdout.rstrip(b"\n"))).resolve()


def parse_porcelain(data: bytes) -> tuple[set[str], set[str]]:
    dirty: set[str] = set()
    staged: set[str] = set()
    records = data.split(b"\0")
    index = 0
    while index < len(records):
        record = records[index]
        index += 1
        if not record:
            continue
        if len(record) < 4 or record[2:3] != b" ":
            raise HostCommitError("unable to parse git status snapshot", REQUEST_ERROR)
        status = record[:2].decode("ascii", errors="strict")
        path = os.fsdecode(record[3:])
        dirty.add(path)
        if status[0] not in {" ", "?", "!"}:
            staged.add(path)
        if "R" in status or "C" in status:
            if index >= len(records) or not records[index]:
                raise HostCommitError("incomplete rename record in git status", REQUEST_ERROR)
            source = os.fsdecode(records[index])
            index += 1
            dirty.add(source)
            if status[0] not in {" ", "?", "!"}:
                staged.add(source)
    return dirty, staged


def working_tree_state(repo: Path) -> tuple[set[str], set[str]]:
    completed = run_git(
        repo,
        ["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )
    if completed.returncode != 0:
        raise HostCommitError("git status failed", REQUEST_ERROR)
    return parse_porcelain(completed.stdout)


def head_oid(repo: Path) -> str | None:
    completed = run_git(repo, ["rev-parse", "--verify", "HEAD"])
    if completed.returncode != 0:
        return None
    return completed.stdout.decode("ascii", errors="strict").strip()


def write_snapshot(repo: Path, output: Path) -> None:
    if output.exists():
        raise HostCommitError(f"snapshot already exists: {output}", REQUEST_ERROR)
    dirty, staged = working_tree_state(repo)
    payload = {
        "schema_version": 1,
        "repo_root": str(repo),
        "head": head_oid(repo),
        "dirty_paths": sorted(dirty),
        "staged_paths": sorted(staged),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def snapshot_digest(path: Path) -> bytes:
    try:
        return hashlib.sha256(path.read_bytes()).digest()
    except OSError as error:
        raise HostCommitError(f"unable to read dirty snapshot: {error}", REQUEST_ERROR) from error


def load_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise HostCommitError(f"invalid {label}: {error}", REQUEST_ERROR) from error
    if not isinstance(document, dict):
        raise HostCommitError(f"invalid {label}: top level must be an object", REQUEST_ERROR)
    return document


def validate_path_text(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise HostCommitError("request paths must be non-empty strings", REQUEST_ERROR)
    if "\x00" in value or "\\" in value:
        raise HostCommitError(f"unsafe request path: {value!r}", REQUEST_ERROR)
    pure = PurePosixPath(value)
    if pure.is_absolute() or value != pure.as_posix() or value in {".", ".."}:
        raise HostCommitError(f"request path must be normalized and relative: {value!r}", REQUEST_ERROR)
    if ".." in pure.parts:
        raise HostCommitError(f"path traversal is forbidden: {value!r}", REQUEST_ERROR)
    lowered_parts = [part.lower() for part in pure.parts]
    if any(part in FORBIDDEN_DIRS for part in lowered_parts):
        raise HostCommitError(f"forbidden directory in request path: {value!r}", REQUEST_ERROR)
    name = lowered_parts[-1]
    suffix = PurePosixPath(name).suffix.lower()
    if name == ".env" or name.startswith(".env."):
        raise HostCommitError(f"environment file is forbidden: {value!r}", REQUEST_ERROR)
    if suffix in FORBIDDEN_AUDIO_SUFFIXES:
        raise HostCommitError(f"audio file is forbidden: {value!r}", REQUEST_ERROR)
    if "cookie" in name:
        raise HostCommitError(f"cookie file is forbidden: {value!r}", REQUEST_ERROR)
    if name in FORBIDDEN_PRIVATE_KEY_NAMES or suffix in FORBIDDEN_SECRET_SUFFIXES:
        raise HostCommitError(f"private key file is forbidden: {value!r}", REQUEST_ERROR)
    if name in FORBIDDEN_HISTORY_NAMES:
        raise HostCommitError(f"shell history is forbidden: {value!r}", REQUEST_ERROR)
    if name.startswith("credentials") or name.startswith("secrets"):
        raise HostCommitError(f"credential or secret file is forbidden: {value!r}", REQUEST_ERROR)
    return value


def load_request(path: Path) -> tuple[str, list[str]]:
    document = load_json_object(path, "commit request")
    if set(document) != {"message", "paths"}:
        raise HostCommitError(
            "commit request must contain only message and paths",
            REQUEST_ERROR,
        )
    message = document["message"]
    if not isinstance(message, str) or not message.strip():
        raise HostCommitError("commit message must not be empty", REQUEST_ERROR)
    if "\n" in message or "\r" in message:
        raise HostCommitError("commit message must be one line", REQUEST_ERROR)
    raw_paths = document["paths"]
    if not isinstance(raw_paths, list) or not raw_paths:
        raise HostCommitError("commit request paths must not be empty", REQUEST_ERROR)
    paths = [validate_path_text(value) for value in raw_paths]
    if len(paths) != len(set(paths)):
        raise HostCommitError("duplicate paths are forbidden", REQUEST_ERROR)
    return message, paths


def load_snapshot(path: Path, repo: Path) -> tuple[set[str], set[str]]:
    document = load_json_object(path, "dirty snapshot")
    required = {"schema_version", "repo_root", "head", "dirty_paths", "staged_paths"}
    if set(document) != required or document["schema_version"] != 1:
        raise HostCommitError("dirty snapshot schema is invalid", REQUEST_ERROR)
    if document["repo_root"] != str(repo):
        raise HostCommitError("dirty snapshot belongs to a different repository", REQUEST_ERROR)
    dirty_values = document["dirty_paths"]
    staged_values = document["staged_paths"]
    if not isinstance(dirty_values, list) or not isinstance(staged_values, list):
        raise HostCommitError("dirty snapshot paths must be arrays", REQUEST_ERROR)
    dirty = {validate_path_text(value) for value in dirty_values}
    staged = {validate_path_text(value) for value in staged_values}
    if not staged.issubset(dirty):
        raise HostCommitError("dirty snapshot staged paths are inconsistent", REQUEST_ERROR)
    return dirty, staged


def staged_paths(repo: Path) -> set[str]:
    completed = run_git(repo, ["diff", "--cached", "--name-only", "-z"])
    if completed.returncode != 0:
        raise HostCommitError("unable to inspect staged paths", STAGE_ERROR)
    return {os.fsdecode(item) for item in completed.stdout.split(b"\0") if item}


def validate_ignored(repo: Path, paths: list[str]) -> None:
    for path in paths:
        completed = run_git(repo, ["check-ignore", "--no-index", "--quiet", "--", path])
        if completed.returncode == 0:
            raise HostCommitError(f"ignored path is forbidden: {path!r}", REQUEST_ERROR)
        if completed.returncode not in {1}:
            raise HostCommitError(f"unable to evaluate ignore rules for {path!r}", REQUEST_ERROR)


def validate_request_state(
    repo: Path,
    paths: list[str],
    preexisting: set[str],
    preexisting_staged: set[str],
) -> None:
    requested = set(paths)
    overlap = requested & preexisting
    if overlap:
        raise HostCommitError(
            f"pre-existing dirty paths cannot be staged: {sorted(overlap)!r}",
            REQUEST_ERROR,
        )
    if preexisting_staged:
        raise HostCommitError(
            f"pre-existing staged paths require human review: {sorted(preexisting_staged)!r}",
            STAGE_ERROR,
        )
    current_dirty, current_staged = working_tree_state(repo)
    if current_staged:
        raise HostCommitError(
            f"agent-created staging is forbidden: {sorted(current_staged)!r}",
            STAGE_ERROR,
        )
    unexpected = current_dirty - preexisting - requested
    if unexpected:
        raise HostCommitError(
            f"dirty paths outside the request are forbidden: {sorted(unexpected)!r}",
            REQUEST_ERROR,
        )
    missing_dirty = requested - current_dirty
    if missing_dirty:
        raise HostCommitError(
            f"request paths are not dirty: {sorted(missing_dirty)!r}",
            REQUEST_ERROR,
        )
    for path in paths:
        candidate = repo / path
        if not candidate.exists() and not candidate.is_symlink():
            raise HostCommitError(f"deleted or missing paths require human review: {path!r}", REQUEST_ERROR)
        if candidate.is_dir():
            raise HostCommitError(f"request paths must name files: {path!r}", REQUEST_ERROR)
        try:
            candidate.resolve(strict=False).relative_to(repo)
        except ValueError as error:
            raise HostCommitError(f"request path escapes the repository: {path!r}", REQUEST_ERROR) from error
    validate_ignored(repo, paths)


def unstage_after_failure(repo: Path, paths: list[str], had_head: bool) -> None:
    if had_head:
        run_git(repo, ["restore", "--staged", "--", *paths])
    else:
        run_git(repo, ["rm", "--cached", "-r", "--ignore-unmatch", "--", *paths])


def commit_request(repo: Path, request_path: Path, snapshot_path: Path) -> None:
    message, paths = load_request(request_path)
    preexisting, preexisting_staged = load_snapshot(snapshot_path, repo)
    validate_request_state(repo, paths, preexisting, preexisting_staged)
    had_head = head_oid(repo) is not None
    staged = False
    try:
        added = run_git(repo, ["add", "--", *paths])
        if added.returncode != 0:
            detail = added.stderr.decode("utf-8", errors="replace").strip()
            raise HostCommitError(f"git add failed: {detail or 'unknown error'}", STAGE_ERROR)
        staged = True
        actual = staged_paths(repo)
        expected = set(paths)
        if actual != expected:
            raise HostCommitError(
                f"staged paths do not match request: expected={sorted(expected)!r} actual={sorted(actual)!r}",
                STAGE_ERROR,
            )
        checked = run_git(repo, ["diff", "--cached", "--check"])
        if checked.returncode != 0:
            detail = checked.stdout.decode("utf-8", errors="replace").strip()
            raise HostCommitError(f"git diff --cached --check failed: {detail}", STAGE_ERROR)
        committed = run_git(repo, ["commit", "-m", message], capture=False)
        if committed.returncode != 0:
            detail = committed.stderr.decode("utf-8", errors="replace").strip()
            raise HostCommitError(f"git commit failed: {detail or 'unknown error'}", COMMIT_ERROR)
        staged = False
    finally:
        if staged:
            unstage_after_failure(repo, paths, had_head)


def find_python() -> str:
    return sys.executable


def validate_json_tool(path: Path) -> None:
    completed = subprocess.run(
        [find_python(), "-m", "json.tool", str(path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise HostCommitError(f"commit request is not valid JSON: {detail}", REQUEST_ERROR)


def create_run_dir(repo: Path, kind: str) -> Path:
    logs = repo / "logs"
    logs.mkdir(exist_ok=True)
    stem = f"{kind}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{os.getpid()}"
    run_dir = logs / stem
    run_dir.mkdir()
    return run_dir


def stream_agent(command: list[str], prompt: Path, log: Path, environment: dict[str, str]) -> int:
    try:
        with prompt.open("rb") as prompt_stream, log.open("wb") as log_stream:
            process = subprocess.Popen(
                command,
                stdin=prompt_stream,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=environment,
            )
            assert process.stdout is not None
            for chunk in iter(lambda: process.stdout.read(65536), b""):
                log_stream.write(chunk)
                log_stream.flush()
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()
            return process.wait()
    except FileNotFoundError as error:
        print(f"error: agent executable was not found: {error}", file=sys.stderr)
        return 127


def agent_command(agent: str) -> list[str]:
    if agent == "codex":
        return ["codex", "exec", "--sandbox", "workspace-write", "-"]
    if agent == "claude":
        return ["claude", "-p", "--permission-mode", "acceptEdits"]
    raise HostCommitError(f"unknown agent: {agent}", REQUEST_ERROR)


def map_commit_error(error: HostCommitError) -> int:
    if error.exit_code == REQUEST_ERROR:
        return RUNNER_REQUEST_ERROR
    if error.exit_code == STAGE_ERROR:
        return RUNNER_STAGE_ERROR
    return RUNNER_COMMIT_ERROR


def load_features(repo: Path) -> dict[str, Any]:
    document = load_json_object(repo / "docs" / "features.json", "features document")
    if feature_completion_state(document) == FEATURE_STATE_INVALID:
        raise HostCommitError("features document schema is invalid", REQUEST_ERROR)
    return document


def feature_completion_state(document: Any) -> str:
    """Return the fail-closed global completion state for a features document."""
    if not isinstance(document, dict):
        return FEATURE_STATE_INVALID
    features = document.get("features")
    if not isinstance(features, list) or not features:
        return FEATURE_STATE_INVALID
    for feature in features:
        if not isinstance(feature, dict):
            return FEATURE_STATE_INVALID
        if not isinstance(feature.get("id"), str) or not feature["id"]:
            return FEATURE_STATE_INVALID
        if "passes" not in feature or not isinstance(feature["passes"], bool):
            return FEATURE_STATE_INVALID
        if "blocked" not in feature or not isinstance(feature["blocked"], bool):
            return FEATURE_STATE_INVALID

    unfinished = [feature for feature in features if not feature["passes"]]
    if not unfinished:
        return FEATURE_STATE_ALL_PASSED
    if all(feature["blocked"] for feature in unfinished):
        return FEATURE_STATE_ALL_REMAINING_BLOCKED
    return FEATURE_STATE_CONTINUE


def pending_feature(document: dict[str, Any]) -> dict[str, Any] | None:
    for feature in document["features"]:
        if not isinstance(feature, dict) or not isinstance(feature.get("id"), str):
            raise HostCommitError("each feature must contain a string id", REQUEST_ERROR)
        if feature.get("passes") is not True and feature.get("blocked") is not True:
            return feature
    return None


def render_feature_value(value: Any, fallback: str) -> str:
    if isinstance(value, list) and value:
        return "\n".join(f"  - {item}" for item in value)
    if isinstance(value, str) and value.strip():
        return f"  - {value.strip()}"
    return f"  - {fallback}"


def build_iteration_prompt(base_prompt: str, feature: dict[str, Any], iteration: int) -> str:
    feature_id = feature["id"]
    title = feature.get("title") or feature.get("description") or feature_id
    acceptance = feature.get("acceptance_criteria") or feature.get("description")
    steps = feature.get("test_expectations") or feature.get("steps")
    allowed = feature.get("allowed_files") or feature.get("scope")
    prohibited = feature.get("prohibited_scope")
    contract = f"""# Runner-assigned bounded feature

- feature ID: {feature_id}
- title: {title}
- iteration: {iteration}
- acceptance criteria:
{render_feature_value(acceptance, "docs/features.jsonの指定featureに記載された条件")}
- test expectations:
{render_feature_value(steps, "指定featureのstepsとdocs/PLAN.mdの対応テスト")}
- allowed files / scope:
{render_feature_value(allowed, "指定featureを完了するために必要な最小範囲")}
- prohibited scope:
{render_feature_value(prohibited, "指定feature以外のfeatureと無関係な変更")}

次のfeatureを選ばない。subagent、agent delegation、`/goal`、wait_agentを使用しない。

"""
    return contract + base_prompt


def run_commit_boundary(
    repo: Path,
    request: Path,
    snapshot: Path,
    expected_snapshot_digest: bytes | None = None,
) -> int:
    try:
        if not request.is_file():
            raise HostCommitError(f"commit request was not created: {request}", REQUEST_ERROR)
        if (
            expected_snapshot_digest is not None
            and snapshot_digest(snapshot) != expected_snapshot_digest
        ):
            raise HostCommitError("pre-existing dirty snapshot was modified by the agent", REQUEST_ERROR)
        validate_json_tool(request)
        commit_request(repo, request, snapshot)
        return 0
    except HostCommitError as error:
        print(f"error: {error}", file=sys.stderr)
        return map_commit_error(error)


def run_legacy_loop(repo: Path, agent: str, max_iterations: int) -> int:
    prompt = repo / "PROMPT.md"
    if not prompt.is_file():
        print("error: PROMPT.md was not found", file=sys.stderr)
        return 66
    run_dir = create_run_dir(repo, "run")
    base_prompt = prompt.read_text(encoding="utf-8")
    for iteration in range(1, max_iterations + 1):
        document = load_features(repo)
        feature = pending_feature(document)
        if feature is None:
            incomplete = [item for item in document["features"] if item.get("passes") is not True]
            if incomplete:
                print("[blocked] no selectable feature remains", file=sys.stderr)
                return 2
            print("[done] all features already pass")
            return 0
        iteration_dir = run_dir / f"iter-{iteration:03d}"
        iteration_dir.mkdir()
        request = iteration_dir / "commit-request.json"
        snapshot = iteration_dir / "pre-existing-dirty.json"
        if request.exists():
            print(f"error: commit request already exists: {request}", file=sys.stderr)
            return RUNNER_REQUEST_ERROR
        write_snapshot(repo, snapshot)
        trusted_snapshot_digest = snapshot_digest(snapshot)
        generated_prompt = iteration_dir / "prompt.md"
        generated_prompt.write_text(
            build_iteration_prompt(base_prompt, feature, iteration),
            encoding="utf-8",
        )
        environment = os.environ.copy()
        environment["GOAL_LOOP_COMMIT_REQUEST"] = str(request)
        environment["GOAL_LOOP_PREEXISTING_DIRTY"] = str(snapshot)
        print(
            f"[start] iteration {iteration}/{max_iterations} agent={agent} feature={feature['id']}",
            flush=True,
        )
        exit_code = stream_agent(
            agent_command(agent),
            generated_prompt,
            iteration_dir / "agent.log",
            environment,
        )
        if exit_code != 0:
            print(f"error: agent exited with {exit_code}; host commit was skipped", file=sys.stderr)
            return AGENT_ERROR
        boundary = run_commit_boundary(repo, request, snapshot, trusted_snapshot_digest)
        if boundary != 0:
            return boundary
        completion_state = feature_completion_state(load_features(repo))
        if completion_state == FEATURE_STATE_ALL_PASSED:
            print(f"[done] all features pass after host commit (iteration {iteration})")
            return 0
        if completion_state == FEATURE_STATE_ALL_REMAINING_BLOCKED:
            print(f"[blocked] all remaining features are blocked after host commit (iteration {iteration})")
            return 2
    print(f"[stop] maximum iterations reached: {max_iterations}")
    return 1


def run_kickoff(repo: Path, agent: str) -> int:
    prompt = repo / "prompts" / "KICKOFF.md"
    if not prompt.is_file():
        print("error: prompts/KICKOFF.md was not found", file=sys.stderr)
        return 66
    run_dir = create_run_dir(repo, "kickoff")
    request = run_dir / "commit-request.json"
    snapshot = run_dir / "pre-existing-dirty.json"
    if request.exists():
        print(f"error: commit request already exists: {request}", file=sys.stderr)
        return RUNNER_REQUEST_ERROR
    write_snapshot(repo, snapshot)
    trusted_snapshot_digest = snapshot_digest(snapshot)
    environment = os.environ.copy()
    environment["GOAL_LOOP_COMMIT_REQUEST"] = str(request)
    environment["GOAL_LOOP_PREEXISTING_DIRTY"] = str(snapshot)
    exit_code = stream_agent(agent_command(agent), prompt, run_dir / "agent.log", environment)
    if exit_code != 0:
        print(f"error: agent exited with {exit_code}; host commit was skipped", file=sys.stderr)
        return AGENT_ERROR
    boundary = run_commit_boundary(repo, request, snapshot, trusted_snapshot_digest)
    if boundary == 0:
        print("[done] kickoff host commit completed; implementation loop was not started")
    return boundary


def positive_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    snapshot = subparsers.add_parser("snapshot")
    snapshot.add_argument("--output", type=Path, required=True)

    commit = subparsers.add_parser("commit")
    commit.add_argument("--request", type=Path, required=True)
    commit.add_argument("--pre-existing", type=Path, required=True)

    loop = subparsers.add_parser("loop")
    loop.add_argument("agent", nargs="?", choices=("claude", "codex"), default="claude")
    loop.add_argument("max_iterations", nargs="?", type=positive_integer, default=10)

    kickoff = subparsers.add_parser("kickoff")
    kickoff.add_argument("agent", nargs="?", choices=("claude", "codex"), default="claude")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        repo = repo_root(Path.cwd())
        if args.command == "snapshot":
            write_snapshot(repo, args.output.resolve())
        elif args.command == "commit":
            validate_json_tool(args.request)
            commit_request(repo, args.request.resolve(), args.pre_existing.resolve())
        elif args.command == "loop":
            return run_legacy_loop(repo, args.agent, args.max_iterations)
        else:
            return run_kickoff(repo, args.agent)
        return 0
    except HostCommitError as error:
        print(f"error: {error}", file=sys.stderr)
        return error.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
