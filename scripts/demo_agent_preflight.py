#!/usr/bin/env python3
"""Plan-only AI-agent preflight demo.

The script runs repo-health-doctor against a repository, prints the intended
target command as a plan, and stops. It never executes the target command.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
from typing import Mapping, Sequence


GATE_FAIL_MODES: Mapping[str, frozenset[str]] = {
    "block": frozenset({"block"}),
    "quarantine": frozenset({"quarantine", "block"}),
    "warn": frozenset({"warn", "quarantine", "block"}),
    "unknown": frozenset({"unknown", "warn", "quarantine", "block"}),
}
DOT = r"\."
LOCAL_IP_PATTERN = re.compile(
    r"(?<!\d)(?:"
    + "127" + DOT + "0" + DOT + "0" + DOT + "1"
    + "|10" + DOT + r"\d{1,3}" + DOT + r"\d{1,3}" + DOT + r"\d{1,3}"
    + "|192" + DOT + "168" + DOT + r"\d{1,3}" + DOT + r"\d{1,3}"
    + "|172" + DOT + r"(?:1[6-9]|2\d|3[01])" + DOT + r"\d{1,3}" + DOT + r"\d{1,3}"
    + r")(?!\d)"
)
DRIVE_PATH_PATTERN = re.compile(r"^[A-Za-z]:\\")


def main(argv: Sequence[str] | None = None) -> int:
    preflight_args, target_argv = _split_target_argv(list(sys.argv[1:] if argv is None else argv))
    parser = _build_parser()
    args = parser.parse_args(preflight_args)

    repo_root = Path(__file__).resolve().parents[1]
    repo_path = Path(args.repo_path)
    result = _run_repo_health_doctor(repo_root, repo_path)

    print("Repo Health Doctor AI Agent Preflight Demo")
    print(f"Repository: {_display_repo(repo_path)}")
    print(f"Intended target command (display only): {_format_target_command(target_argv)}")
    print("Target command executed: false")
    print("Global agent hook/config changed: false")

    if not result.gate_decision:
        print("Preflight status: failed")
        print("Action: DO NOT EXECUTE target command.")
        print("Reason: repo-health-doctor did not produce a gate decision.")
        print("Safety note: no evidence is not PASS.")
        return 2

    gate = result.gate_decision
    verdict = str(gate.get("verdict", "unknown")).lower()
    execution_authorized = gate.get("execution_authorized") is True
    print(f"Preflight CLI exit code: {result.returncode}")
    print(f"Gate decision: {verdict.upper()}")
    print(f"Execution authorized: {'true' if execution_authorized else 'false'}")

    action_blocks = verdict in GATE_FAIL_MODES[args.fail_on_gate]
    if action_blocks:
        print("Action: DO NOT EXECUTE target command.")
    else:
        print("Action: REVIEW ONLY; this demo still does not execute the target command.")

    for reason in _key_reasons(gate)[:4]:
        print(f"Reason: {reason}")

    print("Safety note: no findings is not proof of safety.")
    print("Safety note: scanner unavailable or no evidence is not PASS.")
    print("Safety note: a gate decision is not execution authorization.")
    return 2 if action_blocks or not execution_authorized else 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Plan-only AI agent preflight demo. It runs repo-health-doctor, "
            "prints the intended target command, and never executes that command."
        ),
        epilog=(
            "Example: env PYTHONPATH=src python3 scripts/demo_agent_preflight.py "
            "examples/demo-synthetic-supply-chain -- npm install"
        ),
    )
    parser.add_argument(
        "repo_path",
        nargs="?",
        default="examples/demo-synthetic-supply-chain",
        help="Repository path to preflight. Defaults to the synthetic supply-chain demo fixture.",
    )
    parser.add_argument(
        "--fail-on-gate",
        choices=tuple(GATE_FAIL_MODES),
        default="unknown",
        help=(
            "Demo threshold for DO NOT EXECUTE. The target command is still never executed, "
            "and Claude Code, Codex, Cursor, and global hook configuration are not changed."
        ),
    )
    return parser


def _split_target_argv(argv: list[str]) -> tuple[list[str], list[str]]:
    if "--" not in argv:
        return argv, []
    separator = argv.index("--")
    return argv[:separator], argv[separator + 1 :]


class PreflightResult:
    def __init__(self, *, returncode: int, gate_decision: Mapping[str, object] | None) -> None:
        self.returncode = returncode
        self.gate_decision = gate_decision


def _run_repo_health_doctor(repo_root: Path, repo_path: Path) -> PreflightResult:
    with tempfile.TemporaryDirectory(prefix="rhd-agent-preflight-") as temp_dir:
        report_path = Path(temp_dir) / "report.json"
        gate_path = Path(temp_dir) / "gate.json"
        command = (
            sys.executable,
            "-m",
            "repo_health_doctor",
            str(repo_path),
            "--public-safety",
            "--gate-summary",
            "--format",
            "json",
            "--output",
            str(report_path),
            "--gate-decision-output",
            str(gate_path),
        )
        completed = subprocess.run(
            list(command),
            check=False,
            capture_output=True,
            text=True,
            env=_cli_env(repo_root),
        )
        gate_decision = _load_gate_decision(gate_path)
        return PreflightResult(returncode=completed.returncode, gate_decision=gate_decision)


def _cli_env(repo_root: Path) -> dict[str, str]:
    env = os.environ.copy()
    src_path = repo_root / "src"
    if src_path.is_dir():
        current = env.get("PYTHONPATH")
        env["PYTHONPATH"] = str(src_path) if not current else str(src_path) + os.pathsep + current
    return env


def _load_gate_decision(path: Path) -> Mapping[str, object] | None:
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _display_repo(repo_path: Path) -> str:
    return str(repo_path) if not repo_path.is_absolute() else "<repo>"


def _format_target_command(argv: Sequence[str]) -> str:
    if not argv:
        return "<none supplied>"
    redacted: list[str] = []
    redact_next = False
    for item in argv:
        if redact_next:
            redacted.append("<redacted>")
            redact_next = _redacts_following_arg(item)
            continue
        redacted.append(_redact_arg(item))
        redact_next = _redacts_following_arg(item)
    return " ".join(item if item.startswith("<") and item.endswith(">") else shlex.quote(item) for item in redacted)


def _redact_arg(value: str) -> str:
    lowered = value.lower()
    if Path(value).is_absolute() or DRIVE_PATH_PATTERN.match(value):
        return "<path>"
    if LOCAL_IP_PATTERN.search(value):
        return "<redacted>"
    sensitive_markers = (
        "secret",
        "credential",
        "pass" + "word",
        "to" + "ken",
        "authorization",
        "bearer",
    )
    if any(marker in lowered for marker in sensitive_markers):
        return "<redacted>"
    return value


def _redacts_following_arg(value: str) -> bool:
    lowered = value.lower().strip()
    if "=" in lowered:
        return False
    sensitive_markers = (
        "secret",
        "credential",
        "pass" + "word",
        "to" + "ken",
        "authorization",
        "bearer",
    )
    normalized = lowered.rstrip(":")
    if normalized in {"bearer", "authorization"}:
        return True
    return normalized.startswith("-") and any(marker in normalized for marker in sensitive_markers)


def _key_reasons(gate_decision: Mapping[str, object]) -> list[str]:
    explanation = gate_decision.get("explanation")
    if not isinstance(explanation, Mapping):
        return []
    reasons = explanation.get("key_reasons")
    return [item for item in reasons if isinstance(item, str)] if isinstance(reasons, list) else []


if __name__ == "__main__":
    raise SystemExit(main())
