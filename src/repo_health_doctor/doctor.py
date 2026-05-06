from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
import json
import re
from typing import Iterable


DEFAULT_LARGE_FILE_THRESHOLD_MB = 10
LARGE_FILE_THRESHOLD_BYTES = DEFAULT_LARGE_FILE_THRESHOLD_MB * 1024 * 1024
TEXT_FILE_SCAN_LIMIT_BYTES = 1 * 1024 * 1024
MAX_SCANNED_FILES = 200

README_NAMES = ("README", "README.md", "README.rst", "README.txt")
LICENSE_NAMES = ("LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING")
GITIGNORE_NAMES = (".gitignore", ".git/info/exclude")
TEST_DIR_NAMES = ("tests", "test")
DOCS_DIR_NAMES = ("docs", "doc")
SCRIPT_DIR_NAMES = ("scripts", "script", "bin")
DEFAULT_SECRETS_IGNORES = (
    ".git/",
    ".venv/",
    "venv/",
    "node_modules/",
    "__pycache__/",
    ".pytest_cache/",
    "dist/",
    "build/",
)

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github_token", re.compile(r"github_pat_[A-Za-z0-9_]{20,}")),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("private_key", re.compile(r"-----BEGIN (RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----")),
    ("generic_api_key", re.compile(r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}")),
)

IGNORED_DIRS = {".git", ".hg", ".svn", "__pycache__", ".venv", "node_modules", "dist", "build"}
TEXT_EXTENSIONS = {
    ".py", ".md", ".rst", ".txt", ".json", ".toml", ".yaml", ".yml", ".ini",
    ".cfg", ".env", ".sh", ".bash", ".zsh", ".js", ".ts", ".tsx", ".jsx",
    ".java", ".go", ".rs", ".rb", ".php", ".c", ".cc", ".cpp", ".h", ".hpp",
}
NULL_BYTE = b"\x00"


@dataclass
class CheckResult:
    name: str
    status: str
    summary: str
    details: dict


def _iter_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if any(part in IGNORED_DIRS for part in path.parts):
            continue
        if path.is_file():
            yield path


def _has_any(root: Path, names: tuple[str, ...]) -> list[str]:
    found: list[str] = []
    for name in names:
        candidate = root / name
        if candidate.exists():
            found.append(name)
    return found


def _has_dir(root: Path, names: tuple[str, ...]) -> list[str]:
    found: list[str] = []
    for name in names:
        candidate = root / name
        if candidate.is_dir():
            found.append(name)
    return found


def _normalize_ignore_pattern(pattern: str) -> str:
    normalized = pattern.replace("\\", "/").strip()
    if not normalized:
        return normalized
    return normalized if normalized.endswith("/") else f"{normalized}/"


def _is_ignored_for_secrets(relative_path: Path, ignore_patterns: tuple[str, ...]) -> bool:
    relative_text = relative_path.as_posix()
    path_with_sep = f"{relative_text}/"
    for pattern in ignore_patterns:
        normalized_pattern = _normalize_ignore_pattern(pattern)
        if not normalized_pattern:
            continue
        if path_with_sep.startswith(normalized_pattern) or f"/{normalized_pattern}" in path_with_sep:
            return True
    return False


def _is_binary_file(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            sample = handle.read(1024)
    except OSError:
        return True
    return NULL_BYTE in sample


def _scan_secrets(root: Path, ignore_patterns: tuple[str, ...]) -> tuple[list[dict], int]:
    findings: list[dict] = []
    scanned_files = 0

    for path in _iter_files(root):
        if scanned_files >= MAX_SCANNED_FILES:
            break
        relative_path = path.relative_to(root)
        if _is_ignored_for_secrets(relative_path, ignore_patterns):
            continue
        if path.suffix.lower() not in TEXT_EXTENSIONS and path.name not in {".env", ".env.local"}:
            continue
        if _is_binary_file(path):
            continue
        try:
            if path.stat().st_size > TEXT_FILE_SCAN_LIMIT_BYTES:
                continue
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        scanned_files += 1
        for label, pattern in SECRET_PATTERNS:
            match = pattern.search(content)
            if match:
                findings.append(
                    {
                        "file": str(path.relative_to(root)),
                        "pattern": label,
                        "excerpt": match.group(0)[:80],
                    }
                )

    return findings, scanned_files


def _scan_large_files(root: Path, threshold_bytes: int) -> list[dict]:
    findings: list[dict] = []
    for path in _iter_files(root):
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size >= threshold_bytes:
            findings.append(
                {
                    "file": str(path.relative_to(root)),
                    "size_bytes": size,
                }
            )
    findings.sort(key=lambda item: item["size_bytes"], reverse=True)
    return findings


def diagnose_repo(
    repo_path: str | Path,
    large_file_threshold_mb: int = DEFAULT_LARGE_FILE_THRESHOLD_MB,
    secrets_ignores: tuple[str, ...] = (),
) -> dict:
    root = Path(repo_path).resolve()
    threshold_bytes = large_file_threshold_mb * 1024 * 1024
    combined_secrets_ignores = DEFAULT_SECRETS_IGNORES + tuple(secrets_ignores)
    checks: list[CheckResult] = []

    readmes = _has_any(root, README_NAMES)
    checks.append(
        CheckResult(
            name="readme",
            status="pass" if readmes else "warn",
            summary="README found." if readmes else "README is missing.",
            details={"found": readmes},
        )
    )

    licenses = _has_any(root, LICENSE_NAMES)
    checks.append(
        CheckResult(
            name="license",
            status="pass" if licenses else "warn",
            summary="License file found." if licenses else "License file is missing.",
            details={"found": licenses},
        )
    )

    gitignores = _has_any(root, GITIGNORE_NAMES)
    checks.append(
        CheckResult(
            name="gitignore",
            status="pass" if gitignores else "warn",
            summary=".gitignore found." if gitignores else ".gitignore is missing.",
            details={"found": gitignores},
        )
    )

    test_dirs = _has_dir(root, TEST_DIR_NAMES)
    checks.append(
        CheckResult(
            name="tests",
            status="pass" if test_dirs else "warn",
            summary="Test directory found." if test_dirs else "Test directory is missing.",
            details={"found": test_dirs},
        )
    )

    docs_dirs = _has_dir(root, DOCS_DIR_NAMES)
    checks.append(
        CheckResult(
            name="docs",
            status="pass" if docs_dirs else "warn",
            summary="Docs directory found." if docs_dirs else "Docs directory is missing.",
            details={"found": docs_dirs},
        )
    )

    script_dirs = _has_dir(root, SCRIPT_DIR_NAMES)
    checks.append(
        CheckResult(
            name="scripts",
            status="pass" if script_dirs else "warn",
            summary="Scripts directory found." if script_dirs else "Scripts directory is missing.",
            details={"found": script_dirs},
        )
    )

    secret_findings, scanned_files = _scan_secrets(root, combined_secrets_ignores)
    checks.append(
        CheckResult(
            name="secrets_scan",
            status="fail" if secret_findings else "pass",
            summary="Potential secrets detected." if secret_findings else "No obvious secrets detected.",
            details={
                "findings": secret_findings,
                "scanned_files": scanned_files,
                "ignored_paths": list(combined_secrets_ignores),
            },
        )
    )

    large_files = _scan_large_files(root, threshold_bytes)
    checks.append(
        CheckResult(
            name="large_files",
            status="warn" if large_files else "pass",
            summary="Large files detected." if large_files else "No large files detected.",
            details={
                "threshold_mb": large_file_threshold_mb,
                "threshold_bytes": threshold_bytes,
                "findings": large_files,
            },
        )
    )

    counts = {
        "pass": sum(1 for check in checks if check.status == "pass"),
        "warn": sum(1 for check in checks if check.status == "warn"),
        "fail": sum(1 for check in checks if check.status == "fail"),
    }

    overall_status = "fail" if counts["fail"] else "warn" if counts["warn"] else "pass"
    return {
        "tool": "repo-health-doctor",
        "version": "0.1.0",
        "repo_path": str(root),
        "overall_status": overall_status,
        "summary": counts,
        "checks": [asdict(check) for check in checks],
    }


def format_text(report: dict) -> str:
    lines = [
        f"Repo Health Doctor: {report['overall_status'].upper()}",
        f"Target: {report['repo_path']}",
        (
            "Summary: "
            f"{report['summary']['pass']} pass, "
            f"{report['summary']['warn']} warn, "
            f"{report['summary']['fail']} fail"
        ),
        "",
    ]

    for check in report["checks"]:
        lines.append(f"[{check['status'].upper()}] {check['name']}: {check['summary']}")
        details = check["details"]
        if details.get("found"):
            lines.append(f"  found: {', '.join(details['found'])}")
        if check["name"] == "secrets_scan":
            lines.append(f"  scanned_files: {details['scanned_files']}")
            for finding in details["findings"][:5]:
                lines.append(f"  possible secret: {finding['file']} ({finding['pattern']})")
        if check["name"] == "large_files":
            lines.append(f"  threshold_bytes: {details['threshold_bytes']}")
            for finding in details["findings"][:5]:
                lines.append(f"  large file: {finding['file']} ({finding['size_bytes']} bytes)")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def format_json(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"


def determine_exit_code(report: dict, strict: bool = False) -> int:
    if report["summary"]["fail"] > 0:
        return 1
    if strict and report["summary"]["warn"] > 0:
        return 1
    return 0
