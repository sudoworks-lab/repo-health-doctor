from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
import json
import re
import subprocess
from typing import Iterable


DEFAULT_LARGE_FILE_THRESHOLD_MB = 10
LARGE_FILE_THRESHOLD_BYTES = DEFAULT_LARGE_FILE_THRESHOLD_MB * 1024 * 1024
TEXT_FILE_SCAN_LIMIT_BYTES = 1 * 1024 * 1024
MAX_SCANNED_FILES = 200
REPORT_SCHEMA_VERSION = "1.0"

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
TRACKED_ARTIFACT_TOP_LEVEL_DIRS = {
    "artifacts",
    "logs",
    "log",
    "tmp",
    "temp",
    "cache",
}
TRACKED_ARTIFACT_CACHE_DIRS = {
    ".cache",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "htmlcov",
}
TRACKED_ARTIFACT_FILE_NAMES = {
    ".coverage",
    "coverage.xml",
}
TRACKED_ARTIFACT_SUFFIXES = {
    ".log",
    ".tmp",
    ".cache",
}
TRACKED_ENV_ALLOWED_NAMES = {
    ".env.example",
    ".env.sample",
    ".env.template",
}
TRACKED_ENV_PREFIX = ".env."

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
STATUS_PASS = "pass"
STATUS_WARN = "warn"
STATUS_BLOCK = "block"
RULE_ID_LARGE_FILE = "rhd.repository.large_file"
SECRET_RULE_IDS = {
    "aws_access_key": "rhd.secret.aws_access_key",
    "github_token": "rhd.secret.github_token",
    "slack_token": "rhd.secret.slack_token",
    "private_key": "rhd.secret.private_key",
    "generic_api_key": "rhd.secret.generic_api_key",
}
PUBLIC_TEXT_RULE_IDS = {
    "restricted_term": "rhd.public_text.restricted_term",
    "private_path": "rhd.public_text.private_path",
    "local_ip": "rhd.public_text.local_ip",
}
TRACKED_ARTIFACT_RULE_IDS = {
    "generated_dir": "rhd.tracked_artifact.generated_dir",
    "cache_dir": "rhd.tracked_artifact.cache_dir",
    "generated_file": "rhd.tracked_artifact.generated_file",
    "env_file": "rhd.tracked_artifact.env_file",
}


def _join_fragments(*parts: str) -> str:
    return "".join(parts)


RESTRICTED_PUBLIC_TERMS = (
    _join_fragments("Fi", "nd", "y"),
    _join_fragments("fi", "nd", "y"),
    _join_fragments("フ", "ァ", "イ", "ン", "デ", "ィ"),
    _join_fragments("転", "職"),
    _join_fragments("採", "用"),
    _join_fragments("採", "用", "担", "当"),
    _join_fragments("評", "価", "さ", "れ", "る"),
    _join_fragments("評", "価", "し", "て", "も", "ら", "う"),
    _join_fragments("評", "価", "向", "け"),
    _join_fragments("求", "人"),
    _join_fragments("ポ", "ー", "ト", "フ", "ォ", "リ", "オ", "向", "け"),
)
PUBLIC_TEXT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "restricted_term",
        re.compile("|".join(re.escape(term) for term in RESTRICTED_PUBLIC_TERMS)),
    ),
    (
        "private_path",
        re.compile(
            "|".join(
                (
                    re.escape(_join_fragments("/", "ho", "me", "/")) + r"[^/\s]+/",
                    re.escape(_join_fragments("/", "Users", "/")) + r"[^/\s]+/",
                    re.escape(_join_fragments("/", "mnt", "/", "c", "/", "Users", "/")) + r"[^/\s]+/",
                    re.escape(_join_fragments("C", ":", "\\", "Users", "\\")) + r"[^\\\s]+\\",
                )
            )
        ),
    ),
    (
        "local_ip",
        re.compile(
            "|".join(
                (
                    rf"{_join_fragments('1', '0')}\.\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}",
                    rf"{_join_fragments('1', '2', '7')}\.\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}",
                    rf"{_join_fragments('1', '7', '2')}\.(1[6-9]|2[0-9]|3[0-1])\.\d{{1,3}}\.\d{{1,3}}",
                    rf"{_join_fragments('1', '9', '2')}\.{_join_fragments('1', '6', '8')}\.\d{{1,3}}\.\d{{1,3}}",
                    rf"{_join_fragments('1', '0', '0')}\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.\d{{1,3}}\.\d{{1,3}}",
                )
            )
        ),
    ),
)


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


def _iter_candidate_files(
    root: Path,
    tracked_files: tuple[Path, ...] | None = None,
    include_ignored: bool = False,
) -> Iterable[Path]:
    if tracked_files is not None:
        for path in sorted(tracked_files, key=lambda item: item.as_posix()):
            try:
                relative_parts = path.relative_to(root).parts
            except ValueError:
                continue
            if not include_ignored and any(part in IGNORED_DIRS for part in relative_parts):
                continue
            if path.is_file():
                yield path
        return

    for path in root.rglob("*"):
        if not include_ignored and any(part in IGNORED_DIRS for part in path.parts):
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


def _list_tracked_files(root: Path) -> tuple[Path, ...] | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            check=False,
            capture_output=True,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None

    tracked_files: list[Path] = []
    for raw_path in result.stdout.split(NULL_BYTE):
        if not raw_path:
            continue
        try:
            relative_path = Path(raw_path.decode("utf-8"))
        except UnicodeDecodeError:
            continue
        candidate = root / relative_path
        if candidate.is_file():
            tracked_files.append(candidate)
    return tuple(tracked_files)


def _safe_repo_path(root: Path) -> str:
    try:
        cwd = Path.cwd().resolve()
    except OSError:
        return "<repo>"
    if root == cwd:
        return "."
    try:
        return root.relative_to(cwd).as_posix()
    except ValueError:
        return f"<repo:{root.name}>"


def _finding(
    *,
    rule_id: str,
    severity: str,
    file: str,
    pattern: str,
    redacted: bool,
    line: int | None = None,
    size_bytes: int | None = None,
) -> dict:
    finding = {
        "rule_id": rule_id,
        "severity": severity,
        "file": file,
        "pattern": pattern,
        "redacted": redacted,
    }
    if line is not None:
        finding["line"] = line
    if size_bytes is not None:
        finding["size_bytes"] = size_bytes
    return finding


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
                    _finding(
                        rule_id=SECRET_RULE_IDS[label],
                        severity=STATUS_BLOCK,
                        file=str(path.relative_to(root)),
                        pattern=label,
                        line=content.count("\n", 0, match.start()) + 1,
                        redacted=True,
                    )
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
                _finding(
                    rule_id=RULE_ID_LARGE_FILE,
                    severity=STATUS_WARN,
                    file=str(path.relative_to(root)),
                    pattern="large_file",
                    size_bytes=size,
                    redacted=False,
                )
            )
    findings.sort(key=lambda item: item["size_bytes"], reverse=True)
    return findings


def _scan_public_text_safety(
    root: Path,
    tracked_files: tuple[Path, ...] | None,
) -> tuple[list[dict], int, str]:
    findings: list[dict] = []
    scanned_files = 0
    scope = "tracked" if tracked_files is not None else "all"

    for path in _iter_candidate_files(root, tracked_files=tracked_files, include_ignored=True):
        if path.suffix.lower() not in TEXT_EXTENSIONS and path.name not in {".env", ".env.local", ".envrc"}:
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
        for label, pattern in PUBLIC_TEXT_PATTERNS:
            match = pattern.search(content)
            if not match:
                continue
            findings.append(
                _finding(
                    rule_id=PUBLIC_TEXT_RULE_IDS[label],
                    severity=STATUS_BLOCK,
                    file=str(path.relative_to(root)),
                    pattern=label,
                    line=content.count("\n", 0, match.start()) + 1,
                    redacted=True,
                )
            )

    return findings, scanned_files, scope


def _classify_tracked_artifact(relative_path: Path) -> str | None:
    lowered_parts = [part.lower() for part in relative_path.parts]
    if lowered_parts and lowered_parts[0] in TRACKED_ARTIFACT_TOP_LEVEL_DIRS:
        return "generated_dir"
    if any(part in TRACKED_ARTIFACT_CACHE_DIRS for part in lowered_parts[:-1]):
        return "cache_dir"

    name = relative_path.name.lower()
    if name in TRACKED_ARTIFACT_FILE_NAMES:
        return "generated_file"
    if name == ".env":
        return "env_file"
    if name.startswith(TRACKED_ENV_PREFIX) and name not in TRACKED_ENV_ALLOWED_NAMES:
        return "env_file"
    if relative_path.suffix.lower() in TRACKED_ARTIFACT_SUFFIXES:
        return "generated_file"
    return None


def _scan_tracked_artifacts(root: Path, tracked_files: tuple[Path, ...] | None) -> tuple[list[dict], str]:
    if tracked_files is None:
        return [], "unavailable"

    findings: list[dict] = []
    for path in sorted(tracked_files, key=lambda item: item.as_posix()):
        relative_path = path.relative_to(root)
        category = _classify_tracked_artifact(relative_path)
        if category:
            findings.append(
                _finding(
                    rule_id=TRACKED_ARTIFACT_RULE_IDS[category],
                    severity=STATUS_BLOCK,
                    file=str(relative_path),
                    pattern=category,
                    redacted=True,
                )
            )
    return findings, "tracked"


def diagnose_repo(
    repo_path: str | Path,
    large_file_threshold_mb: int = DEFAULT_LARGE_FILE_THRESHOLD_MB,
    secrets_ignores: tuple[str, ...] = (),
    public_safety: bool = False,
) -> dict:
    root = Path(repo_path).resolve()
    threshold_bytes = large_file_threshold_mb * 1024 * 1024
    combined_secrets_ignores = DEFAULT_SECRETS_IGNORES + tuple(secrets_ignores)
    checks: list[CheckResult] = []

    readmes = _has_any(root, README_NAMES)
    checks.append(
        CheckResult(
            name="readme",
            status=STATUS_PASS if readmes else STATUS_WARN,
            summary="README found." if readmes else "README is missing.",
            details={"found": readmes},
        )
    )

    licenses = _has_any(root, LICENSE_NAMES)
    checks.append(
        CheckResult(
            name="license",
            status=STATUS_PASS if licenses else STATUS_WARN,
            summary="License file found." if licenses else "License file is missing.",
            details={"found": licenses},
        )
    )

    gitignores = _has_any(root, GITIGNORE_NAMES)
    checks.append(
        CheckResult(
            name="gitignore",
            status=STATUS_PASS if gitignores else STATUS_WARN,
            summary=".gitignore found." if gitignores else ".gitignore is missing.",
            details={"found": gitignores},
        )
    )

    test_dirs = _has_dir(root, TEST_DIR_NAMES)
    checks.append(
        CheckResult(
            name="tests",
            status=STATUS_PASS if test_dirs else STATUS_WARN,
            summary="Test directory found." if test_dirs else "Test directory is missing.",
            details={"found": test_dirs},
        )
    )

    docs_dirs = _has_dir(root, DOCS_DIR_NAMES)
    checks.append(
        CheckResult(
            name="docs",
            status=STATUS_PASS if docs_dirs else STATUS_WARN,
            summary="Docs directory found." if docs_dirs else "Docs directory is missing.",
            details={"found": docs_dirs},
        )
    )

    script_dirs = _has_dir(root, SCRIPT_DIR_NAMES)
    checks.append(
        CheckResult(
            name="scripts",
            status=STATUS_PASS if script_dirs else STATUS_WARN,
            summary="Scripts directory found." if script_dirs else "Scripts directory is missing.",
            details={"found": script_dirs},
        )
    )

    secret_findings, scanned_files = _scan_secrets(root, combined_secrets_ignores)
    checks.append(
        CheckResult(
            name="secrets_scan",
            status=STATUS_BLOCK if secret_findings else STATUS_PASS,
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
            status=STATUS_WARN if large_files else STATUS_PASS,
            summary="Large files detected." if large_files else "No large files detected.",
            details={
                "threshold_mb": large_file_threshold_mb,
                "threshold_bytes": threshold_bytes,
                "findings": large_files,
            },
        )
    )

    if public_safety:
        tracked_files = _list_tracked_files(root)
        public_text_findings, scanned_files, scope = _scan_public_text_safety(root, tracked_files)
        checks.append(
            CheckResult(
                name="public_text_safety",
                status=STATUS_BLOCK if public_text_findings else STATUS_PASS,
                summary=(
                    "Public-facing text should be reviewed before release."
                    if public_text_findings
                    else "No obvious public-facing text issues detected."
                ),
                details={
                    "findings": public_text_findings,
                    "scanned_files": scanned_files,
                    "scan_scope": scope,
                },
            )
        )

        tracked_artifacts, tracked_scope = _scan_tracked_artifacts(root, tracked_files)
        tracked_artifact_status = STATUS_BLOCK if tracked_artifacts else STATUS_PASS
        tracked_artifact_summary = (
            "Tracked generated or environment files should be reviewed before release."
            if tracked_artifacts
            else (
                "Tracked generated or environment files were not detected."
                if tracked_scope == "tracked"
                else "Tracked file scan was unavailable."
            )
        )
        if tracked_scope == "unavailable":
            tracked_artifact_status = STATUS_WARN

        checks.append(
            CheckResult(
                name="tracked_artifacts",
                status=tracked_artifact_status,
                summary=tracked_artifact_summary,
                details={
                    "findings": tracked_artifacts,
                    "scan_scope": tracked_scope,
                },
            )
        )

    counts = {
        STATUS_PASS: sum(1 for check in checks if check.status == STATUS_PASS),
        STATUS_WARN: sum(1 for check in checks if check.status == STATUS_WARN),
        STATUS_BLOCK: sum(1 for check in checks if check.status == STATUS_BLOCK),
    }

    overall_status = (
        STATUS_BLOCK
        if counts[STATUS_BLOCK]
        else STATUS_WARN
        if counts[STATUS_WARN]
        else STATUS_PASS
    )
    return {
        "tool": "repo-health-doctor",
        "version": "0.1.0",
        "schema_version": REPORT_SCHEMA_VERSION,
        "repo_path": _safe_repo_path(root),
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
            f"{report['summary']['block']} block"
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
        if check["name"] == "public_text_safety":
            lines.append(f"  scanned_files: {details['scanned_files']}")
            lines.append(f"  scan_scope: {details['scan_scope']}")
            for finding in details["findings"][:5]:
                lines.append(
                    "  public text issue: "
                    f"{finding['file']} ({finding['pattern']} line {finding['line']})"
                )
        if check["name"] == "tracked_artifacts":
            lines.append(f"  scan_scope: {details['scan_scope']}")
            for finding in details["findings"][:5]:
                lines.append(f"  tracked file issue: {finding['file']} ({finding['pattern']})")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def format_json(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"


def determine_exit_code(report: dict, strict: bool = False) -> int:
    if report["summary"]["block"] > 0:
        return 1
    if strict and report["summary"]["warn"] > 0:
        return 1
    return 0
