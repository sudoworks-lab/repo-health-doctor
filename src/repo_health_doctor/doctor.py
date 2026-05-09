from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import date
import fnmatch
from pathlib import Path
import json
import re
import subprocess
from typing import Iterable


DEFAULT_LARGE_FILE_THRESHOLD_MB = 10
LARGE_FILE_THRESHOLD_BYTES = DEFAULT_LARGE_FILE_THRESHOLD_MB * 1024 * 1024
TEXT_FILE_SCAN_LIMIT_BYTES = 1 * 1024 * 1024
MAX_SCANNED_FILES = 200
REPORT_SCHEMA_VERSION = "1.1"
TOOL_VERSION = "0.1.0"

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
POLICY_RULE_IDS = {
    "invalid_config": "rhd.policy.invalid_config",
    "invalid_ignore": "rhd.policy.invalid_ignore",
    "invalid_allow": "rhd.policy.invalid_allow",
    "expired_allow": "rhd.policy.expired_allow",
    "unknown_rule_id": "rhd.policy.unknown_rule_id",
    "restricted_secret_allow": "rhd.policy.restricted_secret_allow",
}
KNOWN_FINDING_RULE_IDS = (
    set(SECRET_RULE_IDS.values())
    | set(PUBLIC_TEXT_RULE_IDS.values())
    | set(TRACKED_ARTIFACT_RULE_IDS.values())
    | {RULE_ID_LARGE_FILE}
)
SECRET_RULE_ID_VALUES = set(SECRET_RULE_IDS.values())
SECRET_ALLOW_FIXTURE_PREFIXES = ("tests/fixtures/", "test/fixtures/")


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


@dataclass(frozen=True)
class AllowFindingPolicy:
    policy_id: str
    source: str
    rule_id: str
    path_pattern: str


@dataclass
class PolicyConfig:
    ignore_paths: tuple[str, ...]
    allow_findings: tuple[AllowFindingPolicy, ...]
    issues: list[dict]
    sources: tuple[str, ...]
    ignore_path_count: int
    allow_finding_count: int


def _iter_files(root: Path, ignore_patterns: tuple[str, ...] = ()) -> Iterable[Path]:
    for path in root.rglob("*"):
        if any(part in IGNORED_DIRS for part in path.parts):
            continue
        if path.is_file():
            if _is_ignored_path(path.relative_to(root), ignore_patterns):
                continue
            yield path


def _iter_candidate_files(
    root: Path,
    tracked_files: tuple[Path, ...] | None = None,
    include_ignored: bool = False,
    ignore_patterns: tuple[str, ...] = (),
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
                if _is_ignored_path(path.relative_to(root), ignore_patterns):
                    continue
                yield path
        return

    for path in root.rglob("*"):
        if not include_ignored and any(part in IGNORED_DIRS for part in path.parts):
            continue
        if path.is_file():
            if _is_ignored_path(path.relative_to(root), ignore_patterns):
                continue
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
    return _is_ignored_path(relative_path, ignore_patterns)


def _is_ignored_path(relative_path: Path, ignore_patterns: tuple[str, ...]) -> bool:
    relative_text = relative_path.as_posix()
    path_with_sep = f"{relative_text}/"
    for pattern in ignore_patterns:
        normalized_pattern = pattern.replace("\\", "/").strip()
        if not normalized_pattern:
            continue
        if any(char in normalized_pattern for char in "*?[]"):
            if fnmatch.fnmatch(relative_text, normalized_pattern):
                return True
            continue
        normalized_pattern = _normalize_ignore_pattern(normalized_pattern)
        if path_with_sep.startswith(normalized_pattern):
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


def _parse_scalar(value: str) -> str:
    stripped = value.strip()
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in {"'", '"'}:
        return stripped[1:-1]
    return stripped


def _parse_simple_policy_yaml(content: str) -> dict:
    parsed: dict[str, list] = {}
    current_key: str | None = None
    current_item: dict | None = None
    for raw_line in content.splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        stripped = line.strip()
        if not line.startswith(" "):
            key, separator, value = stripped.partition(":")
            if not separator:
                raise ValueError("invalid top-level entry")
            current_key = key.strip()
            current_item = None
            if value.strip():
                parsed[current_key] = [_parse_scalar(value)]
            else:
                parsed[current_key] = []
            continue
        if current_key is None:
            raise ValueError("nested entry without top-level key")
        if stripped.startswith("- "):
            rest = stripped[2:].strip()
            if not rest:
                raise ValueError("empty list item")
            if ":" in rest:
                key, _, value = rest.partition(":")
                current_item = {key.strip(): _parse_scalar(value)}
                parsed[current_key].append(current_item)
            else:
                current_item = None
                parsed[current_key].append(_parse_scalar(rest))
            continue
        if current_item is None or ":" not in stripped:
            raise ValueError("invalid nested entry")
        key, _, value = stripped.partition(":")
        current_item[key.strip()] = _parse_scalar(value)
    return parsed


def _load_policy_document(path: Path) -> dict:
    content = path.read_text(encoding="utf-8")
    if not content.strip():
        return {}
    try:
        payload = json.loads(content)
    except json.JSONDecodeError:
        payload = _parse_simple_policy_yaml(content)
    if not isinstance(payload, dict):
        raise ValueError("policy document must be an object")
    return payload


def _finding(
    *,
    rule_id: str,
    severity: str,
    file: str,
    pattern: str,
    redacted: bool,
    line: int | None = None,
    size_bytes: int | None = None,
    allowed: bool | None = None,
    matched_policy_id: str | None = None,
    policy_source: str | None = None,
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
    if allowed is not None:
        finding["allowed"] = allowed
    if matched_policy_id is not None:
        finding["matched_policy_id"] = matched_policy_id
    if policy_source is not None:
        finding["policy_source"] = policy_source
    return finding


def _policy_issue(pattern: str, source: str, policy_id: str) -> dict:
    return _finding(
        rule_id=POLICY_RULE_IDS[pattern],
        severity=STATUS_BLOCK,
        file="<policy>",
        pattern=pattern,
        redacted=True,
        policy_source=source,
        matched_policy_id=policy_id,
    )


def _is_secret_fixture_path(path_pattern: str) -> bool:
    normalized = path_pattern.replace("\\", "/").strip().lstrip("/")
    return any(normalized.startswith(prefix) for prefix in SECRET_ALLOW_FIXTURE_PREFIXES)


def _load_policy_config(
    root: Path,
    config_path: str | Path | None = None,
    local_config_path: str | Path | None = None,
    load_local_config: bool = True,
) -> PolicyConfig:
    sources: list[tuple[str, Path, bool]] = []
    default_config_path = root / "repo-health-doctor.yml"
    if config_path is None:
        sources.append(("repo", default_config_path, False))
    else:
        sources.append(("repo", Path(config_path), True))
    if load_local_config:
        source_path = root / ".repo-health-doctor.local.yml" if local_config_path is None else Path(local_config_path)
        sources.append(("local", source_path, local_config_path is not None))

    ignore_paths: list[str] = []
    allow_findings: list[AllowFindingPolicy] = []
    issues: list[dict] = []
    loaded_sources: list[str] = []
    ignore_count = 0
    allow_count = 0

    for source, path, required in sources:
        if not path.is_absolute():
            path = root / path
        if not path.exists():
            if required:
                issues.append(_policy_issue("invalid_config", source, f"{source}:config"))
                loaded_sources.append(source)
            continue
        loaded_sources.append(source)
        try:
            payload = _load_policy_document(path)
        except (OSError, ValueError, json.JSONDecodeError):
            issues.append(_policy_issue("invalid_config", source, f"{source}:config"))
            continue

        raw_ignore_paths = payload.get("ignore_paths", [])
        if not isinstance(raw_ignore_paths, list):
            issues.append(_policy_issue("invalid_ignore", source, f"{source}:ignore"))
        else:
            for index, item in enumerate(raw_ignore_paths, start=1):
                policy_id = f"{source}:ignore:{index}"
                if not isinstance(item, str) or not item.strip():
                    issues.append(_policy_issue("invalid_ignore", source, policy_id))
                    continue
                ignore_count += 1
                ignore_paths.append(item)

        raw_allow_findings = payload.get("allow_findings", [])
        if not isinstance(raw_allow_findings, list):
            issues.append(_policy_issue("invalid_allow", source, f"{source}:allow"))
            continue

        for index, item in enumerate(raw_allow_findings, start=1):
            policy_id = f"{source}:allow:{index}"
            allow_count += 1
            if not isinstance(item, dict):
                issues.append(_policy_issue("invalid_allow", source, policy_id))
                continue
            missing_required = [
                key
                for key in ("rule_id", "path", "reason", "owner", "expires")
                if not isinstance(item.get(key), str) or not item.get(key, "").strip()
            ]
            if missing_required:
                issues.append(_policy_issue("invalid_allow", source, policy_id))
                continue

            rule_id = item["rule_id"].strip()
            path_pattern = item["path"].strip()
            if rule_id not in KNOWN_FINDING_RULE_IDS:
                issues.append(_policy_issue("unknown_rule_id", source, policy_id))
                continue

            try:
                expires = date.fromisoformat(item["expires"].strip())
            except ValueError:
                issues.append(_policy_issue("invalid_allow", source, policy_id))
                continue
            if expires < date.today():
                issues.append(_policy_issue("expired_allow", source, policy_id))
                continue

            if rule_id in SECRET_RULE_ID_VALUES and not _is_secret_fixture_path(path_pattern):
                issues.append(_policy_issue("restricted_secret_allow", source, policy_id))
                continue

            allow_findings.append(
                AllowFindingPolicy(
                    policy_id=policy_id,
                    source=source,
                    rule_id=rule_id,
                    path_pattern=path_pattern,
                )
            )

    return PolicyConfig(
        ignore_paths=tuple(ignore_paths),
        allow_findings=tuple(allow_findings),
        issues=issues,
        sources=tuple(dict.fromkeys(loaded_sources)),
        ignore_path_count=ignore_count,
        allow_finding_count=allow_count,
    )


def _matches_path_pattern(relative_path: str, pattern: str) -> bool:
    normalized_path = relative_path.replace("\\", "/").strip().lstrip("/")
    normalized_pattern = pattern.replace("\\", "/").strip().lstrip("/")
    if not normalized_pattern:
        return False
    if any(char in normalized_pattern for char in "*?[]"):
        return fnmatch.fnmatch(normalized_path, normalized_pattern)
    if normalized_pattern.endswith("/"):
        return normalized_path.startswith(normalized_pattern)
    return normalized_path == normalized_pattern or normalized_path.startswith(f"{normalized_pattern}/")


def _apply_allow_findings(findings: list[dict], policy: PolicyConfig) -> list[dict]:
    allowed_findings: list[dict] = []
    for finding in findings:
        matched_allow = None
        for allow in policy.allow_findings:
            if allow.rule_id != finding["rule_id"]:
                continue
            if _matches_path_pattern(finding["file"], allow.path_pattern):
                matched_allow = allow
                break
        normalized = dict(finding)
        if matched_allow is None:
            normalized["allowed"] = False
        else:
            normalized["allowed"] = True
            normalized["matched_policy_id"] = matched_allow.policy_id
            normalized["policy_source"] = matched_allow.source
        allowed_findings.append(normalized)
    return allowed_findings


def _has_unallowed_findings(findings: list[dict]) -> bool:
    return any(not finding.get("allowed", False) for finding in findings)


def _policy_check(policy: PolicyConfig) -> CheckResult:
    if policy.issues:
        summary = "Policy configuration has blocking issues."
    elif policy.sources:
        summary = "Policy configuration loaded."
    else:
        summary = "No policy configuration found."
    return CheckResult(
        name="policy",
        status=STATUS_BLOCK if policy.issues else STATUS_PASS,
        summary=summary,
        details={
            "findings": policy.issues,
            "policy_sources": list(policy.sources),
            "ignore_path_count": policy.ignore_path_count,
            "allow_finding_count": policy.allow_finding_count,
        },
    )


def _build_report(root: Path, checks: list[CheckResult]) -> dict:
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
        "version": TOOL_VERSION,
        "schema_version": REPORT_SCHEMA_VERSION,
        "repo_path": _safe_repo_path(root),
        "overall_status": overall_status,
        "summary": counts,
        "checks": [asdict(check) for check in checks],
    }


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


def _scan_large_files(root: Path, threshold_bytes: int, ignore_patterns: tuple[str, ...]) -> list[dict]:
    findings: list[dict] = []
    for path in _iter_files(root, ignore_patterns=ignore_patterns):
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
    ignore_patterns: tuple[str, ...],
) -> tuple[list[dict], int, str]:
    findings: list[dict] = []
    scanned_files = 0
    scope = "tracked" if tracked_files is not None else "all"

    for path in _iter_candidate_files(
        root,
        tracked_files=tracked_files,
        include_ignored=True,
        ignore_patterns=ignore_patterns,
    ):
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


def _scan_tracked_artifacts(
    root: Path,
    tracked_files: tuple[Path, ...] | None,
    ignore_patterns: tuple[str, ...],
) -> tuple[list[dict], str]:
    if tracked_files is None:
        return [], "unavailable"

    findings: list[dict] = []
    for path in sorted(tracked_files, key=lambda item: item.as_posix()):
        relative_path = path.relative_to(root)
        if _is_ignored_path(relative_path, ignore_patterns):
            continue
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
    config_path: str | Path | None = None,
    local_config_path: str | Path | None = None,
    load_local_config: bool = True,
) -> dict:
    root = Path(repo_path).resolve()
    threshold_bytes = large_file_threshold_mb * 1024 * 1024
    policy = _load_policy_config(
        root,
        config_path=config_path,
        local_config_path=local_config_path,
        load_local_config=load_local_config,
    )
    policy_ignore_paths = policy.ignore_paths
    combined_secrets_ignores = DEFAULT_SECRETS_IGNORES + tuple(secrets_ignores) + policy_ignore_paths
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
    secret_findings = _apply_allow_findings(secret_findings, policy)
    checks.append(
        CheckResult(
            name="secrets_scan",
            status=STATUS_BLOCK if _has_unallowed_findings(secret_findings) else STATUS_PASS,
            summary=(
                "Potential secrets detected."
                if _has_unallowed_findings(secret_findings)
                else "No obvious unallowed secrets detected."
            ),
            details={
                "findings": secret_findings,
                "scanned_files": scanned_files,
                "ignored_path_count": len(combined_secrets_ignores),
            },
        )
    )

    large_files = _apply_allow_findings(_scan_large_files(root, threshold_bytes, policy_ignore_paths), policy)
    checks.append(
        CheckResult(
            name="large_files",
            status=STATUS_WARN if _has_unallowed_findings(large_files) else STATUS_PASS,
            summary="Large files detected." if _has_unallowed_findings(large_files) else "No unallowed large files detected.",
            details={
                "threshold_mb": large_file_threshold_mb,
                "threshold_bytes": threshold_bytes,
                "findings": large_files,
            },
        )
    )

    if public_safety:
        tracked_files = _list_tracked_files(root)
        public_text_findings, scanned_files, scope = _scan_public_text_safety(
            root,
            tracked_files,
            policy_ignore_paths,
        )
        public_text_findings = _apply_allow_findings(public_text_findings, policy)
        checks.append(
            CheckResult(
                name="public_text_safety",
                status=STATUS_BLOCK if _has_unallowed_findings(public_text_findings) else STATUS_PASS,
                summary=(
                    "Public-facing text should be reviewed before release."
                    if _has_unallowed_findings(public_text_findings)
                    else "No obvious public-facing text issues detected."
                ),
                details={
                    "findings": public_text_findings,
                    "scanned_files": scanned_files,
                    "scan_scope": scope,
                },
            )
        )

        tracked_artifacts, tracked_scope = _scan_tracked_artifacts(root, tracked_files, policy_ignore_paths)
        tracked_artifacts = _apply_allow_findings(tracked_artifacts, policy)
        tracked_artifact_status = STATUS_BLOCK if _has_unallowed_findings(tracked_artifacts) else STATUS_PASS
        tracked_artifact_summary = (
            "Tracked generated or environment files should be reviewed before release."
            if _has_unallowed_findings(tracked_artifacts)
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

    if policy.sources or policy.issues:
        checks.append(_policy_check(policy))

    return _build_report(root, checks)


def validate_policy(
    repo_path: str | Path,
    config_path: str | Path | None = None,
    local_config_path: str | Path | None = None,
    load_local_config: bool = True,
) -> dict:
    root = Path(repo_path).resolve()
    policy = _load_policy_config(
        root,
        config_path=config_path,
        local_config_path=local_config_path,
        load_local_config=load_local_config,
    )
    return _build_report(root, [_policy_check(policy)])


def format_text(report: dict) -> str:
    lines = [
        f"Repo Health Doctor: {report['overall_status'].upper()}",
        f"Target: {report['repo_path']}",
        f"Schema: {report['schema_version']}",
        (
            "Summary: "
            f"{report['summary']['pass']} pass, "
            f"{report['summary']['warn']} warn, "
            f"{report['summary']['block']} block"
        ),
        "Status: PASS ok, WARN review, BLOCK release blocker",
        "",
        "Checks:",
    ]

    for check in report["checks"]:
        lines.append(f"- [{check['status'].upper()}] {check['name']}: {check['summary']}")
        details = check["details"]
        if details.get("found"):
            lines.append(f"    found: {', '.join(details['found'])}")
        if check["name"] == "secrets_scan":
            lines.append(f"    scanned_files: {details['scanned_files']}")
            for finding in details["findings"][:5]:
                prefix = "allowed finding" if finding.get("allowed") else "finding"
                lines.append(
                    f"    {prefix}: file={finding['file']} "
                    f"rule={finding['rule_id']} category={finding['pattern']}"
                )
        if check["name"] == "large_files":
            lines.append(f"    threshold_bytes: {details['threshold_bytes']}")
            for finding in details["findings"][:5]:
                prefix = "allowed finding" if finding.get("allowed") else "finding"
                lines.append(
                    f"    {prefix}: file={finding['file']} "
                    f"rule={finding['rule_id']} size_bytes={finding['size_bytes']}"
                )
        if check["name"] == "public_text_safety":
            lines.append(f"    scanned_files: {details['scanned_files']}")
            lines.append(f"    scan_scope: {details['scan_scope']}")
            for finding in details["findings"][:5]:
                prefix = "allowed finding" if finding.get("allowed") else "finding"
                lines.append(
                    f"    {prefix}: file={finding['file']} "
                    f"rule={finding['rule_id']} category={finding['pattern']} line={finding['line']}"
                )
        if check["name"] == "tracked_artifacts":
            lines.append(f"    scan_scope: {details['scan_scope']}")
            for finding in details["findings"][:5]:
                prefix = "allowed finding" if finding.get("allowed") else "finding"
                lines.append(
                    f"    {prefix}: file={finding['file']} "
                    f"rule={finding['rule_id']} category={finding['pattern']}"
                )
        if check["name"] == "policy":
            policy_sources = ", ".join(details["policy_sources"]) if details["policy_sources"] else "none"
            lines.append(f"    policy_sources: {policy_sources}")
            lines.append(f"    ignore_path_count: {details['ignore_path_count']}")
            lines.append(f"    allow_finding_count: {details['allow_finding_count']}")
            for finding in details["findings"][:5]:
                lines.append(
                    f"    policy issue: policy_id={finding['matched_policy_id']} "
                    f"rule={finding['rule_id']} category={finding['pattern']}"
                )
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def format_json(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"


def determine_exit_code(report: dict, strict: bool = False, fail_on: str = STATUS_BLOCK) -> int:
    if fail_on not in {STATUS_BLOCK, STATUS_WARN}:
        raise ValueError("fail_on must be 'block' or 'warn'")
    if report["summary"]["block"] > 0:
        return 1
    if (strict or fail_on == STATUS_WARN) and report["summary"]["warn"] > 0:
        return 1
    return 0
