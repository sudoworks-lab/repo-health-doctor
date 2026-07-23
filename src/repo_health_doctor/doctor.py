from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import date
import fnmatch
from collections import Counter
from pathlib import Path
import json
import re
import subprocess
from typing import Iterable


DEFAULT_LARGE_FILE_THRESHOLD_MB = 10
LARGE_FILE_THRESHOLD_BYTES = DEFAULT_LARGE_FILE_THRESHOLD_MB * 1024 * 1024
TEXT_FILE_SCAN_LIMIT_BYTES = 1 * 1024 * 1024
MAX_SCANNED_FILES = 200
POLICY_ALLOW_EXPIRING_SOON_DAYS = 30
REPORT_SCHEMA_VERSION = "1.1"
TOOL_VERSION = "0.1.0"
REPORT_KIND_DIFF = "report_diff"
REPORT_KIND_RELEASE_CHECK = "release_check"

README_NAMES = ("README", "README.md", "README.rst", "README.txt")
LICENSE_NAMES = ("LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING")
GITIGNORE_NAMES = (".gitignore", ".git/info/exclude")
TEST_DIR_NAMES = ("tests", "test")
DOCS_DIR_NAMES = ("docs", "doc")
SCRIPT_DIR_NAMES = ("scripts", "script", "bin")
WORKFLOW_FILE_SUFFIXES = (".yml", ".yaml")
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
    "build",
    "dist",
    "coverage",
    "generated",
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
POLICY_ALLOW_STATUS_ACTIVE = "active"
POLICY_ALLOW_STATUS_EXPIRING_SOON = "expiring-soon"
POLICY_ALLOW_STATUS_EXPIRED = "expired"
POLICY_ALLOW_STATUS_VALUES = (
    POLICY_ALLOW_STATUS_ACTIVE,
    POLICY_ALLOW_STATUS_EXPIRING_SOON,
    POLICY_ALLOW_STATUS_EXPIRED,
)
RUNTIME_STATUS_VALUES = (STATUS_PASS, STATUS_WARN, STATUS_BLOCK)
RUNTIME_FINDING_SEVERITY_VALUES = (STATUS_WARN, STATUS_BLOCK)
RULE_ID_LARGE_FILE = "rhd.repository.large_file"
RULE_ID_MISSING_README = "rhd.repository.missing_readme"
RULE_ID_MISSING_LICENSE = "rhd.repository.missing_license"
RULE_ID_MISSING_CI = "rhd.repository.missing_ci"
RULE_ID_MISSING_TESTS = "rhd.repository.missing_tests"
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
    "unknown_top_level_key": "rhd.policy.unknown_top_level_key",
    "restricted_secret_allow": "rhd.policy.restricted_secret_allow",
}
RULE_REGISTRY = {
    RULE_ID_MISSING_README: {"severity": STATUS_WARN, "family": "repository"},
    RULE_ID_MISSING_LICENSE: {"severity": STATUS_WARN, "family": "repository"},
    RULE_ID_MISSING_CI: {"severity": STATUS_WARN, "family": "repository"},
    RULE_ID_MISSING_TESTS: {"severity": STATUS_WARN, "family": "repository"},
    RULE_ID_LARGE_FILE: {"severity": STATUS_WARN, "family": "repository"},
    **{rule_id: {"severity": STATUS_BLOCK, "family": "secret"} for rule_id in SECRET_RULE_IDS.values()},
    **{rule_id: {"severity": STATUS_BLOCK, "family": "public_text"} for rule_id in PUBLIC_TEXT_RULE_IDS.values()},
    **{
        rule_id: {"severity": STATUS_BLOCK, "family": "tracked_artifact"}
        for rule_id in TRACKED_ARTIFACT_RULE_IDS.values()
    },
    **{rule_id: {"severity": STATUS_BLOCK, "family": "policy"} for rule_id in POLICY_RULE_IDS.values()},
}
KNOWN_FINDING_RULE_IDS = frozenset(RULE_REGISTRY)
SECRET_RULE_ID_VALUES = frozenset(
    rule_id for rule_id, metadata in RULE_REGISTRY.items() if metadata["family"] == "secret"
)
DOCUMENTED_RESERVED_RULE_IDS = frozenset()
SECRET_ALLOW_FIXTURE_PREFIXES = ("tests/fixtures/", "test/fixtures/")
POLICY_TOP_LEVEL_KEYS = frozenset({"ignore_paths", "allow_findings"})


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
    expires: date


@dataclass(frozen=True)
class PolicyAllowInventoryEntry:
    policy_source: str
    policy_id: str
    rule_id: str
    path_scope: str
    expires: str
    status: str
    redacted: bool = True


@dataclass
class PolicyConfig:
    ignore_paths: tuple[str, ...]
    allow_findings: tuple[AllowFindingPolicy, ...]
    allow_inventory: tuple[PolicyAllowInventoryEntry, ...]
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


def _list_workflow_files(root: Path) -> list[str]:
    workflow_dir = root / ".github" / "workflows"
    if not workflow_dir.is_dir():
        return []

    found: list[str] = []
    for path in sorted(workflow_dir.iterdir(), key=lambda item: item.name):
        if path.is_file() and path.suffix.lower() in WORKFLOW_FILE_SUFFIXES:
            found.append(path.relative_to(root).as_posix())
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


def _classify_policy_path_scope(path_pattern: str) -> str:
    normalized = path_pattern.replace("\\", "/").strip().lstrip("/")
    if any(char in normalized for char in "*?[]"):
        return "wildcard_pattern"
    if normalized.endswith("/"):
        return "directory_prefix"
    return "exact_path"


def _policy_allow_status(expires: date, today: date | None = None) -> str:
    current_day = date.today() if today is None else today
    if expires < current_day:
        return POLICY_ALLOW_STATUS_EXPIRED
    if expires <= current_day.fromordinal(current_day.toordinal() + POLICY_ALLOW_EXPIRING_SOON_DAYS):
        return POLICY_ALLOW_STATUS_EXPIRING_SOON
    return POLICY_ALLOW_STATUS_ACTIVE


def _policy_allow_inventory_entry(
    *,
    source: str,
    policy_id: str,
    rule_id: str,
    path_pattern: str,
    expires: date,
) -> PolicyAllowInventoryEntry:
    return PolicyAllowInventoryEntry(
        policy_source=source,
        policy_id=policy_id,
        rule_id=rule_id,
        path_scope=_classify_policy_path_scope(path_pattern),
        expires=expires.isoformat(),
        status=_policy_allow_status(expires),
    )


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
    allow_inventory: list[PolicyAllowInventoryEntry] = []
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

        unknown_top_level_keys = [key for key in payload if key not in POLICY_TOP_LEVEL_KEYS]
        for index, _ in enumerate(unknown_top_level_keys, start=1):
            issues.append(_policy_issue("unknown_top_level_key", source, f"{source}:top-level:{index}"))

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
            inventory_entry = _policy_allow_inventory_entry(
                source=source,
                policy_id=policy_id,
                rule_id=rule_id,
                path_pattern=path_pattern,
                expires=expires,
            )
            allow_inventory.append(inventory_entry)
            if inventory_entry.status == POLICY_ALLOW_STATUS_EXPIRED:
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
                    expires=expires,
                )
            )

    return PolicyConfig(
        ignore_paths=tuple(ignore_paths),
        allow_findings=tuple(allow_findings),
        allow_inventory=tuple(allow_inventory),
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


def _policy_allow_inventory_check(policy: PolicyConfig) -> CheckResult:
    return _policy_allow_inventory_check_with_filter(policy)


def _policy_allow_inventory_check_with_filter(
    policy: PolicyConfig,
    *,
    status_filter: str | None = None,
    fail_on: str | None = None,
) -> CheckResult:
    active_count = sum(1 for entry in policy.allow_inventory if entry.status == POLICY_ALLOW_STATUS_ACTIVE)
    expiring_soon_count = sum(
        1 for entry in policy.allow_inventory if entry.status == POLICY_ALLOW_STATUS_EXPIRING_SOON
    )
    expired_count = sum(1 for entry in policy.allow_inventory if entry.status == POLICY_ALLOW_STATUS_EXPIRED)
    allows = [
        asdict(entry)
        for entry in policy.allow_inventory
        if status_filter is None or entry.status == status_filter
    ]

    if expired_count:
        status = STATUS_BLOCK
        summary = "Expired allow entries require review."
    elif expiring_soon_count:
        status = STATUS_WARN
        summary = "Some allow entries are expiring soon."
    elif policy.allow_inventory and status_filter is not None and not allows:
        status = STATUS_PASS
        summary = "No allow entries matched filter."
    elif allows:
        status = STATUS_PASS
        summary = "Allow inventory loaded."
    else:
        status = STATUS_PASS
        summary = "No allow entries found."

    details = {
        "policy_sources": list(policy.sources),
        "allow_finding_count": policy.allow_finding_count,
        "active_count": active_count,
        "expiring_soon_count": expiring_soon_count,
        "expired_count": expired_count,
        "displayed_allow_count": len(allows),
        "allows": allows,
    }
    if status_filter is not None:
        details["filter"] = status_filter
    if fail_on is not None:
        details["fail_on"] = fail_on

    return CheckResult(
        name="policy_allow_inventory",
        status=status,
        summary=summary,
        details=details,
    )


def _repository_presence_check(
    *,
    name: str,
    found: list[str],
    missing_rule_id: str,
    missing_pattern: str,
    pass_summary: str,
    warn_summary: str,
) -> CheckResult:
    findings: list[dict] = []
    if not found:
        findings.append(
            _finding(
                rule_id=missing_rule_id,
                severity=STATUS_WARN,
                file=".",
                pattern=missing_pattern,
                redacted=False,
            )
        )
    return CheckResult(
        name=name,
        status=STATUS_PASS if found else STATUS_WARN,
        summary=pass_summary if found else warn_summary,
        details={
            "found": found,
            "findings": findings,
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


def _validate_loaded_report(payload: object) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("report payload must be a JSON object")
    if payload.get("tool") != "repo-health-doctor":
        raise ValueError("report payload must be produced by repo-health-doctor")
    if payload.get("report_kind") is not None:
        raise ValueError("diff-reports expects scan, validate-policy, or list-allows JSON reports")
    if payload.get("schema_version") != REPORT_SCHEMA_VERSION:
        raise ValueError("report schema_version does not match the current CLI")
    if payload.get("overall_status") not in RUNTIME_STATUS_VALUES:
        raise ValueError("report overall_status is invalid")
    summary = payload.get("summary")
    if not isinstance(summary, dict):
        raise ValueError("report summary must be an object")
    for key in RUNTIME_STATUS_VALUES:
        if not isinstance(summary.get(key), int):
            raise ValueError("report summary counts are invalid")
    checks = payload.get("checks")
    if not isinstance(checks, list):
        raise ValueError("report checks must be an array")
    for check in checks:
        if not isinstance(check, dict):
            raise ValueError("report checks must contain objects")
        if not isinstance(check.get("name"), str):
            raise ValueError("report check name is invalid")
        if check.get("status") not in RUNTIME_STATUS_VALUES:
            raise ValueError("report check status is invalid")
        details = check.get("details")
        if details is not None and not isinstance(details, dict):
            raise ValueError("report check details must be an object")
    return payload


def _load_report_file(report_path: str | Path) -> dict:
    path = Path(report_path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"report file not found: {path}") from exc
    except OSError as exc:
        raise ValueError(f"could not read report file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON report: {path}") from exc
    return _validate_loaded_report(payload)


def _finding_identity(finding: dict) -> tuple[str, str, str, bool, str, str]:
    return (
        str(finding.get("rule_id", "")),
        str(finding.get("file", "")),
        str(finding.get("pattern", "")),
        bool(finding.get("redacted", False)),
        str(finding.get("matched_policy_id", "")),
        str(finding.get("policy_source", "")),
    )


def _diff_finding_entry(finding: dict) -> dict:
    entry = {
        "rule_id": finding["rule_id"],
        "severity": finding["severity"],
        "file": finding["file"],
        "pattern": finding["pattern"],
        "redacted": bool(finding["redacted"]),
    }
    if "allowed" in finding:
        entry["allowed"] = bool(finding["allowed"])
    if "matched_policy_id" in finding:
        entry["matched_policy_id"] = finding["matched_policy_id"]
    if "policy_source" in finding:
        entry["policy_source"] = finding["policy_source"]
    return entry


def _diff_severity_change_entry(before_finding: dict, after_finding: dict) -> dict:
    entry = _diff_finding_entry(after_finding)
    entry["before_severity"] = before_finding["severity"]
    entry["after_severity"] = after_finding["severity"]
    entry.pop("severity", None)
    return entry


def _flatten_report_findings(report: dict) -> tuple[dict, Counter[tuple[str, str, str, bool, str, str]]]:
    finding_map: dict[tuple[str, str, str, bool, str, str], dict] = {}
    finding_counts: Counter[tuple[str, str, str, bool, str, str]] = Counter()
    for check in report["checks"]:
        details = check.get("details", {})
        findings = details.get("findings", [])
        if not isinstance(findings, list):
            continue
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            if not all(key in finding for key in ("rule_id", "severity", "file", "pattern", "redacted")):
                continue
            key = _finding_identity(finding)
            finding_counts[key] += 1
            finding_map.setdefault(key, _diff_finding_entry(finding))
    return finding_map, finding_counts


def _report_status_map(report: dict) -> dict[str, str]:
    return {
        check["name"]: check["status"]
        for check in report["checks"]
        if isinstance(check, dict) and isinstance(check.get("name"), str) and check.get("status") in RUNTIME_STATUS_VALUES
    }


def _diff_loaded_reports(before_report: dict, after_report: dict) -> dict:
    before_findings, before_counts = _flatten_report_findings(before_report)
    after_findings, after_counts = _flatten_report_findings(after_report)
    before_statuses = _report_status_map(before_report)
    after_statuses = _report_status_map(after_report)

    shared_keys = sorted(before_findings.keys() & after_findings.keys())
    added_keys = sorted(after_findings.keys() - before_findings.keys())
    resolved_keys = sorted(before_findings.keys() - after_findings.keys())

    severity_changes = [
        _diff_severity_change_entry(before_findings[key], after_findings[key])
        for key in shared_keys
        if before_findings[key]["severity"] != after_findings[key]["severity"]
    ]
    unchanged_findings_count = sum(
        min(before_counts[key], after_counts[key])
        for key in shared_keys
        if before_findings[key]["severity"] == after_findings[key]["severity"]
    )
    status_changes = [
        {
            "check": check_name,
            "before_status": before_statuses.get(check_name, "missing"),
            "after_status": after_statuses.get(check_name, "missing"),
        }
        for check_name in sorted(set(before_statuses) | set(after_statuses))
        if before_statuses.get(check_name, "missing") != after_statuses.get(check_name, "missing")
    ]

    return {
        "tool": "repo-health-doctor",
        "version": TOOL_VERSION,
        "schema_version": REPORT_SCHEMA_VERSION,
        "report_kind": REPORT_KIND_DIFF,
        "reports": {
            "before": {
                "repo_path": before_report["repo_path"],
                "overall_status": before_report["overall_status"],
                "summary": before_report["summary"],
            },
            "after": {
                "repo_path": after_report["repo_path"],
                "overall_status": after_report["overall_status"],
                "summary": after_report["summary"],
            },
        },
        "overall_status": {
            "before": before_report["overall_status"],
            "after": after_report["overall_status"],
            "changed": before_report["overall_status"] != after_report["overall_status"],
        },
        "summary": {
            "added_findings": len(added_keys),
            "resolved_findings": len(resolved_keys),
            "unchanged_findings": unchanged_findings_count,
            "severity_changes": len(severity_changes),
            "status_changes": len(status_changes),
        },
        "findings": {
            "added": [after_findings[key] for key in added_keys],
            "resolved": [before_findings[key] for key in resolved_keys],
            "severity_changes": severity_changes,
            "unchanged_count": unchanged_findings_count,
        },
        "status_changes": status_changes,
    }


def diff_reports(before_report_path: str | Path, after_report_path: str | Path) -> dict:
    before_report = _load_report_file(before_report_path)
    after_report = _load_report_file(after_report_path)
    return _diff_loaded_reports(before_report, after_report)


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
    tracked_relative_paths: tuple[str, ...] | None = None,
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
    combined_secrets_ignores = DEFAULT_SECRETS_IGNORES + tuple(secrets_ignores)
    checks: list[CheckResult] = []

    readmes = _has_any(root, README_NAMES)
    checks.append(
        _repository_presence_check(
            name="readme",
            found=readmes,
            missing_rule_id=RULE_ID_MISSING_README,
            missing_pattern="missing_readme",
            pass_summary="README found.",
            warn_summary="README is missing.",
        )
    )

    licenses = _has_any(root, LICENSE_NAMES)
    checks.append(
        _repository_presence_check(
            name="license",
            found=licenses,
            missing_rule_id=RULE_ID_MISSING_LICENSE,
            missing_pattern="missing_license",
            pass_summary="License file found.",
            warn_summary="License file is missing.",
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

    workflow_files = _list_workflow_files(root)
    checks.append(
        _repository_presence_check(
            name="ci",
            found=workflow_files,
            missing_rule_id=RULE_ID_MISSING_CI,
            missing_pattern="missing_ci",
            pass_summary="Workflow file found.",
            warn_summary="Workflow file is missing.",
        )
    )

    test_dirs = _has_dir(root, TEST_DIR_NAMES)
    checks.append(
        _repository_presence_check(
            name="tests",
            found=test_dirs,
            missing_rule_id=RULE_ID_MISSING_TESTS,
            missing_pattern="missing_tests",
            pass_summary="Test directory found.",
            warn_summary="Test directory is missing.",
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
        tracked_files = (
            tuple(root / relative for relative in tracked_relative_paths)
            if tracked_relative_paths is not None
            else _list_tracked_files(root)
        )
        public_text_findings, scanned_files, scope = _scan_public_text_safety(
            root,
            tracked_files,
            (),
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

        tracked_artifacts, tracked_scope = _scan_tracked_artifacts(root, tracked_files, ())
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


def list_policy_allows(
    repo_path: str | Path,
    config_path: str | Path | None = None,
    local_config_path: str | Path | None = None,
    load_local_config: bool = True,
    status_filter: str | None = None,
    fail_on: str | None = None,
) -> dict:
    root = Path(repo_path).resolve()
    policy = _load_policy_config(
        root,
        config_path=config_path,
        local_config_path=local_config_path,
        load_local_config=load_local_config,
    )
    checks = [
        _policy_check(policy),
        _policy_allow_inventory_check_with_filter(policy, status_filter=status_filter, fail_on=fail_on),
    ]
    return _build_report(root, checks)


def _report_check(report: dict, name: str) -> dict:
    for check in report["checks"]:
        if check["name"] == name:
            return check
    raise ValueError(f"missing expected check: {name}")


def _report_finding_count(report: dict) -> int:
    return sum(
        len(check.get("details", {}).get("findings", []))
        for check in report.get("checks", [])
        if isinstance(check, dict)
    )


def _report_check_names(report: dict, status: str) -> list[str]:
    return [
        check["name"]
        for check in report.get("checks", [])
        if isinstance(check, dict) and check.get("status") == status and isinstance(check.get("name"), str)
    ]


def _release_diff_status(diff_report: dict) -> tuple[str, str]:
    summary = diff_report["summary"]
    has_review_changes = (
        summary["added_findings"] > 0
        or summary["severity_changes"] > 0
        or summary["status_changes"] > 0
        or diff_report["overall_status"]["changed"]
    )
    if has_review_changes:
        return STATUS_WARN, "Current scan differs from baseline and should be reviewed."
    return STATUS_PASS, "Current scan matches baseline or only resolves prior findings."


def _recommended_release_action(overall_status: str, checks: list[CheckResult]) -> str:
    if overall_status == STATUS_BLOCK:
        if any(check.name == "policy_validation" and check.status == STATUS_BLOCK for check in checks):
            return "Do not release. Fix policy validation blockers and rerun release-check."
        return "Do not release. Resolve blocking findings and rerun release-check."
    if overall_status == STATUS_WARN:
        if any(check.name == "allow_inventory" and check.status == STATUS_WARN for check in checks):
            return "Review expiring allow entries before release."
        if any(check.name == "report_diff" and check.status == STATUS_WARN for check in checks):
            return "Review changes since the baseline report before release."
        return "Review warnings and rerun release-check before release."
    return "Release readiness checks passed. Proceed with maintainer release review."


def release_check(
    repo_path: str | Path,
    large_file_threshold_mb: int = DEFAULT_LARGE_FILE_THRESHOLD_MB,
    secrets_ignores: tuple[str, ...] = (),
    config_path: str | Path | None = None,
    local_config_path: str | Path | None = None,
    load_local_config: bool = True,
    baseline_report_path: str | Path | None = None,
) -> dict:
    root = Path(repo_path).resolve()
    scan_report = diagnose_repo(
        root,
        large_file_threshold_mb=large_file_threshold_mb,
        secrets_ignores=secrets_ignores,
        public_safety=True,
        config_path=config_path,
        local_config_path=local_config_path,
        load_local_config=load_local_config,
    )
    policy_report = validate_policy(
        root,
        config_path=config_path,
        local_config_path=local_config_path,
        load_local_config=load_local_config,
    )
    allows_report = list_policy_allows(
        root,
        config_path=config_path,
        local_config_path=local_config_path,
        load_local_config=load_local_config,
    )

    scan_warning_checks = _report_check_names(scan_report, STATUS_WARN)
    scan_blocking_checks = _report_check_names(scan_report, STATUS_BLOCK)
    policy_check = _report_check(policy_report, "policy")
    inventory_check = _report_check(allows_report, "policy_allow_inventory")

    checks = [
        CheckResult(
            name="repo_scan",
            status=scan_report["overall_status"],
            summary=(
                "Repository scan passed release checks."
                if scan_report["overall_status"] == STATUS_PASS
                else "Repository scan has release warnings."
                if scan_report["overall_status"] == STATUS_WARN
                else "Repository scan has release blockers."
            ),
            details={
                "report_overall_status": scan_report["overall_status"],
                "pass_count": scan_report["summary"]["pass"],
                "warn_count": scan_report["summary"]["warn"],
                "block_count": scan_report["summary"]["block"],
                "finding_count": _report_finding_count(scan_report),
                "warning_checks": scan_warning_checks,
                "blocking_checks": scan_blocking_checks,
            },
        ),
        CheckResult(
            name="policy_validation",
            status=policy_check["status"],
            summary=policy_check["summary"],
            details={
                "report_overall_status": policy_report["overall_status"],
                "policy_sources": policy_check["details"].get("policy_sources", []),
                "ignore_path_count": policy_check["details"].get("ignore_path_count", 0),
                "allow_finding_count": policy_check["details"].get("allow_finding_count", 0),
                "issue_count": len(policy_check["details"].get("findings", [])),
                "issue_rule_ids": sorted(
                    {
                        finding["rule_id"]
                        for finding in policy_check["details"].get("findings", [])
                        if isinstance(finding, dict) and isinstance(finding.get("rule_id"), str)
                    }
                ),
            },
        ),
        CheckResult(
            name="allow_inventory",
            status=inventory_check["status"],
            summary=inventory_check["summary"],
            details={
                "report_overall_status": inventory_check["status"],
                "policy_sources": inventory_check["details"].get("policy_sources", []),
                "allow_finding_count": inventory_check["details"].get("allow_finding_count", 0),
                "active_count": inventory_check["details"].get("active_count", 0),
                "expiring_soon_count": inventory_check["details"].get("expiring_soon_count", 0),
                "expired_count": inventory_check["details"].get("expired_count", 0),
                "displayed_allow_count": inventory_check["details"].get("displayed_allow_count", 0),
            },
        ),
    ]

    if baseline_report_path is None:
        checks.append(
            CheckResult(
                name="report_diff",
                status=STATUS_PASS,
                summary="Baseline report not provided; diff summary skipped.",
                details={"comparison_available": False},
            )
        )
    else:
        baseline_report = _load_report_file(baseline_report_path)
        diff_report = _diff_loaded_reports(baseline_report, scan_report)
        diff_status, diff_summary = _release_diff_status(diff_report)
        checks.append(
            CheckResult(
                name="report_diff",
                status=diff_status,
                summary=diff_summary,
                details={
                    "comparison_available": True,
                    "report_overall_status": diff_report["overall_status"]["after"],
                    "added_findings": diff_report["summary"]["added_findings"],
                    "resolved_findings": diff_report["summary"]["resolved_findings"],
                    "unchanged_findings": diff_report["summary"]["unchanged_findings"],
                    "severity_changes": diff_report["summary"]["severity_changes"],
                    "status_changes": diff_report["summary"]["status_changes"],
                },
            )
        )

    report = _build_report(root, checks)
    report["report_kind"] = REPORT_KIND_RELEASE_CHECK
    report["release_readiness"] = {
        "status": report["overall_status"],
        "summary": (
            "Release readiness checks passed."
            if report["overall_status"] == STATUS_PASS
            else "Release readiness requires review."
            if report["overall_status"] == STATUS_WARN
            else "Release readiness is blocked."
        ),
    }
    report["recommended_next_action"] = _recommended_release_action(report["overall_status"], checks)
    return report


def format_text(report: dict) -> str:
    if report.get("report_kind") == REPORT_KIND_DIFF:
        return _format_diff_text(report)
    if report.get("report_kind") == REPORT_KIND_RELEASE_CHECK:
        return _format_release_check_text(report)
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
        if check["name"] == "policy_allow_inventory":
            policy_sources = ", ".join(details["policy_sources"]) if details["policy_sources"] else "none"
            lines.append(f"    policy_sources: {policy_sources}")
            lines.append(f"    allow_finding_count: {details['allow_finding_count']}")
            lines.append(f"    active_count: {details['active_count']}")
            lines.append(f"    expiring_soon_count: {details['expiring_soon_count']}")
            lines.append(f"    expired_count: {details['expired_count']}")
            if "displayed_allow_count" in details:
                lines.append(f"    displayed_allow_count: {details['displayed_allow_count']}")
            if "filter" in details:
                lines.append(f"    filter: status={details['filter']}")
            if "fail_on" in details:
                lines.append(f"    fail_on: {details['fail_on']}")
            for allow in details["allows"][:10]:
                lines.append(
                    f"    allow: policy_source={allow['policy_source']} "
                    f"policy_id={allow['policy_id']} rule={allow['rule_id']} "
                    f"path_scope={allow['path_scope']} expires={allow['expires']} status={allow['status']}"
                )
        if check["name"] not in {
            "secrets_scan",
            "large_files",
            "public_text_safety",
            "tracked_artifacts",
            "policy",
            "policy_allow_inventory",
        }:
            for finding in details.get("findings", [])[:5]:
                prefix = "allowed finding" if finding.get("allowed") else "finding"
                lines.append(
                    f"    {prefix}: file={finding['file']} "
                    f"rule={finding['rule_id']} category={finding['pattern']}"
                )
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def format_json(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"


def _format_markdown_code(value: object) -> str:
    text = str(value).replace("`", "\\`")
    return f"`{text}`"


def _format_markdown_table_row(values: list[object]) -> str:
    cells = [str(value).replace("\n", " ").replace("|", "\\|") for value in values]
    return "| " + " | ".join(cells) + " |"


def _format_markdown_finding_notes(finding: dict) -> str:
    notes: list[str] = []
    if "line" in finding:
        notes.append(f"line={finding['line']}")
    if "size_bytes" in finding:
        notes.append(f"size_bytes={finding['size_bytes']}")
    if finding.get("allowed"):
        notes.append("allowed")
    if "matched_policy_id" in finding:
        notes.append(f"policy_id={finding['matched_policy_id']}")
    if "policy_source" in finding:
        notes.append(f"policy_source={finding['policy_source']}")
    if not notes:
        return "-"
    return ", ".join(notes)


def _format_diff_text_finding(finding: dict) -> str:
    notes: list[str] = [f"severity={finding['severity']}"]
    if "allowed" in finding:
        notes.append(f"allowed={'true' if finding['allowed'] else 'false'}")
    if "matched_policy_id" in finding:
        notes.append(f"policy_id={finding['matched_policy_id']}")
    if "policy_source" in finding:
        notes.append(f"policy_source={finding['policy_source']}")
    return (
        f"    finding: file={finding['file']} "
        f"rule={finding['rule_id']} category={finding['pattern']} "
        f"redacted={'true' if finding['redacted'] else 'false'} "
        f"{' '.join(notes)}"
    )


def _format_diff_text(report: dict) -> str:
    lines = [
        "Repo Health Doctor Report Diff",
        f"Schema: {report['schema_version']}",
        (
            "Overall Status: "
            f"{report['overall_status']['before'].upper()} -> {report['overall_status']['after'].upper()}"
        ),
        f"Before Target: {report['reports']['before']['repo_path']}",
        f"After Target: {report['reports']['after']['repo_path']}",
        (
            "Diff Summary: "
            f"{report['summary']['added_findings']} added, "
            f"{report['summary']['resolved_findings']} resolved, "
            f"{report['summary']['unchanged_findings']} unchanged, "
            f"{report['summary']['severity_changes']} severity changed, "
            f"{report['summary']['status_changes']} status changed"
        ),
        "",
        "Status Changes:",
    ]

    if report["status_changes"]:
        for change in report["status_changes"]:
            lines.append(
                f"- {change['check']}: {change['before_status'].upper()} -> {change['after_status'].upper()}"
            )
    else:
        lines.append("- none")

    lines.extend(["", "Added Findings:"])
    if report["findings"]["added"]:
        for finding in report["findings"]["added"]:
            lines.append(_format_diff_text_finding(finding))
    else:
        lines.append("- none")

    lines.extend(["", "Resolved Findings:"])
    if report["findings"]["resolved"]:
        for finding in report["findings"]["resolved"]:
            lines.append(_format_diff_text_finding(finding))
    else:
        lines.append("- none")

    lines.extend(["", "Severity Changes:"])
    if report["findings"]["severity_changes"]:
        for finding in report["findings"]["severity_changes"]:
            lines.append(
                f"    finding: file={finding['file']} "
                f"rule={finding['rule_id']} category={finding['pattern']} "
                f"redacted={'true' if finding['redacted'] else 'false'} "
                f"severity={finding['before_severity']}->{finding['after_severity']}"
            )
    else:
        lines.append("- none")

    lines.extend(["", f"Unchanged Findings Count: {report['findings']['unchanged_count']}"])
    return "\n".join(lines).rstrip() + "\n"


def _format_release_check_text(report: dict) -> str:
    lines = [
        f"Repo Health Doctor Release Check: {report['overall_status'].upper()}",
        f"Target: {report['repo_path']}",
        f"Schema: {report['schema_version']}",
        f"Release Readiness: {report['release_readiness']['status'].upper()}",
        f"Recommended Next Action: {report['recommended_next_action']}",
        (
            "Summary: "
            f"{report['summary']['pass']} pass, "
            f"{report['summary']['warn']} warn, "
            f"{report['summary']['block']} block"
        ),
        "",
        "Checks:",
    ]

    for check in report["checks"]:
        lines.append(f"- [{check['status'].upper()}] {check['name']}: {check['summary']}")
        details = check["details"]
        if "report_overall_status" in details:
            lines.append(f"    report_overall_status: {details['report_overall_status']}")
        if "pass_count" in details:
            lines.append(f"    pass_count: {details['pass_count']}")
        if "warn_count" in details:
            lines.append(f"    warn_count: {details['warn_count']}")
        if "block_count" in details:
            lines.append(f"    block_count: {details['block_count']}")
        if "finding_count" in details:
            lines.append(f"    finding_count: {details['finding_count']}")
        if "warning_checks" in details:
            lines.append(f"    warning_checks: {', '.join(details['warning_checks']) or 'none'}")
        if "blocking_checks" in details:
            lines.append(f"    blocking_checks: {', '.join(details['blocking_checks']) or 'none'}")
        if "policy_sources" in details:
            lines.append(f"    policy_sources: {', '.join(details['policy_sources']) or 'none'}")
        if "ignore_path_count" in details:
            lines.append(f"    ignore_path_count: {details['ignore_path_count']}")
        if "allow_finding_count" in details:
            lines.append(f"    allow_finding_count: {details['allow_finding_count']}")
        if "issue_count" in details:
            lines.append(f"    issue_count: {details['issue_count']}")
        if "issue_rule_ids" in details:
            lines.append(f"    issue_rule_ids: {', '.join(details['issue_rule_ids']) or 'none'}")
        if "active_count" in details:
            lines.append(f"    active_count: {details['active_count']}")
        if "expiring_soon_count" in details:
            lines.append(f"    expiring_soon_count: {details['expiring_soon_count']}")
        if "expired_count" in details:
            lines.append(f"    expired_count: {details['expired_count']}")
        if "displayed_allow_count" in details:
            lines.append(f"    displayed_allow_count: {details['displayed_allow_count']}")
        if "comparison_available" in details:
            lines.append(f"    comparison_available: {'true' if details['comparison_available'] else 'false'}")
        if "added_findings" in details:
            lines.append(f"    added_findings: {details['added_findings']}")
        if "resolved_findings" in details:
            lines.append(f"    resolved_findings: {details['resolved_findings']}")
        if "unchanged_findings" in details:
            lines.append(f"    unchanged_findings: {details['unchanged_findings']}")
        if "severity_changes" in details:
            lines.append(f"    severity_changes: {details['severity_changes']}")
        if "status_changes" in details:
            lines.append(f"    status_changes: {details['status_changes']}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def format_markdown(report: dict) -> str:
    if report.get("report_kind") == REPORT_KIND_DIFF:
        return _format_diff_markdown(report)
    if report.get("report_kind") == REPORT_KIND_RELEASE_CHECK:
        return _format_release_check_markdown(report)
    lines = [
        "# Repo Health Doctor Report",
        "",
        f"- Target Repo Path: {_format_markdown_code(report['repo_path'])}",
        f"- Overall Status: {_format_markdown_code(report['overall_status'].upper())}",
        f"- Schema Version: {_format_markdown_code(report['schema_version'])}",
        "",
        "## Summary Counts",
        "",
        "| PASS | WARN | BLOCK |",
        "| --- | --- | --- |",
        f"| {report['summary']['pass']} | {report['summary']['warn']} | {report['summary']['block']} |",
        "",
        "## Status Meanings",
        "",
        "- `PASS`: ok",
        "- `WARN`: review",
        "- `BLOCK`: release blocker",
        "",
        "## Checks",
        "",
        "| Status | Check | Summary |",
        "| --- | --- | --- |",
    ]

    for check in report["checks"]:
        lines.append(
            _format_markdown_table_row(
                [
                    _format_markdown_code(check["status"].upper()),
                    _format_markdown_code(check["name"]),
                    check["summary"],
                ]
            )
        )

    for check in report["checks"]:
        lines.extend(
            [
                "",
                f"### {_format_markdown_code(check['name'])}",
                "",
                f"- Status: {_format_markdown_code(check['status'].upper())}",
                f"- Summary: {check['summary']}",
            ]
        )
        details = check["details"]
        if details.get("found"):
            found = ", ".join(_format_markdown_code(value) for value in details["found"])
            lines.append(f"- Found: {found}")
        if "scanned_files" in details:
            lines.append(f"- Scanned Files: {_format_markdown_code(details['scanned_files'])}")
        if "scan_scope" in details:
            lines.append(f"- Scan Scope: {_format_markdown_code(details['scan_scope'])}")
        if "threshold_mb" in details:
            lines.append(f"- Threshold MB: {_format_markdown_code(details['threshold_mb'])}")
        if "threshold_bytes" in details:
            lines.append(f"- Threshold Bytes: {_format_markdown_code(details['threshold_bytes'])}")
        if "policy_sources" in details:
            policy_sources = ", ".join(_format_markdown_code(source) for source in details["policy_sources"])
            lines.append(f"- Policy Sources: {policy_sources or _format_markdown_code('none')}")
        if "ignore_path_count" in details:
            lines.append(f"- Ignore Path Count: {_format_markdown_code(details['ignore_path_count'])}")
        if "allow_finding_count" in details:
            lines.append(f"- Allow Finding Count: {_format_markdown_code(details['allow_finding_count'])}")
        if "active_count" in details:
            lines.append(f"- Active Count: {_format_markdown_code(details['active_count'])}")
        if "expiring_soon_count" in details:
            lines.append(f"- Expiring Soon Count: {_format_markdown_code(details['expiring_soon_count'])}")
        if "expired_count" in details:
            lines.append(f"- Expired Count: {_format_markdown_code(details['expired_count'])}")
        if "displayed_allow_count" in details:
            lines.append(f"- Displayed Allow Count: {_format_markdown_code(details['displayed_allow_count'])}")
        if "filter" in details:
            lines.append(f"- Filter: {_format_markdown_code(details['filter'])}")
        if "fail_on" in details:
            lines.append(f"- Fail On: {_format_markdown_code(details['fail_on'])}")

        findings = details.get("findings", [])
        if findings:
            lines.extend(
                [
                    "",
                    "| Rule ID | Severity | File | Pattern | Redacted | Notes |",
                    "| --- | --- | --- | --- | --- | --- |",
                ]
            )
            for finding in findings:
                lines.append(
                    _format_markdown_table_row(
                        [
                            _format_markdown_code(finding["rule_id"]),
                            _format_markdown_code(finding["severity"]),
                            _format_markdown_code(finding["file"]),
                            _format_markdown_code(finding["pattern"]),
                            _format_markdown_code(str(finding["redacted"]).lower()),
                            _format_markdown_finding_notes(finding),
                        ]
                    )
                )
        else:
            lines.append("- Findings: none")

        allows = details.get("allows", [])
        if allows:
            lines.extend(
                [
                    "",
                    "| Policy Source | Policy ID | Rule ID | Path Scope | Expires | Status | Redacted |",
                    "| --- | --- | --- | --- | --- | --- | --- |",
                ]
            )
            for allow in allows:
                lines.append(
                    _format_markdown_table_row(
                        [
                            _format_markdown_code(allow["policy_source"]),
                            _format_markdown_code(allow["policy_id"]),
                            _format_markdown_code(allow["rule_id"]),
                            _format_markdown_code(allow["path_scope"]),
                            _format_markdown_code(allow["expires"]),
                            _format_markdown_code(allow["status"]),
                            _format_markdown_code(str(allow["redacted"]).lower()),
                        ]
                    )
                )
        elif "allows" in details:
            lines.append("- Allows: none")

    return "\n".join(lines).rstrip() + "\n"


def _format_diff_markdown(report: dict) -> str:
    lines = [
        "# Repo Health Doctor Report Diff",
        "",
        f"- Before Target Repo Path: {_format_markdown_code(report['reports']['before']['repo_path'])}",
        f"- After Target Repo Path: {_format_markdown_code(report['reports']['after']['repo_path'])}",
        (
            "- Overall Status: "
            f"{_format_markdown_code(report['overall_status']['before'].upper())} -> "
            f"{_format_markdown_code(report['overall_status']['after'].upper())}"
        ),
        f"- Schema Version: {_format_markdown_code(report['schema_version'])}",
        "",
        "## Diff Summary",
        "",
        "| Added | Resolved | Unchanged | Severity Changes | Status Changes |",
        "| --- | --- | --- | --- | --- |",
        (
            f"| {report['summary']['added_findings']} | {report['summary']['resolved_findings']} | "
            f"{report['summary']['unchanged_findings']} | {report['summary']['severity_changes']} | "
            f"{report['summary']['status_changes']} |"
        ),
        "",
        "## Status Changes",
        "",
    ]

    if report["status_changes"]:
        lines.extend(
            [
                "| Check | Before | After |",
                "| --- | --- | --- |",
            ]
        )
        for change in report["status_changes"]:
            lines.append(
                _format_markdown_table_row(
                    [
                        _format_markdown_code(change["check"]),
                        _format_markdown_code(change["before_status"]),
                        _format_markdown_code(change["after_status"]),
                    ]
                )
            )
    else:
        lines.append("- none")

    for heading, findings in (
        ("Added Findings", report["findings"]["added"]),
        ("Resolved Findings", report["findings"]["resolved"]),
    ):
        lines.extend(["", f"## {heading}", ""])
        if findings:
            lines.extend(
                [
                    "| Rule ID | Severity | File | Pattern | Redacted | Notes |",
                    "| --- | --- | --- | --- | --- | --- |",
                ]
            )
            for finding in findings:
                lines.append(
                    _format_markdown_table_row(
                        [
                            _format_markdown_code(finding["rule_id"]),
                            _format_markdown_code(finding["severity"]),
                            _format_markdown_code(finding["file"]),
                            _format_markdown_code(finding["pattern"]),
                            _format_markdown_code(str(finding["redacted"]).lower()),
                            _format_markdown_finding_notes(finding),
                        ]
                    )
                )
        else:
            lines.append("- none")

    lines.extend(["", "## Severity Changes", ""])
    if report["findings"]["severity_changes"]:
        lines.extend(
            [
                "| Rule ID | File | Pattern | Redacted | Before Severity | After Severity | Notes |",
                "| --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for finding in report["findings"]["severity_changes"]:
            lines.append(
                _format_markdown_table_row(
                    [
                        _format_markdown_code(finding["rule_id"]),
                        _format_markdown_code(finding["file"]),
                        _format_markdown_code(finding["pattern"]),
                        _format_markdown_code(str(finding["redacted"]).lower()),
                        _format_markdown_code(finding["before_severity"]),
                        _format_markdown_code(finding["after_severity"]),
                        _format_markdown_finding_notes(finding),
                    ]
                )
            )
    else:
        lines.append("- none")

    lines.extend(
        [
            "",
            "## Unchanged Findings",
            "",
            f"- Count: {_format_markdown_code(report['findings']['unchanged_count'])}",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def _format_release_check_markdown(report: dict) -> str:
    lines = [
        "# Repo Health Doctor Release Check",
        "",
        f"- Target Repo Path: {_format_markdown_code(report['repo_path'])}",
        f"- Overall Release Readiness: {_format_markdown_code(report['release_readiness']['status'].upper())}",
        f"- Readiness Summary: {report['release_readiness']['summary']}",
        f"- Schema Version: {_format_markdown_code(report['schema_version'])}",
        f"- Recommended Next Action: {report['recommended_next_action']}",
        "",
        "## Summary Counts",
        "",
        "| PASS | WARN | BLOCK |",
        "| --- | --- | --- |",
        f"| {report['summary']['pass']} | {report['summary']['warn']} | {report['summary']['block']} |",
        "",
        "## Checks",
        "",
        "| Status | Check | Summary |",
        "| --- | --- | --- |",
    ]

    for check in report["checks"]:
        lines.append(
            _format_markdown_table_row(
                [
                    _format_markdown_code(check["status"].upper()),
                    _format_markdown_code(check["name"]),
                    check["summary"],
                ]
            )
        )

    for check in report["checks"]:
        details = check["details"]
        lines.extend(
            [
                "",
                f"### {_format_markdown_code(check['name'])}",
                "",
                f"- Status: {_format_markdown_code(check['status'].upper())}",
                f"- Summary: {check['summary']}",
            ]
        )
        if "report_overall_status" in details:
            lines.append(f"- Report Overall Status: {_format_markdown_code(details['report_overall_status'].upper())}")
        if "pass_count" in details:
            lines.append(f"- Pass Count: {_format_markdown_code(details['pass_count'])}")
        if "warn_count" in details:
            lines.append(f"- Warn Count: {_format_markdown_code(details['warn_count'])}")
        if "block_count" in details:
            lines.append(f"- Block Count: {_format_markdown_code(details['block_count'])}")
        if "finding_count" in details:
            lines.append(f"- Finding Count: {_format_markdown_code(details['finding_count'])}")
        if "warning_checks" in details:
            warning_checks = ", ".join(_format_markdown_code(value) for value in details["warning_checks"])
            lines.append(f"- Warning Checks: {warning_checks or _format_markdown_code('none')}")
        if "blocking_checks" in details:
            blocking_checks = ", ".join(_format_markdown_code(value) for value in details["blocking_checks"])
            lines.append(f"- Blocking Checks: {blocking_checks or _format_markdown_code('none')}")
        if "policy_sources" in details:
            policy_sources = ", ".join(_format_markdown_code(value) for value in details["policy_sources"])
            lines.append(f"- Policy Sources: {policy_sources or _format_markdown_code('none')}")
        if "ignore_path_count" in details:
            lines.append(f"- Ignore Path Count: {_format_markdown_code(details['ignore_path_count'])}")
        if "allow_finding_count" in details:
            lines.append(f"- Allow Finding Count: {_format_markdown_code(details['allow_finding_count'])}")
        if "issue_count" in details:
            lines.append(f"- Issue Count: {_format_markdown_code(details['issue_count'])}")
        if "issue_rule_ids" in details:
            issue_rule_ids = ", ".join(_format_markdown_code(value) for value in details["issue_rule_ids"])
            lines.append(f"- Issue Rule IDs: {issue_rule_ids or _format_markdown_code('none')}")
        if "active_count" in details:
            lines.append(f"- Active Count: {_format_markdown_code(details['active_count'])}")
        if "expiring_soon_count" in details:
            lines.append(f"- Expiring Soon Count: {_format_markdown_code(details['expiring_soon_count'])}")
        if "expired_count" in details:
            lines.append(f"- Expired Count: {_format_markdown_code(details['expired_count'])}")
        if "displayed_allow_count" in details:
            lines.append(f"- Displayed Allow Count: {_format_markdown_code(details['displayed_allow_count'])}")
        if "comparison_available" in details:
            lines.append(
                f"- Comparison Available: {_format_markdown_code(str(details['comparison_available']).lower())}"
            )
        if "added_findings" in details:
            lines.append(f"- Added Findings: {_format_markdown_code(details['added_findings'])}")
        if "resolved_findings" in details:
            lines.append(f"- Resolved Findings: {_format_markdown_code(details['resolved_findings'])}")
        if "unchanged_findings" in details:
            lines.append(f"- Unchanged Findings: {_format_markdown_code(details['unchanged_findings'])}")
        if "severity_changes" in details:
            lines.append(f"- Severity Changes: {_format_markdown_code(details['severity_changes'])}")
        if "status_changes" in details:
            lines.append(f"- Status Changes: {_format_markdown_code(details['status_changes'])}")

    return "\n".join(lines).rstrip() + "\n"


def determine_exit_code(report: dict, strict: bool = False, fail_on: str = STATUS_BLOCK) -> int:
    if report.get("report_kind") == REPORT_KIND_DIFF:
        return 0
    if fail_on not in {STATUS_BLOCK, STATUS_WARN, POLICY_ALLOW_STATUS_EXPIRED, POLICY_ALLOW_STATUS_EXPIRING_SOON}:
        raise ValueError("fail_on must be 'block', 'warn', 'expired', or 'expiring-soon'")
    if report["summary"]["block"] > 0:
        return 1
    if (strict or fail_on == STATUS_WARN) and report["summary"]["warn"] > 0:
        return 1
    if fail_on in {POLICY_ALLOW_STATUS_EXPIRED, POLICY_ALLOW_STATUS_EXPIRING_SOON}:
        inventory_details = next(
            (check["details"] for check in report.get("checks", []) if check.get("name") == "policy_allow_inventory"),
            {},
        )
        expired_count = inventory_details.get("expired_count", 0)
        expiring_soon_count = inventory_details.get("expiring_soon_count", 0)
        if fail_on == POLICY_ALLOW_STATUS_EXPIRED:
            return 1 if expired_count > 0 else 0
        return 1 if expired_count > 0 or expiring_soon_count > 0 else 0
    return 0
