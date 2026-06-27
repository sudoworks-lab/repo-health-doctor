from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
import tarfile
from typing import Any, Iterable
import zipfile

from .workspace import MaterializedWorkspace


MAX_TEXT_BYTES = 262144
ARCHIVE_SUFFIXES = (".whl", ".zip", ".tgz", ".tar.gz")
TEXT_FILE_SUFFIXES = (
    ".py",
    ".js",
    ".json",
    ".toml",
    ".cfg",
    ".ini",
    ".txt",
)
FETCH_ARTIFACT_FILENAMES = {
    "package.json",
    "setup.py",
    "setup.cfg",
    "pyproject.toml",
    "METADATA",
    "PKG-INFO",
    "entry_points.txt",
}
LIFECYCLE_SCRIPT_NAMES = ("preinstall", "install", "postinstall", "prepare")
METADATA_FILENAMES = {"METADATA", "PKG-INFO", "entry_points.txt"}

CLASS_INSTALL_TIME_EXECUTION_RISK = "install_time_execution_risk"
CLASS_DEPENDENCY_SOURCE_RISK = "dependency_source_risk"
CLASS_SUSPICIOUS_CODE_PATTERN = "suspicious_code_pattern"
CLASS_ORDINARY_LIBRARY_CAPABILITY = "ordinary_library_capability"
CLASS_METADATA_OR_STRING_REFERENCE = "metadata_or_string_reference"
CLASS_BENIGN_EXPECTED_REFERENCE = "benign_expected_reference"
CLASS_UNKNOWN_REQUIRES_REVIEW = "unknown_requires_review"

DYNAMIC_EXEC_PATTERN = re.compile(
    r"(?i)((?:child_process|require\(['\"]child_process['\"]\))\.(?:exec|spawn)\b|subprocess\.(?:Popen|run|call|check_call|check_output)\b|"
    r"os\.system\b|(?<![\w.])eval\s*\(|(?<![\w.])exec\s*\(|(?:sh|bash)\s+-c\b)"
)
OBFUSCATION_PATTERN = re.compile(r"(?i)(base64(?:\.b64decode|\s*\()|Buffer\.from\([^)]*base64)")
NETWORK_REFERENCE_PATTERN = re.compile(
    r"(?i)(https?://|requests\.|urllib\.|http\.client|socket\.|axios|fetch\s*\(|XMLHttpRequest|getaddrinfo)"
)
ENV_REFERENCE_PATTERN = re.compile(r"(?i)(os\.environ|process\.env|os\.getenv|process\.env\[[^\]]+\])")
SECRET_OR_PATH_REFERENCE_PATTERN = re.compile(
    r"(?i)(\.aws/|\.ssh/|\.env\b|\.netrc\b|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|NPM_TOKEN|"
    r"REQUESTS_CA_BUNDLE|CURL_CA_BUNDLE|SSL_CERT_FILE|SSL_CERT_DIR|certifi|cacert\.pem|\.pem\b|\.crt\b)"
)
IP_LITERAL_PATTERN = re.compile(r"(?<![\w.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\w.])")
BUILD_BACKEND_PATTERN = re.compile(r"(?im)^\s*build-backend\s*=")
COMMENT_ONLY_PATTERN = re.compile(r"^\s*(#|//|/\*|\*)")


@dataclass(frozen=True)
class RescanFinding:
    category: str
    classification: str
    severity: str
    path: str
    summary: str
    artifact_kind: str

    def as_dict(self) -> dict[str, str]:
        return {
            "category": self.category,
            "classification": self.classification,
            "severity": self.severity,
            "path": self.path,
            "summary": self.summary,
            "artifact_kind": self.artifact_kind,
        }


class FindingCollector:
    def __init__(self) -> None:
        self._findings: list[RescanFinding] = []
        self._seen: set[tuple[str, str, str, str, str, str]] = set()

    def add(
        self,
        *,
        category: str,
        classification: str,
        severity: str,
        path: str,
        summary: str,
        artifact_kind: str,
    ) -> None:
        finding = RescanFinding(
            category=category,
            classification=classification,
            severity=severity,
            path=path,
            summary=summary,
            artifact_kind=artifact_kind,
        )
        key = (
            finding.category,
            finding.classification,
            finding.severity,
            finding.path,
            finding.summary,
            finding.artifact_kind,
        )
        if key in self._seen:
            return
        self._seen.add(key)
        self._findings.append(finding)

    def as_list(self) -> list[RescanFinding]:
        return list(self._findings)


def _logical_path(path: Path, materialized: MaterializedWorkspace) -> str:
    for key, root in materialized.host_paths.items():
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        base = materialized.redact_text(str(root))
        rel = relative.as_posix()
        return base if not rel or rel == "." else f"{base}/{rel}"
    return materialized.redact_text(str(path))


def _iter_scan_roots(materialized: MaterializedWorkspace) -> Iterable[tuple[str, Path]]:
    for key in ("workspace", "pip_cache", "npm_cache"):
        path = materialized.host_paths.get(key)
        if path is not None and path.exists():
            yield key, path


def _should_scan_file(root_name: str, path: Path) -> bool:
    if any(path.name.endswith(suffix) for suffix in ARCHIVE_SUFFIXES):
        return True
    if "node_modules" in path.parts and (path.name == "package.json" or path.suffix in TEXT_FILE_SUFFIXES):
        return True
    if ".dist-info" in path.parts and (path.name in FETCH_ARTIFACT_FILENAMES or path.suffix in TEXT_FILE_SUFFIXES):
        return True
    if root_name in {"pip_cache", "npm_cache"} and (path.name in FETCH_ARTIFACT_FILENAMES or path.suffix in TEXT_FILE_SUFFIXES):
        return True
    return False


def _read_text_file(path: Path) -> str | None:
    try:
        with path.open("rb") as handle:
            payload = handle.read(MAX_TEXT_BYTES + 1)
    except OSError:
        return None
    return payload[:MAX_TEXT_BYTES].decode("utf-8", errors="replace")


def _archive_path(logical_path: str) -> str:
    return logical_path.split("!/", 1)[0]


def _member_path(logical_archive_path: str, member_name: str) -> str:
    return f"{logical_archive_path}!/{member_name}"


def _is_metadata_member(member_name: str) -> bool:
    basename = Path(member_name).name
    return basename in METADATA_FILENAMES or ".dist-info/" in member_name


def _is_packaged_test_support_member(member_name: str) -> bool:
    parts = [part.lower() for part in Path(member_name).parts]
    basename = Path(member_name).name.lower()
    return any(part in {"tests", "testing", "test"} for part in parts) or basename.startswith("test_")


def _non_comment_text(text: str) -> str:
    return "\n".join(line for line in text.splitlines() if not COMMENT_ONLY_PATTERN.match(line))


def _record_build_metadata_reference(
    collector: FindingCollector,
    *,
    logical_archive_path: str,
    member_name: str,
    artifact_kind: str,
    is_source_archive: bool,
    text: str,
) -> None:
    member_logical_path = _member_path(logical_archive_path, member_name)
    basename = Path(member_name).name
    if basename == "setup.py":
        if is_source_archive:
            collector.add(
                category="python_build_script_present",
                classification=CLASS_INSTALL_TIME_EXECUTION_RISK,
                severity="block",
                path=member_logical_path,
                summary="Fetched source archive contains setup.py that could execute during install.",
                artifact_kind=artifact_kind,
            )
        else:
            collector.add(
                category="packaged_build_script_reference",
                classification=CLASS_UNKNOWN_REQUIRES_REVIEW,
                severity="warn",
                path=logical_archive_path,
                summary="Fetched archive packages setup.py content, which is unusual but not itself proof of install-time execution.",
                artifact_kind=artifact_kind,
            )
    if BUILD_BACKEND_PATTERN.search(text):
        if is_source_archive:
            collector.add(
                category="python_build_backend_present",
                classification=CLASS_INSTALL_TIME_EXECUTION_RISK,
                severity="block",
                path=member_logical_path,
                summary="Fetched source archive declares a build backend that could execute during install.",
                artifact_kind=artifact_kind,
            )
        else:
            collector.add(
                category="packaged_build_backend_reference",
                classification=CLASS_UNKNOWN_REQUIRES_REVIEW,
                severity="warn",
                path=logical_archive_path,
                summary="Fetched archive packages build-backend metadata, which remains review-worthy before later execution phases.",
                artifact_kind=artifact_kind,
            )


def _record_code_pattern_findings(
    collector: FindingCollector,
    *,
    text: str,
    logical_archive_path: str,
    member_name: str,
    artifact_kind: str,
    metadata_only: bool,
    install_context: bool,
) -> None:
    member_logical_path = _member_path(logical_archive_path, member_name)
    executable_text = _non_comment_text(text)
    has_dynamic_exec = bool(DYNAMIC_EXEC_PATTERN.search(executable_text))
    has_obfuscation = bool(OBFUSCATION_PATTERN.search(executable_text))
    has_network_ref = bool(NETWORK_REFERENCE_PATTERN.search(text))
    has_env_ref = bool(ENV_REFERENCE_PATTERN.search(text))
    has_secret_or_path_ref = bool(SECRET_OR_PATH_REFERENCE_PATTERN.search(text))
    has_ip_literal = bool(IP_LITERAL_PATTERN.search(text))
    is_packaged_test_support = _is_packaged_test_support_member(member_name) and not install_context

    if has_obfuscation and has_dynamic_exec:
        collector.add(
            category="obfuscated_dynamic_execution",
            classification=CLASS_SUSPICIOUS_CODE_PATTERN,
            severity="block",
            path=member_logical_path,
            summary="Fetched artifact combines obfuscation with dynamic execution primitives.",
            artifact_kind=artifact_kind,
        )
    elif is_packaged_test_support and has_dynamic_exec and (has_env_ref or has_secret_or_path_ref or has_network_ref):
        collector.add(
            category="packaged_test_support_dynamic_execution",
            classification=CLASS_UNKNOWN_REQUIRES_REVIEW,
            severity="warn",
            path=member_logical_path,
            summary=(
                "Fetched archive packages test or support code that combines dynamic execution with environment, "
                "credential, path, or network references; this is not an install-time path by itself but still needs review."
            ),
            artifact_kind=artifact_kind,
        )
    elif has_dynamic_exec and (has_env_ref or has_secret_or_path_ref):
        collector.add(
            category="dynamic_execution_with_secret_or_env_access",
            classification=CLASS_SUSPICIOUS_CODE_PATTERN,
            severity="block",
            path=member_logical_path,
            summary="Fetched artifact combines dynamic execution with environment or credential-oriented references.",
            artifact_kind=artifact_kind,
        )
    elif install_context and has_dynamic_exec:
        collector.add(
            category="dynamic_execution_during_install",
            classification=CLASS_INSTALL_TIME_EXECUTION_RISK,
            severity="block",
            path=member_logical_path,
            summary="Install-time script contains dynamic execution primitives and remains blocked.",
            artifact_kind=artifact_kind,
        )

    if metadata_only:
        if has_network_ref or has_env_ref or has_secret_or_path_ref or has_ip_literal:
            collector.add(
                category="metadata_reference",
                classification=CLASS_METADATA_OR_STRING_REFERENCE,
                severity="info",
                path=logical_archive_path,
                summary="Fetched archive metadata contains ordinary reference strings that are not executed during Phase 1 fetch.",
                artifact_kind=artifact_kind,
            )
        return

    if install_context:
        return

    if has_network_ref:
        collector.add(
            category="network_api_reference",
            classification=CLASS_ORDINARY_LIBRARY_CAPABILITY,
            severity="warn",
            path=logical_archive_path,
            summary="Fetched archive exposes ordinary networking capability in packaged code; review before later execution phases.",
            artifact_kind=artifact_kind,
        )
    if has_env_ref:
        collector.add(
            category="env_reference",
            classification=CLASS_ORDINARY_LIBRARY_CAPABILITY,
            severity="warn",
            path=logical_archive_path,
            summary="Fetched archive references environment-derived configuration in packaged code.",
            artifact_kind=artifact_kind,
        )
    if has_secret_or_path_ref:
        collector.add(
            category="expected_secret_or_path_reference",
            classification=CLASS_BENIGN_EXPECTED_REFERENCE,
            severity="info",
            path=logical_archive_path,
            summary="Fetched archive references common secret, certificate, or path names as packaged strings only.",
            artifact_kind=artifact_kind,
        )
    if has_ip_literal:
        collector.add(
            category="ip_or_host_literal_reference",
            classification=CLASS_BENIGN_EXPECTED_REFERENCE,
            severity="info",
            path=logical_archive_path,
            summary="Fetched archive contains host or IP literals as packaged content only.",
            artifact_kind=artifact_kind,
        )


def _scan_python_archive_member(
    collector: FindingCollector,
    *,
    text: str,
    logical_archive_path: str,
    member_name: str,
    artifact_kind: str,
    is_source_archive: bool,
) -> None:
    if is_source_archive:
        collector.add(
            category="source_distribution_present",
            classification=CLASS_DEPENDENCY_SOURCE_RISK,
            severity="block",
            path=logical_archive_path,
            summary="Fetched Python source archive would require install-time build execution and remains blocked.",
            artifact_kind=artifact_kind,
        )
    _record_build_metadata_reference(
        collector,
        logical_archive_path=logical_archive_path,
        member_name=member_name,
        artifact_kind=artifact_kind,
        is_source_archive=is_source_archive,
        text=text,
    )
    _record_code_pattern_findings(
        collector,
        text=text,
        logical_archive_path=logical_archive_path,
        member_name=member_name,
        artifact_kind=artifact_kind,
        metadata_only=_is_metadata_member(member_name),
        install_context=False,
    )


def _scan_package_json_text(
    text: str,
    *,
    logical_path: str,
    collector: FindingCollector,
    artifact_kind: str,
) -> None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        collector.add(
            category="manifest_parse_error",
            classification=CLASS_UNKNOWN_REQUIRES_REVIEW,
            severity="warn",
            path=logical_path,
            summary="Fetched package.json could not be parsed during Phase 1.5 rescan.",
            artifact_kind=artifact_kind,
        )
        return
    scripts = payload.get("scripts")
    if not isinstance(scripts, dict):
        return
    for script_name in LIFECYCLE_SCRIPT_NAMES:
        script_value = scripts.get(script_name)
        if not isinstance(script_value, str) or not script_value.strip():
            continue
        collector.add(
            category="lifecycle_script_present",
            classification=CLASS_INSTALL_TIME_EXECUTION_RISK,
            severity="block",
            path=logical_path,
            summary=f"Fetched package manifest declares a {script_name} lifecycle script that could execute during install.",
            artifact_kind=artifact_kind,
        )
        _record_code_pattern_findings(
            collector,
            text=script_value,
            logical_archive_path=logical_path,
            member_name=f"scripts.{script_name}",
            artifact_kind=artifact_kind,
            metadata_only=False,
            install_context=True,
        )


def _scan_package_json(
    path: Path,
    *,
    materialized: MaterializedWorkspace,
    collector: FindingCollector,
) -> None:
    text = _read_text_file(path)
    if text is None:
        collector.add(
            category="artifact_read_error",
            classification=CLASS_UNKNOWN_REQUIRES_REVIEW,
            severity="warn",
            path=_logical_path(path, materialized),
            summary="Fetched package manifest could not be read during Phase 1.5 rescan.",
            artifact_kind="node_package_manifest",
        )
        return
    _scan_package_json_text(
        text,
        logical_path=_logical_path(path, materialized),
        collector=collector,
        artifact_kind="node_package_manifest",
    )


def _scan_zip_archive(
    path: Path,
    *,
    materialized: MaterializedWorkspace,
    collector: FindingCollector,
    limitations: list[str],
) -> None:
    logical_archive_path = _logical_path(path, materialized)
    try:
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                member_name = member.filename
                basename = Path(member_name).name
                if basename not in FETCH_ARTIFACT_FILENAMES and not member_name.endswith(TEXT_FILE_SUFFIXES):
                    continue
                try:
                    payload = archive.read(member)
                except (KeyError, OSError):
                    limitations.append("One or more fetched archive members could not be read during Phase 1.5 rescan.")
                    continue
                text = payload[:MAX_TEXT_BYTES].decode("utf-8", errors="replace")
                if basename == "package.json":
                    _scan_package_json_text(
                        text,
                        logical_path=_member_path(logical_archive_path, member_name),
                        collector=collector,
                        artifact_kind="python_archive",
                    )
                    continue
                _scan_python_archive_member(
                    collector,
                    text=text,
                    logical_archive_path=logical_archive_path,
                    member_name=member_name,
                    artifact_kind="python_archive",
                    is_source_archive=False,
                )
    except (OSError, zipfile.BadZipFile):
        limitations.append("One or more fetched archives could not be opened during Phase 1.5 rescan.")
        collector.add(
            category="artifact_read_error",
            classification=CLASS_UNKNOWN_REQUIRES_REVIEW,
            severity="warn",
            path=logical_archive_path,
            summary="Fetched archive could not be opened during Phase 1.5 rescan.",
            artifact_kind="archive",
        )


def _scan_tar_archive(
    path: Path,
    *,
    materialized: MaterializedWorkspace,
    collector: FindingCollector,
    limitations: list[str],
    artifact_kind: str,
) -> None:
    logical_archive_path = _logical_path(path, materialized)
    is_python_source_archive = artifact_kind == "python_archive" and path.name.endswith(".tar.gz")
    try:
        with tarfile.open(path) as archive:
            for member in archive.getmembers():
                if not member.isfile():
                    continue
                basename = Path(member.name).name
                if basename not in FETCH_ARTIFACT_FILENAMES and not member.name.endswith(TEXT_FILE_SUFFIXES):
                    continue
                try:
                    member_file = archive.extractfile(member)
                except (KeyError, OSError, tarfile.TarError):
                    limitations.append("One or more fetched source-archive members could not be read during Phase 1.5 rescan.")
                    continue
                if member_file is None:
                    continue
                try:
                    payload = member_file.read(MAX_TEXT_BYTES)
                except OSError:
                    limitations.append("One or more fetched source-archive members could not be read during Phase 1.5 rescan.")
                    continue
                text = payload.decode("utf-8", errors="replace")
                if basename == "package.json":
                    _scan_package_json_text(
                        text,
                        logical_path=_member_path(logical_archive_path, member.name),
                        collector=collector,
                        artifact_kind=artifact_kind,
                    )
                    continue
                if artifact_kind == "python_archive":
                    _scan_python_archive_member(
                        collector,
                        text=text,
                        logical_archive_path=logical_archive_path,
                        member_name=member.name,
                        artifact_kind=artifact_kind,
                        is_source_archive=is_python_source_archive,
                    )
    except (OSError, tarfile.TarError):
        limitations.append("One or more fetched source archives could not be opened during Phase 1.5 rescan.")
        collector.add(
            category="artifact_read_error",
            classification=CLASS_UNKNOWN_REQUIRES_REVIEW,
            severity="warn",
            path=logical_archive_path,
            summary="Fetched source archive could not be opened during Phase 1.5 rescan.",
            artifact_kind="archive",
        )


def _scan_plain_text_artifact(
    path: Path,
    *,
    materialized: MaterializedWorkspace,
    collector: FindingCollector,
) -> bool:
    text = _read_text_file(path)
    if text is None:
        collector.add(
            category="artifact_read_error",
            classification=CLASS_UNKNOWN_REQUIRES_REVIEW,
            severity="warn",
            path=_logical_path(path, materialized),
            summary="Fetched artifact could not be read during Phase 1.5 rescan.",
            artifact_kind="plain_text_artifact",
        )
        return False
    logical_path = _logical_path(path, materialized)
    if path.name == "package.json":
        _scan_package_json_text(
            text,
            logical_path=logical_path,
            collector=collector,
            artifact_kind="plain_text_artifact",
        )
        return True
    _record_build_metadata_reference(
        collector,
        logical_archive_path=logical_path,
        member_name=path.name,
        artifact_kind="plain_text_artifact",
        is_source_archive=False,
        text=text,
    )
    _record_code_pattern_findings(
        collector,
        text=text,
        logical_archive_path=logical_path,
        member_name=path.name,
        artifact_kind="plain_text_artifact",
        metadata_only=path.name in METADATA_FILENAMES,
        install_context=False,
    )
    return True


def _group_findings(findings: list[RescanFinding]) -> dict[str, list[dict[str, str]]]:
    blocked = [item.as_dict() for item in findings if item.severity == "block"]
    warned = [
        item.as_dict()
        for item in findings
        if item.severity == "warn" and item.classification != CLASS_UNKNOWN_REQUIRES_REVIEW
    ]
    info = [item.as_dict() for item in findings if item.severity == "info"]
    unknown = [item.as_dict() for item in findings if item.classification == CLASS_UNKNOWN_REQUIRES_REVIEW]
    return {
        "blocked_findings": blocked,
        "warn_findings": warned,
        "info_findings": info,
        "unknown_findings": unknown,
        "ordinary_library_capabilities": [
            item.as_dict() for item in findings if item.classification == CLASS_ORDINARY_LIBRARY_CAPABILITY
        ],
        "install_time_risks": [
            item.as_dict() for item in findings if item.classification == CLASS_INSTALL_TIME_EXECUTION_RISK
        ],
        "dependency_source_risks": [
            item.as_dict() for item in findings if item.classification == CLASS_DEPENDENCY_SOURCE_RISK
        ],
    }


def _residual_risks(
    *,
    blocked_findings: list[dict[str, str]],
    warn_findings: list[dict[str, str]],
    unknown_findings: list[dict[str, str]],
    read_error_count: int,
    performed: bool,
) -> list[str]:
    residual_risks: list[str] = []
    if performed:
        residual_risks.append("phase1_5_static_rescan_only")
    if blocked_findings:
        residual_risks.append("phase1_5_blocked_findings_present")
    if warn_findings:
        residual_risks.append("phase1_5_warn_findings_require_human_review")
    if unknown_findings:
        residual_risks.append("phase1_5_unknown_findings_require_review")
    if read_error_count:
        residual_risks.append("phase1_5_read_errors_reduce_confidence")
    return residual_risks


def run_phase1_rescan(materialized: MaterializedWorkspace) -> dict[str, Any]:
    collector = FindingCollector()
    limitations: list[str] = []
    scanned_file_count = 0
    artifact_candidate_count = 0
    read_error_count = 0
    artifact_kind_counts = {
        "node_package_manifest": 0,
        "node_package_archive": 0,
        "python_archive": 0,
        "plain_text_artifact": 0,
    }

    for root_name, root in _iter_scan_roots(materialized):
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if not _should_scan_file(root_name, path):
                continue
            artifact_candidate_count += 1
            scanned_file_count += 1
            if path.name == "package.json":
                artifact_kind_counts["node_package_manifest"] += 1
                _scan_package_json(path, materialized=materialized, collector=collector)
                continue
            if path.name.endswith(".whl") or path.name.endswith(".zip"):
                artifact_kind_counts["python_archive"] += 1
                _scan_zip_archive(path, materialized=materialized, collector=collector, limitations=limitations)
                continue
            if path.name.endswith(".tgz") or path.name.endswith(".tar.gz"):
                artifact_kind = "node_package_archive" if path.name.endswith(".tgz") else "python_archive"
                artifact_kind_counts[artifact_kind] += 1
                _scan_tar_archive(
                    path,
                    materialized=materialized,
                    collector=collector,
                    limitations=limitations,
                    artifact_kind=artifact_kind,
                )
                continue
            artifact_kind_counts["plain_text_artifact"] += 1
            if not _scan_plain_text_artifact(path, materialized=materialized, collector=collector):
                read_error_count += 1

    if read_error_count:
        limitations.append("One or more fetched artifacts could not be read completely during Phase 1.5 rescan.")

    findings = collector.as_list()
    grouped = _group_findings(findings)

    status = "skipped"
    performed = False
    if artifact_candidate_count:
        performed = True
        if grouped["blocked_findings"]:
            status = "blocked"
        elif grouped["warn_findings"] or grouped["unknown_findings"] or read_error_count:
            status = "warn"
        else:
            status = "passed"
    else:
        limitations.append("No fetched dependency artifacts were available for Phase 1.5 static rescan.")

    blocked_findings = grouped["blocked_findings"]
    warn_findings = grouped["warn_findings"]
    info_findings = grouped["info_findings"]
    unknown_findings = grouped["unknown_findings"]

    return {
        "requested": True,
        "performed": performed,
        "status": status,
        "artifact_summary": {
            "scanned_file_count": scanned_file_count,
            "artifact_candidate_count": artifact_candidate_count,
            "read_error_count": read_error_count,
            "artifact_kind_counts": artifact_kind_counts,
        },
        "finding_summary": {
            "blocked_count": len(blocked_findings),
            "warn_count": len(warn_findings),
            "info_count": len(info_findings),
            "unknown_count": len(unknown_findings),
        },
        "findings": [item.as_dict() for item in findings],
        "blocked_findings": blocked_findings,
        "warn_findings": warn_findings,
        "info_findings": info_findings,
        "unknown_findings": unknown_findings,
        "ordinary_library_capabilities": grouped["ordinary_library_capabilities"],
        "install_time_risks": grouped["install_time_risks"],
        "dependency_source_risks": grouped["dependency_source_risks"],
        "limitations": list(dict.fromkeys(limitations)),
        "residual_risks": _residual_risks(
            blocked_findings=blocked_findings,
            warn_findings=warn_findings,
            unknown_findings=unknown_findings,
            read_error_count=read_error_count,
            performed=performed,
        ),
    }
