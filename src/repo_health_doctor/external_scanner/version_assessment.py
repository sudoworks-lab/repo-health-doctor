"""Shared version assessment for real scanner compatibility evidence."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterable


VERSION_STATUS_TESTED = "tested"
VERSION_STATUS_COMPATIBLE_FAMILY_UNVERIFIED = "compatible_family_unverified"
VERSION_STATUS_UNSUPPORTED = "unsupported"
VERSION_STATUS_DENYLISTED = "denylisted"
VERSION_STATUS_UNPARSEABLE = "unparseable"

VERSION_STATUSES = (
    VERSION_STATUS_TESTED,
    VERSION_STATUS_COMPATIBLE_FAMILY_UNVERIFIED,
    VERSION_STATUS_UNSUPPORTED,
    VERSION_STATUS_DENYLISTED,
    VERSION_STATUS_UNPARSEABLE,
)

_VERSION_TOKEN = r"(?P<version>\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9._-]+)?)"


@dataclass(frozen=True)
class ScannerVersionPolicy:
    scanner_name: str
    output_names: tuple[str, ...]
    tested_versions: tuple[str, ...]
    compatible_major_versions: tuple[int, ...]
    denylisted_versions: frozenset[str]


@dataclass(frozen=True)
class ScannerVersionAssessment:
    scanner_name: str
    version: str
    status: str
    supported_for_live_scan: bool
    suite_degraded: bool
    unsupported_version: bool
    blocking_error: str | None
    unknown_reason: str | None

    @property
    def execution_allowed(self) -> bool:
        return self.supported_for_live_scan

    @property
    def degraded(self) -> bool:
        return self.suite_degraded

    def to_dict(self) -> dict[str, object]:
        return {
            "scanner_name": self.scanner_name,
            "version": self.version,
            "status": self.status,
            "supported_for_live_scan": self.supported_for_live_scan,
            "suite_degraded": self.suite_degraded,
            "unsupported_version": self.unsupported_version,
            "blocking_error": self.blocking_error,
            "unknown_reason": self.unknown_reason,
        }


GITLEAKS_VERSION_POLICY = ScannerVersionPolicy(
    scanner_name="gitleaks",
    output_names=("gitleaks",),
    tested_versions=("8.27.2",),
    compatible_major_versions=(8,),
    denylisted_versions=frozenset({"0.0.0"}),
)

OSV_SCANNER_VERSION_POLICY = ScannerVersionPolicy(
    scanner_name="osv-scanner",
    output_names=("osv-scanner",),
    tested_versions=("2.0.3",),
    compatible_major_versions=(2,),
    denylisted_versions=frozenset({"0.0.0"}),
)


def assess_gitleaks_version(stdout: str, stderr: str = "") -> ScannerVersionAssessment:
    return assess_scanner_version(stdout, stderr, policy=GITLEAKS_VERSION_POLICY)


def assess_osv_scanner_version(stdout: str, stderr: str = "") -> ScannerVersionAssessment:
    return assess_scanner_version(stdout, stderr, policy=OSV_SCANNER_VERSION_POLICY)


def assess_scanner_version(
    stdout: str,
    stderr: str,
    *,
    policy: ScannerVersionPolicy,
) -> ScannerVersionAssessment:
    version = _parse_version(stdout, stderr, output_names=policy.output_names)
    if version is None:
        return _assessment(policy.scanner_name, "unknown", VERSION_STATUS_UNPARSEABLE)

    version_core = _version_core(version)
    if version_core in policy.denylisted_versions:
        return _assessment(policy.scanner_name, version, VERSION_STATUS_DENYLISTED)
    if version in policy.tested_versions:
        return _assessment(policy.scanner_name, version, VERSION_STATUS_TESTED)
    if _major(version) in policy.compatible_major_versions:
        return _assessment(policy.scanner_name, version, VERSION_STATUS_COMPATIBLE_FAMILY_UNVERIFIED)
    return _assessment(policy.scanner_name, version, VERSION_STATUS_UNSUPPORTED)


def _assessment(scanner_name: str, version: str, status: str) -> ScannerVersionAssessment:
    supported = status in {VERSION_STATUS_TESTED, VERSION_STATUS_COMPATIBLE_FAMILY_UNVERIFIED}
    blocking_error = None if supported else f"scanner_version_{status}"
    return ScannerVersionAssessment(
        scanner_name=scanner_name,
        version=version,
        status=status,
        supported_for_live_scan=supported,
        suite_degraded=status != VERSION_STATUS_TESTED,
        unsupported_version=not supported,
        blocking_error=blocking_error,
        unknown_reason=None if supported else status,
    )


def _parse_version(stdout: str, stderr: str, *, output_names: Iterable[str]) -> str | None:
    candidate = _first_nonempty_line(stdout) or _first_nonempty_line(stderr)
    if candidate is None:
        return None
    names = "|".join(re.escape(name) for name in output_names)
    prefix = rf"(?:(?:{names})(?:\s+version)?\s*:?\s+)"
    match = re.fullmatch(rf"(?:{prefix})?v?{_VERSION_TOKEN}", candidate, flags=re.IGNORECASE)
    return match.group("version") if match else None


def _first_nonempty_line(value: str) -> str | None:
    for line in value.splitlines():
        candidate = line.strip()
        if candidate:
            return candidate
    return None


def _version_core(version: str) -> str:
    return re.split(r"[-+]", version, maxsplit=1)[0]


def _major(version: str) -> int:
    return int(version.split(".", maxsplit=1)[0])
