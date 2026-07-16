"""Redacted formatters for the explicit real scanner suite report."""

from __future__ import annotations

from collections.abc import Mapping
import json
import re
from typing import Any


_REDACTED = "<redacted>"
_REDACTED_PATH = "<redacted-path>"
_SENSITIVE_KEYS = re.compile(
    r"(?:^|_)(?:api[_-]?key|credential|password|passwd|secret|token|raw|stdout|stderr|snippet|match)(?:$|_)",
    re.IGNORECASE,
)
_UNIX_PRIVATE_PATH = re.compile(r"/(?:home|Users|private|tmp|var|opt|root|mnt|run)/[^\s\"'`,;)}\]]+")
_WINDOWS_PRIVATE_PATH = re.compile(r"[A-Za-z]:[\\/](?:Users|home|private|Temp|tmp)[^\s\"'`,;)}\]]*")
_TOKEN_VALUE = re.compile(
    r"(?:AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{16,}|sk-[A-Za-z0-9_-]{20,})"
)
_ASSIGNMENT_SECRET = re.compile(
    r"((?:api[_-]?key|password|passwd|secret|token)\s*[:=]\s*)[^\s,;]+",
    re.IGNORECASE,
)


def _report_mapping(report: Any) -> dict[str, Any]:
    if hasattr(report, "to_dict"):
        value = report.to_dict()
    elif isinstance(report, Mapping):
        value = dict(report)
    else:
        raise TypeError("real scanner suite report must be a mapping or report model")
    if not isinstance(value, dict):
        raise TypeError("real scanner suite report must serialize to an object")
    return _redact_value(value, key=None)


def _redact_string(value: str) -> str:
    value = _UNIX_PRIVATE_PATH.sub(_REDACTED_PATH, value)
    value = _WINDOWS_PRIVATE_PATH.sub(_REDACTED_PATH, value)
    value = _TOKEN_VALUE.sub(_REDACTED, value)
    return _ASSIGNMENT_SECRET.sub(r"\1" + _REDACTED, value)


def _redact_value(value: Any, *, key: str | None) -> Any:
    if key is not None and _SENSITIVE_KEYS.search(key):
        if isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, (dict, list, tuple)):
            return _REDACTED
        return _REDACTED if value is not None else None
    if isinstance(value, str):
        return _redact_string(value)
    if isinstance(value, Mapping):
        return {str(item_key): _redact_value(item_value, key=str(item_key)) for item_key, item_value in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_value(item, key=None) for item in value]
    return value


def format_real_scanner_suite_json(report: Any) -> str:
    """Return the canonical indented JSON representation of a redacted report."""

    return json.dumps(_report_mapping(report), indent=2, ensure_ascii=False) + "\n"


def format_real_scanner_suite_text(report: Any) -> str:
    data = _report_mapping(report)
    lines = [
        "Repo Health Doctor Real Scanner Suite: " + str(data["suite_status"]).upper(),
        f"Schema: {data['schema_version']}",
        f"Report kind: {data['report_kind']}",
        f"Execution authorized: {str(data['execution_authorized']).lower()}",
        f"Report fingerprint: {data['report_fingerprint']}",
        f"Generated at: {data['generated_at']}",
        "",
        "Subject:",
        f"- Commit: {data['subject']['repo_commit'] if data['subject']['repo_commit'] is not None else 'unknown'}",
        f"- Dirty state: {data['subject']['dirty_state']}",
        "",
        "Scanner entries:",
    ]
    for entry in data["entries"]:
        lines.extend(
            [
                f"- {entry['scanner_name']}: status={entry['status']}, executed={str(entry['executed']).lower()}, valid={str(entry['valid']).lower()}, findings={entry['finding_count']}, omitted={entry['omitted_finding_count']}, truncated={str(entry['truncated']).lower()}",
                f"  - Blocking errors: {', '.join(entry['blocking_errors']) or 'none'}",
                f"  - Warnings: {', '.join(entry['warnings']) or 'none'}",
                f"  - Risk effect: {entry['risk_summary']['risk_tier_effect']}",
                f"  - Gate effects: {', '.join(entry['risk_summary']['gate_effects']) or 'none'}",
            ]
        )
    lines.extend(["", "Limitations:", *[f"- {item}" for item in data["limitations"]]])
    return "\n".join(lines).rstrip() + "\n"


def format_real_scanner_suite_markdown(report: Any) -> str:
    data = _report_mapping(report)
    lines = [
        "# Repo Health Doctor Real Scanner Suite",
        "",
        f"- Status: `{data['suite_status']}`",
        f"- Schema Version: `{data['schema_version']}`",
        f"- Report Kind: `{data['report_kind']}`",
        f"- Execution Authorized: `{str(data['execution_authorized']).lower()}`",
        f"- Report Fingerprint: `{data['report_fingerprint']}`",
        f"- Generated At: `{data['generated_at']}`",
        "",
        "## Subject",
        "",
        f"- Commit: `{data['subject']['repo_commit'] if data['subject']['repo_commit'] is not None else 'unknown'}`",
        f"- Dirty State: `{data['subject']['dirty_state']}`",
        "",
        "## Scanner Entries",
        "",
        "| Scanner | Status | Executed | Valid | Findings | Omitted | Truncated |",
        "| --- | --- | --- | --- | ---: | ---: | --- |",
    ]
    for entry in data["entries"]:
        lines.append(
            f"| `{entry['scanner_name']}` | `{entry['status']}` | `{str(entry['executed']).lower()}` | `{str(entry['valid']).lower()}` | {entry['finding_count']} | {entry['omitted_finding_count']} | `{str(entry['truncated']).lower()}` |"
        )
    lines.extend(["", "## Entry Details", ""])
    for entry in data["entries"]:
        lines.extend(
            [
                f"### `{entry['scanner_name']}`",
                "",
                f"- Blocking errors: {', '.join(entry['blocking_errors']) or 'none'}",
                f"- Warnings: {', '.join(entry['warnings']) or 'none'}",
                f"- Risk effect: `{entry['risk_summary']['risk_tier_effect']}`",
                f"- Gate effects: {', '.join(entry['risk_summary']['gate_effects']) or 'none'}",
                "",
            ]
        )
    lines.extend(["## Limitations", "", *[f"- {item}" for item in data["limitations"]], ""])
    return "\n".join(lines)


def format_real_scanner_suite(report: Any, output_format: str) -> str:
    if output_format == "json":
        return format_real_scanner_suite_json(report)
    if output_format == "text":
        return format_real_scanner_suite_text(report)
    if output_format in {"markdown", "md"}:
        return format_real_scanner_suite_markdown(report)
    raise ValueError(f"unsupported real scanner suite format: {output_format}")


# Keep the short names available to callers that already select a formatter
# module before choosing the report kind.
format_suite_json = format_real_scanner_suite_json
format_suite_text = format_real_scanner_suite_text
format_suite_markdown = format_real_scanner_suite_markdown
format_json = format_real_scanner_suite_json
format_text = format_real_scanner_suite_text
format_markdown = format_real_scanner_suite_markdown
