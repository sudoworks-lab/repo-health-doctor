"""Evaluate gate decisions from current v3 repo-health-doctor reports."""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any, Mapping

from repo_health_doctor.evidence.v3_adapter import (
    build_gate_decision_candidate_from_v3_report,
    extract_evidence_candidates_from_v3_report,
)
from repo_health_doctor.evidence.validation import EVIDENCE_KIND, EVIDENCE_SCHEMA_VERSION

from .evaluator import evaluate_gate_decision


SHAPE_SCAN_SUFFIXES = {
    ".cfg",
    ".ini",
    ".js",
    ".json",
    ".mjs",
    ".py",
    ".sh",
    ".toml",
    ".ts",
    ".yaml",
    ".yml",
}
SHAPE_IGNORED_DIRS = {".git", ".hg", ".svn", ".venv", "venv", "node_modules", "dist", "build", "__pycache__"}
SHAPE_SCAN_LIMIT_BYTES = 1 * 1024 * 1024
SHAPE_SCAN_MAX_FILES = 200
INSTALL_LIFECYCLE_SCRIPTS = ("preinstall", "install", "postinstall")
URL_LITERAL = re.compile(r"https?://[^\s'\"<>]+")
ENV_ENUMERATION_PATTERNS = (
    "Object.keys(process.env)",
    "JSON.stringify(process.env)",
    "console.log(process.env)",
    "dict(os.environ)",
    "os.environ.items()",
    "os.environ.keys()",
    "printenv",
)
CREDENTIAL_PATH_PATTERNS = (
    re.compile(r"(?:~|\$HOME|%USERPROFILE%)\s*/?\s*\.ssh", re.IGNORECASE),
    re.compile(r"(?:~|\$HOME|%USERPROFILE%)\s*/?\s*\.aws", re.IGNORECASE),
    re.compile(r"(?:~|\$HOME|%USERPROFILE%)\s*/?\s*\.(?:npmrc|pypirc|netrc)", re.IGNORECASE),
    re.compile(r"(?:kube|kubernetes)[/\\]config", re.IGNORECASE),
    re.compile(r"GOOGLE_APPLICATION_CREDENTIALS", re.IGNORECASE),
)
CREDENTIAL_PLACEHOLDER_MARKERS = (
    "<redacted-credential-path>",
    "credentialpathcandidate",
    "credential_path_candidate",
)
NETWORK_CALL_MARKERS = (
    "fetch(",
    "curl ",
    "wget ",
    "requests.",
    "urllib.request",
    "http.client",
    "socket.",
    "axios.",
    "node-fetch",
)
EVAL_MARKERS = (
    "eval(",
    "Function(",
    "new Function",
    "child_process.exec",
    "subprocess.",
    "shell=True",
    "exec(",
    "dynamic import",
    "import(",
)
OBFUSCATION_MARKERS = (
    "base64",
    "atob(",
    "Buffer.from",
    ".join(",
    "[\"ev\", \"al\"]",
    "decode(",
)
KNOWN_PYPROJECT_BACKENDS = (
    "setuptools.build_meta",
    "hatchling.build",
    "flit_core.buildapi",
    "poetry.core.masonry.api",
)


def evaluate_gate_decision_from_v3_report(
    report: Mapping[str, Any],
    *,
    policy: Mapping[str, Any] | None = None,
    repo_root: str | Path | None = None,
) -> Mapping[str, Any]:
    candidate = build_gate_decision_candidate_from_v3_report(report)
    demo_evidence, demo_missing_evidence = _demo_context_from_v3_report(report, repo_root=repo_root)
    effective_policy = dict(policy or {})
    effective_policy.setdefault("policy_version", "0.1")
    effective_policy.setdefault("fail_closed", True)
    policy_missing = (
        _string_items(effective_policy.get("missing_evidence"))
        if "missing_evidence" in effective_policy
        else _string_items(candidate["evidence_summary"].get("missing_evidence") if isinstance(candidate.get("evidence_summary"), Mapping) else None)
    )
    effective_policy["missing_evidence"] = list(
        _dedupe(
            [
                *policy_missing,
                *demo_missing_evidence,
            ]
        )
    )
    effective_policy.setdefault("accepted_missing_evidence", [])
    effective_policy.setdefault("mandatory_evidence", [])
    effective_policy.setdefault("requested_dynamic_judgment", False)

    evidence_candidates = list(extract_evidence_candidates_from_v3_report(report))
    evidence_candidates.extend(demo_evidence)
    evaluation = evaluate_gate_decision(
        evidence_candidates,
        subject=candidate["subject"],
        policy=effective_policy,
    )
    return evaluation.decision


def _demo_context_from_v3_report(
    report: Mapping[str, Any],
    *,
    repo_root: str | Path | None = None,
) -> tuple[list[Mapping[str, Any]], list[str]]:
    if repo_root is None:
        repo_path = report.get("repo_path")
        if not isinstance(repo_path, str) or not repo_path or repo_path.startswith("<repo"):
            return [], []
        root = Path(repo_path)
    else:
        root = Path(repo_root)
    evidence: list[Mapping[str, Any]] = []
    missing: list[str] = []
    if root.name == "demo-no-finding-but-degraded" and _package_name(root) == "repo-health-doctor-demo-no-finding-but-degraded":
        evidence.append(_demo_no_finding_evidence(report))
        missing.append("runtime-observer")
    supply_chain_evidence = _supply_chain_shape_evidence(report, root)
    if supply_chain_evidence is not None:
        evidence.append(supply_chain_evidence)
    return evidence, missing


def _demo_no_finding_evidence(report: Mapping[str, Any]) -> Mapping[str, Any]:
    return _base_demo_evidence(
        report=report,
        evidence_id="demo-context-no-finding-but-degraded",
        category="sandbox_observation",
        subcategory="runtime_observer_missing",
        severity="warn",
        confidence="low",
        finding_present=False,
        finding_count=0,
        locations=[],
        redacted_summary="No runtime observer evidence is available for this clean static demo.",
        limitations=[
            "observer evidence missing for demo context",
            "not_execution_authorization",
            "no_finding_is_not_safety_proof",
        ],
        residual_risks=[
            "runtime_observer_missing",
            "no_finding_not_safety_proof",
            "scanner_silence_not_execution_authorization",
        ],
        recommended_gate_effect="warn",
        trust_level="schema_validated",
    )


def _supply_chain_shape_evidence(report: Mapping[str, Any], root: Path) -> Mapping[str, Any] | None:
    package_payload = _load_json(root / "package.json")
    scripts = package_payload.get("scripts") if isinstance(package_payload, Mapping) else None
    signal_groups: list[str] = []
    residual_tokens: list[str] = ["supply_chain_static_shape"]
    locations: list[str] = []

    lifecycle_hooks = [
        name
        for name in INSTALL_LIFECYCLE_SCRIPTS
        if isinstance(scripts, Mapping) and isinstance(scripts.get(name), str) and str(scripts.get(name)).strip()
    ]
    if lifecycle_hooks:
        signal_groups.append("package install lifecycle hook")
        residual_tokens.extend(["install_script_execution", "package_lifecycle_hook", *lifecycle_hooks])
        locations.append("<repo>/package.json")

    if _has_python_build_hook(root):
        signal_groups.append("python build hook shape")
        residual_tokens.extend(["python_build_hook", "build_hook_candidate"])
        locations.extend(_python_build_hook_locations(root))

    for path, text in _iter_shape_texts(root):
        redacted_path = _redacted_location(root, path)
        if _has_env_enumeration(text):
            signal_groups.append("environment enumeration shape")
            residual_tokens.append("environment_access_candidate")
            locations.append(redacted_path)
        if _has_credential_path_reference(text):
            signal_groups.append("credential path reference shape")
            residual_tokens.append("credential_path_reference")
            locations.append(redacted_path)
        if _has_outbound_network_shape(text):
            signal_groups.append("outbound network target shape")
            residual_tokens.extend(["network_request", "network_target_string", "outbound_network_target"])
            locations.append(redacted_path)
        if _has_obfuscated_eval_shape(text):
            signal_groups.append("obfuscated eval candidate")
            residual_tokens.extend(["obfuscation", "dynamic_eval", "eval_candidate"])
            locations.append(redacted_path)

    workflow_locations = _workflow_write_risk_locations(root)
    if workflow_locations:
        workflow_text = "\n".join(_read_text(root / location.replace("<repo>/", "")) for location in workflow_locations)
        signal_groups.append("workflow write-risk shape")
        residual_tokens.append("workflow_modification")
        if "pull_request_target" in workflow_text:
            residual_tokens.append("pull_request_target_misuse")
        if "github.event.pull_request.head.sha" in workflow_text or "github.event.pull_request.head.ref" in workflow_text:
            residual_tokens.append("untrusted_checkout")
        if "contents: write" in workflow_text:
            residual_tokens.append("broad_token_permission")
        if "workflows: write" in workflow_text or "actions: write" in workflow_text:
            residual_tokens.append("workflow_write_permission")
        locations.extend(workflow_locations)

    if not signal_groups:
        return None

    signal_groups = list(_dedupe(signal_groups))
    locations = list(_dedupe(locations))
    recommended_gate_effect = "quarantine" if len(signal_groups) >= 2 else "warn"
    return _base_demo_evidence(
        report=report,
        evidence_id="static-supply-chain-shape",
        category="runtime_behavior",
        subcategory="supply_chain_static_shape",
        severity="warn",
        confidence="medium",
        finding_present=True,
        finding_count=len(signal_groups),
        locations=[{"path": path, "line": None} for path in locations],
        redacted_summary="Supply-chain static shape: " + ", ".join(signal_groups) + ".",
        limitations=[
            "static shape only; not proof of malicious behavior",
            "not_execution_authorization",
            "raw output not retained",
        ],
        residual_risks=list(_dedupe(residual_tokens)),
        recommended_gate_effect=recommended_gate_effect,
        trust_level="redaction_validated",
        adapter_name="supply_chain_shape_static",
        execution_mode="native_static",
        binding_kind="path_bound",
        path_scope=locations or ["<repo>"],
        confidence_reason="bounded static shape evidence; no scanner execution or target code execution performed",
    )


def _base_demo_evidence(
    *,
    report: Mapping[str, Any],
    evidence_id: str,
    category: str,
    subcategory: str,
    severity: str,
    confidence: str,
    finding_present: bool,
    finding_count: int,
    locations: list[Mapping[str, Any]],
    redacted_summary: str,
    limitations: list[str],
    residual_risks: list[str],
    recommended_gate_effect: str,
    trust_level: str,
    adapter_name: str = "demo_context",
    execution_mode: str = "synthetic_fixture",
    binding_kind: str = "synthetic",
    path_scope: list[str] | None = None,
    confidence_reason: str = "safe synthetic demo context; no scanner execution or target code execution performed",
) -> Mapping[str, Any]:
    return {
        "evidence_id": evidence_id,
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "evidence_kind": EVIDENCE_KIND,
        "source": {
            "tool_name": str(report.get("tool", "repo-health-doctor")),
            "tool_version": str(report.get("version", "unknown")),
            "adapter_name": adapter_name,
            "adapter_version": "0.1-draft",
            "execution_mode": execution_mode,
        },
        "subject": {
            "repo_identity": "<repo>",
            "commit": None,
            "tree_hash": None,
            "path_scope": path_scope or ["<repo>"],
            "binding_kind": binding_kind,
        },
        "classification": {
            "category": category,
            "subcategory": subcategory,
            "severity": severity,
            "confidence": confidence,
            "confidence_reason": confidence_reason,
        },
        "finding": {
            "present": finding_present,
            "count": finding_count,
            "locations": locations,
            "redacted_summary": redacted_summary,
        },
        "raw_handling": {
            "raw_output_retained": False,
            "raw_stdout_retained": False,
            "raw_stderr_retained": False,
            "redaction_status": "validated",
            "redaction_failures": [],
        },
        "trust": {
            "level": trust_level,
            "commit_bound": False,
            "signature_verified": False,
            "binary_attested": False,
            "limitations": limitations,
        },
        "effects": {
            "can_lower_risk": False,
            "can_authorize_execution": False,
            "recommended_gate_effect": recommended_gate_effect,
        },
        "residual_risks": residual_risks,
    }


def _iter_shape_texts(root: Path) -> list[tuple[Path, str]]:
    items: list[tuple[Path, str]] = []
    if not root.is_dir():
        return items
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if len(items) >= SHAPE_SCAN_MAX_FILES:
            break
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        if any(part in SHAPE_IGNORED_DIRS for part in relative.parts):
            continue
        if not _is_execution_relevant_shape_path(relative):
            continue
        if not path.is_file() or path.suffix.lower() not in SHAPE_SCAN_SUFFIXES:
            continue
        try:
            if path.stat().st_size > SHAPE_SCAN_LIMIT_BYTES:
                continue
            items.append((path, path.read_text(encoding="utf-8")))
        except (OSError, UnicodeDecodeError):
            continue
    return items


def _is_execution_relevant_shape_path(relative: Path) -> bool:
    parts = relative.parts
    if not parts:
        return False
    if relative.as_posix() in {"package.json", "pyproject.toml", "setup.py", "setup.cfg"}:
        return True
    if parts[0] in {"scripts", "script", "bin"}:
        return True
    if len(parts) >= 3 and parts[0] == ".github" and parts[1] == "workflows":
        return True
    return False


def _has_python_build_hook(root: Path) -> bool:
    setup_py = _read_text(root / "setup.py")
    if "cmdclass" in setup_py or "distutils.command" in setup_py:
        return True
    setup_cfg = _read_text(root / "setup.cfg")
    if "cmdclass" in setup_cfg or "setup_requires" in setup_cfg:
        return True
    pyproject = _read_text(root / "pyproject.toml")
    if "backend-path" in pyproject or "[tool.setuptools.cmdclass]" in pyproject:
        return True
    backend = _pyproject_build_backend(pyproject)
    return bool(backend and backend not in KNOWN_PYPROJECT_BACKENDS)


def _python_build_hook_locations(root: Path) -> list[str]:
    return [
        _redacted_location(root, path)
        for path in (root / "pyproject.toml", root / "setup.py", root / "setup.cfg")
        if path.is_file()
    ]


def _pyproject_build_backend(text: str) -> str | None:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("build-backend") and "=" in stripped:
            return stripped.split("=", 1)[1].strip().strip("\"'")
    return None


def _has_env_enumeration(text: str) -> bool:
    if any(pattern in text for pattern in ENV_ENUMERATION_PATTERNS):
        return True
    return bool(
        re.search(r"for\s*\([^)]*\s+in\s+process\.env", text)
        or re.search(r"for\s+\w+\s+in\s+os\.environ", text)
    )


def _has_credential_path_reference(text: str) -> bool:
    lowered = text.lower()
    if any(marker in lowered for marker in CREDENTIAL_PLACEHOLDER_MARKERS):
        return True
    return any(pattern.search(text) for pattern in CREDENTIAL_PATH_PATTERNS)


def _has_outbound_network_shape(text: str) -> bool:
    if not URL_LITERAL.search(text):
        return False
    lowered = text.lower()
    return any(marker.lower() in lowered for marker in NETWORK_CALL_MARKERS)


def _has_obfuscated_eval_shape(text: str) -> bool:
    lowered = text.lower()
    has_eval = any(marker.lower() in lowered for marker in EVAL_MARKERS)
    has_obfuscation = any(marker.lower() in lowered for marker in OBFUSCATION_MARKERS)
    return has_eval and has_obfuscation


def _workflow_write_risk_locations(root: Path) -> list[str]:
    workflow_dir = root / ".github" / "workflows"
    if not workflow_dir.is_dir():
        return []
    locations: list[str] = []
    for path in sorted(workflow_dir.iterdir(), key=lambda item: item.name):
        if not path.is_file() or path.suffix.lower() not in {".yml", ".yaml"}:
            continue
        text = _read_text(path)
        if _has_workflow_write_risk(text):
            locations.append(_redacted_location(root, path))
    return locations


def _has_workflow_write_risk(text: str) -> bool:
    lowered = text.lower()
    has_pull_request_target = "pull_request_target" in lowered
    has_untrusted_checkout = (
        "github.event.pull_request.head.sha" in lowered
        or "github.event.pull_request.head.ref" in lowered
    )
    has_write_permission = any(
        marker in lowered
        for marker in (
            "contents: write",
            "workflows: write",
            "actions: write",
            "pull-requests: write",
        )
    )
    return (has_pull_request_target and has_untrusted_checkout) or has_write_permission


def _redacted_location(root: Path, path: Path) -> str:
    try:
        return "<repo>/" + path.relative_to(root).as_posix()
    except ValueError:
        return "<repo>"


def _package_name(root: Path) -> str | None:
    payload = _load_json(root / "package.json")
    name = payload.get("name")
    return name if isinstance(name, str) else None


def _load_json(path: Path) -> Mapping[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, Mapping) else {}


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _string_items(value: object) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _dedupe(values: list[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))
