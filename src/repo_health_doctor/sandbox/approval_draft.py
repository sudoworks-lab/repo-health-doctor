from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping, Sequence

from ..doctor import STATUS_BLOCK, STATUS_WARN, TOOL_VERSION
from .unknown_profile import (
    REPORT_KIND_UNKNOWN_REPO_PROFILE,
    UNKNOWN_PROFILE_SCHEMA_VERSION,
    _fingerprint,
    _redact_value,
    profile_unknown_repo,
)


APPROVAL_DRAFT_SCHEMA_VERSION = "0.1-draft"
REPORT_KIND_APPROVAL_DRAFT = "sandbox_approval_draft"
APPROVAL_DRAFT_STATUS = "draft_requires_human_review"
_PHASES = {"phase2_install_probe", "phase3_runtime_probe"}
_SAFE_KIND = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SAFE_ENV = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_SHELL_PROGRAMS = {"sh", "bash", "zsh", "fish", "cmd", "powershell", "pwsh"}
_REQUIRED_PROFILE_FIELDS = {
    "schema_version",
    "report_kind",
    "mode",
    "execution_permitted",
    "repo_scope",
    "risk",
    "redaction",
}
_REQUIRED_DRAFT_FIELDS = {
    "tool",
    "version",
    "schema_version",
    "report_kind",
    "status",
    "approval_status",
    "approved",
    "execution_permitted",
    "repo_scope",
    "source_profile_report",
    "source_risk_tier",
    "candidate",
    "candidate_key",
    "exact_match_key",
    "live_candidate_generated",
    "execution_constraints",
    "behavior_policy",
    "reasons",
    "blockers",
    "human_review_requirements",
    "promotion_requirements",
    "limitations",
    "residual_risks",
    "redaction",
}


def _canonical_fingerprint(value: Mapping[str, Any]) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _contains_secret_like(value: str) -> bool:
    return _redact_value(value, Path("/nonexistent")) != value


def _read_static_git_metadata(root: Path) -> dict[str, str]:
    """Read only local .git metadata; never call git or inspect the worktree."""
    git_dir = root / ".git"
    if not git_dir.is_dir() or git_dir.is_symlink():
        return {"commit": "unavailable_static", "working_tree_status": "not_evaluated_static"}
    try:
        head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
    except OSError:
        return {"commit": "unavailable_static", "working_tree_status": "not_evaluated_static"}
    if head.startswith("ref: "):
        ref = head.removeprefix("ref: ").strip()
        if not ref.startswith("refs/") or ".." in ref:
            return {"commit": "unavailable_static", "working_tree_status": "not_evaluated_static"}
        try:
            commit = (git_dir / ref).read_text(encoding="utf-8").strip()
        except OSError:
            commit = "unavailable_static"
    else:
        commit = head
    if not re.fullmatch(r"[0-9a-f]{40,64}", commit):
        commit = "unavailable_static"
    return {"commit": commit, "working_tree_status": "not_evaluated_static"}


def _validate_source_profile(profile: Mapping[str, Any]) -> None:
    if not _REQUIRED_PROFILE_FIELDS.issubset(profile):
        raise ValueError("source profile is missing required fields")
    if profile.get("schema_version") != UNKNOWN_PROFILE_SCHEMA_VERSION:
        raise ValueError("source profile schema_version is unsupported")
    if profile.get("report_kind") != REPORT_KIND_UNKNOWN_REPO_PROFILE:
        raise ValueError("source profile report_kind is unsupported")
    if profile.get("mode") != "plan_only" or profile.get("execution_permitted") is not False:
        raise ValueError("source profile does not satisfy the read-only contract")
    repo_scope = profile.get("repo_scope")
    risk = profile.get("risk")
    redaction = profile.get("redaction")
    if not isinstance(repo_scope, Mapping) or not isinstance(risk, Mapping) or not isinstance(redaction, Mapping):
        raise ValueError("source profile has invalid required structure")
    repository_identity = repo_scope.get("repository_identity")
    if not isinstance(repository_identity, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", repository_identity):
        raise ValueError("source profile repository identity is invalid")
    if risk.get("tier") not in {"T0", "T1", "T2", "T3", "T4", "T5"}:
        raise ValueError("source profile risk tier is invalid")
    if redaction.get("raw_host_paths_redacted") is not True or redaction.get("secret_like_values_redacted") is not True:
        raise ValueError("source profile redaction contract is invalid")


def _normalise_candidate(
    *,
    phase: str,
    kind: str,
    cwd: str,
    argv: Sequence[str],
    env_allowlist: Sequence[str],
    shell: bool,
    network_policy: str,
) -> dict[str, Any]:
    if phase not in _PHASES:
        raise ValueError("candidate phase must be phase2_install_probe or phase3_runtime_probe")
    if not isinstance(kind, str) or not _SAFE_KIND.fullmatch(kind) or _contains_secret_like(kind):
        raise ValueError("candidate kind is not a safe normalized label")
    if shell:
        raise ValueError("shell candidates are not draftable")
    if network_policy != "none":
        raise ValueError("network-enabled candidates are not draftable")
    if not isinstance(cwd, str) or not (cwd == "/workspace" or cwd.startswith("/workspace/")):
        raise ValueError("candidate cwd must be a logical /workspace path")
    if ".." in Path(cwd).parts or _contains_secret_like(cwd):
        raise ValueError("candidate cwd is unsafe")
    if not argv or not all(isinstance(item, str) and item for item in argv):
        raise ValueError("candidate argv must be a non-empty string array")
    if argv[0].lower() in _SHELL_PROGRAMS or any(item in {"-c", "/c", "-command"} for item in argv):
        raise ValueError("shell argv candidates are not draftable")
    for item in argv:
        if _contains_secret_like(item):
            raise ValueError("candidate argv contains a secret-like value")
        if item.startswith("/") and not item.startswith("/workspace/"):
            raise ValueError("candidate argv contains a non-sandbox absolute path")
    normalized_env = sorted(dict.fromkeys(env_allowlist))
    if not all(isinstance(item, str) and _SAFE_ENV.fullmatch(item) for item in normalized_env):
        raise ValueError("candidate env_allowlist contains an invalid name")
    return {
        "phase": phase,
        "kind": kind,
        "cwd": cwd,
        "argv": list(argv),
        "env_allowlist": normalized_env,
        "shell": False,
    }


def _candidate_key_material(
    *,
    repository_identity: str,
    commit: str,
    source_risk_tier: str,
    candidate: Mapping[str, Any],
    network_policy: str,
    image_policy: Mapping[str, str],
    behavior_policy: Mapping[str, str],
) -> dict[str, Any]:
    return {
        "repository_identity": repository_identity,
        "commit": commit,
        "source_risk_tier": source_risk_tier,
        "phase": candidate["phase"],
        "kind": candidate["kind"],
        "cwd": candidate["cwd"],
        "argv": candidate["argv"],
        "env_allowlist": candidate["env_allowlist"],
        "shell": candidate["shell"],
        "network_policy": network_policy,
        "image_policy": dict(image_policy),
        "behavior_policy_schema_version": behavior_policy["schema_version"],
        "behavior_policy_report_kind": behavior_policy["report_kind"],
    }


def validate_unknown_repo_approval_draft(report: Mapping[str, Any]) -> None:
    """Fail closed for unsupported versions, missing fields, and unsafe draft state."""
    if set(report) != _REQUIRED_DRAFT_FIELDS:
        raise ValueError("approval draft schema mismatch or unexpected field")
    if report.get("schema_version") != APPROVAL_DRAFT_SCHEMA_VERSION:
        raise ValueError("approval draft schema_version is unsupported")
    if report.get("report_kind") != REPORT_KIND_APPROVAL_DRAFT:
        raise ValueError("approval draft report_kind is unsupported")
    if report.get("status") != APPROVAL_DRAFT_STATUS or report.get("approval_status") != APPROVAL_DRAFT_STATUS:
        raise ValueError("approval draft status is invalid")
    if report.get("approved") is not False or report.get("execution_permitted") is not False:
        raise ValueError("approval draft must never authorize execution")
    if report.get("source_risk_tier") not in {"T0", "T1", "T2", "T3", "T4", "T5"}:
        raise ValueError("approval draft risk tier is invalid")
    if report.get("tool") != "repo-health-doctor" or not isinstance(report.get("version"), str):
        raise ValueError("approval draft tool metadata is invalid")
    repo_scope = report.get("repo_scope")
    if not isinstance(repo_scope, Mapping) or set(repo_scope) != {"repository_identity", "commit", "working_tree_status", "path"} or repo_scope.get("path") != "<repo>":
        raise ValueError("approval draft repo scope is invalid")
    if not all(isinstance(repo_scope.get(field), str) for field in ("repository_identity", "commit", "working_tree_status")):
        raise ValueError("approval draft repo scope is invalid")
    source = report.get("source_profile_report")
    if not isinstance(source, Mapping) or set(source) != {"schema_version", "report_kind", "repository_identity", "profile_reference"}:
        raise ValueError("approval draft source profile reference is invalid")
    if source.get("schema_version") != UNKNOWN_PROFILE_SCHEMA_VERSION or source.get("report_kind") != REPORT_KIND_UNKNOWN_REPO_PROFILE:
        raise ValueError("approval draft source profile reference is unsupported")
    if source.get("repository_identity") != repo_scope["repository_identity"] or not isinstance(source.get("profile_reference"), str):
        raise ValueError("approval draft source profile reference is invalid")
    constraints = report.get("execution_constraints")
    if not isinstance(constraints, Mapping) or set(constraints) != {"network_policy", "shell_allowed", "docker_used", "image_pull_performed", "image_policy"}:
        raise ValueError("approval draft execution constraints are invalid")
    if constraints.get("network_policy") != "none" or constraints.get("shell_allowed") is not False or constraints.get("docker_used") is not False or constraints.get("image_pull_performed") is not False:
        raise ValueError("approval draft network policy must remain none")
    image_policy = constraints.get("image_policy")
    behavior_policy = report.get("behavior_policy")
    for placeholder, kind in ((image_policy, "sandbox_image_lock"), (behavior_policy, "sandbox_command_behavior_policy")):
        if not isinstance(placeholder, Mapping) or set(placeholder) != {"schema_version", "report_kind", "status"}:
            raise ValueError("approval draft policy placeholder is invalid")
        if placeholder.get("schema_version") != "unconfigured" or placeholder.get("report_kind") != kind or placeholder.get("status") != "placeholder_not_validated":
            raise ValueError("approval draft policy placeholder is invalid")
    redaction = report.get("redaction")
    if not isinstance(redaction, Mapping) or set(redaction) != {"raw_host_paths_redacted", "secret_like_values_redacted"}:
        raise ValueError("approval draft redaction contract is invalid")
    if redaction.get("raw_host_paths_redacted") is not True or redaction.get("secret_like_values_redacted") is not True:
        raise ValueError("approval draft redaction contract is invalid")
    for field in ("reasons", "blockers", "human_review_requirements", "promotion_requirements", "limitations", "residual_risks"):
        if not isinstance(report.get(field), list) or not all(isinstance(item, str) for item in report[field]):
            raise ValueError("approval draft list field is invalid")
    candidate = report.get("candidate")
    has_candidate = report.get("live_candidate_generated") is True
    if has_candidate != isinstance(candidate, Mapping):
        raise ValueError("approval draft candidate state is inconsistent")
    if has_candidate:
        if report.get("source_risk_tier") in {"T4", "T5"}:
            raise ValueError("T4/T5 drafts cannot contain a live candidate")
        if not isinstance(report.get("candidate_key"), str) or report["candidate_key"] != report.get("exact_match_key"):
            raise ValueError("approval draft exact-match key is invalid")
        if set(candidate) != {"phase", "kind", "cwd", "argv", "env_allowlist", "shell"}:
            raise ValueError("approval draft candidate schema mismatch")
        _normalise_candidate(
            phase=candidate.get("phase"),
            kind=candidate.get("kind"),
            cwd=candidate.get("cwd"),
            argv=candidate.get("argv"),
            env_allowlist=candidate.get("env_allowlist"),
            shell=candidate.get("shell"),
            network_policy=constraints["network_policy"],
        )
    elif report.get("candidate_key") is not None or report.get("exact_match_key") is not None:
        raise ValueError("approval draft without a candidate cannot carry a match key")


def generate_unknown_repo_approval_draft(
    repo_path: str | Path,
    *,
    phase: str | None = None,
    kind: str | None = None,
    cwd: str | None = None,
    argv: Sequence[str] = (),
    env_allowlist: Sequence[str] = (),
    shell: bool = False,
    network_policy: str = "none",
    source_profile: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Generate a non-executable review report for an unknown-repository candidate."""
    root = Path(repo_path).resolve()
    profile = dict(source_profile) if source_profile is not None else profile_unknown_repo(root)
    _validate_source_profile(profile)
    risk = profile["risk"]
    assert isinstance(risk, Mapping)
    tier = str(risk["tier"])
    metadata = _read_static_git_metadata(root)
    repo_scope = {
        "repository_identity": profile["repo_scope"]["repository_identity"],
        "commit": metadata["commit"],
        "working_tree_status": metadata["working_tree_status"],
        "path": "<repo>",
    }
    image_policy = {
        "schema_version": "unconfigured",
        "report_kind": "sandbox_image_lock",
        "status": "placeholder_not_validated",
    }
    behavior_policy = {
        "schema_version": "unconfigured",
        "report_kind": "sandbox_command_behavior_policy",
        "status": "placeholder_not_validated",
    }
    supplied = any(value is not None for value in (phase, kind, cwd)) or bool(argv) or bool(env_allowlist) or shell or network_policy != "none"
    if shell:
        raise ValueError("shell candidates are not draftable")
    if network_policy != "none":
        raise ValueError("network-enabled candidates are not draftable")
    if supplied and (phase is None or kind is None or cwd is None or not argv):
        raise ValueError("candidate phase, kind, cwd, and argv must be supplied together")

    candidate: dict[str, Any] | None = None
    blockers: list[str] = [
        "approval_draft_is_not_an_approval_file",
        "human_created_approval_file_required_for_any_future_execution",
        "behavior_policy_not_implemented",
        "digest_pinned_image_policy_not_configured",
        "unknown_repo_live_execution_not_implemented",
    ]
    reasons = list(risk.get("reasons", []))
    if tier == "T2":
        reasons.append("phase1_fetch_and_phase1_5_rescan_required_before_any_promotion")
    if tier == "T3":
        reasons.append("needs_review_and_stronger_isolation_required")
    if tier in {"T4", "T5"}:
        blockers.append("dedicated_vm_or_specialist_review_required")
        reasons.append("live_candidate_not_generated_for_high_risk_tier")
    elif supplied:
        assert phase is not None and kind is not None and cwd is not None
        candidate = _normalise_candidate(
            phase=phase,
            kind=kind,
            cwd=cwd,
            argv=argv,
            env_allowlist=env_allowlist,
            shell=shell,
            network_policy=network_policy,
        )
        if tier == "T0" and not candidate["kind"].startswith("harmless_"):
            raise ValueError("T0 candidates must use a harmless_ kind or remain candidate-free")
    else:
        blockers.append("candidate_not_supplied")

    candidate_key: str | None = None
    if candidate is not None:
        candidate_key = _canonical_fingerprint(
            _candidate_key_material(
                repository_identity=repo_scope["repository_identity"],
                commit=repo_scope["commit"],
                source_risk_tier=tier,
                candidate=candidate,
                network_policy="none",
                image_policy=image_policy,
                behavior_policy=behavior_policy,
            )
        )
    report = {
        "tool": "repo-health-doctor",
        "version": TOOL_VERSION,
        "schema_version": APPROVAL_DRAFT_SCHEMA_VERSION,
        "report_kind": REPORT_KIND_APPROVAL_DRAFT,
        "status": APPROVAL_DRAFT_STATUS,
        "approval_status": APPROVAL_DRAFT_STATUS,
        "approved": False,
        "execution_permitted": False,
        "repo_scope": repo_scope,
        "source_profile_report": {
            "schema_version": profile["schema_version"],
            "report_kind": profile["report_kind"],
            "repository_identity": repo_scope["repository_identity"],
            "profile_reference": _fingerprint(json.dumps(profile, sort_keys=True)),
        },
        "source_risk_tier": tier,
        "candidate": candidate,
        "candidate_key": candidate_key,
        "exact_match_key": candidate_key,
        "live_candidate_generated": candidate is not None,
        "execution_constraints": {
            "network_policy": "none",
            "shell_allowed": False,
            "docker_used": False,
            "image_pull_performed": False,
            "image_policy": image_policy,
        },
        "behavior_policy": behavior_policy,
        "reasons": sorted(dict.fromkeys(str(item) for item in reasons)),
        "blockers": sorted(dict.fromkeys(blockers)),
        "human_review_requirements": [
            "review_source_profile_and_risk_tier",
            "review_exact_candidate_key_material",
            "verify_repository_identity_and_commit_again",
            "review_behavior_policy_and_digest_pinned_image_policy_separately",
        ],
        "promotion_requirements": [
            "separate_human_created_approval_file",
            "approved_remains_false_in_this_draft",
            "exact_match_of_phase_kind_cwd_argv_env_shell_network_image_and_behavior_policy",
            "phase2_approval_cannot_authorize_phase3_and_vice_versa",
            "all_existing_sandbox_gates_must_pass_in_a_future_implementation",
        ],
        "limitations": [
            "This report is an approval draft, not an approval file or execution permit.",
            "No Docker, image pull, network access, Phase 1 fetch, Phase 1.5 rescan, Phase 2 live, or Phase 3 live action was performed.",
            "Git metadata is read statically; working tree status is not evaluated.",
        ],
        "residual_risks": [
            "static_profile_not_runtime_safety_proof",
            "candidate_key_does_not_authorize_execution",
            "behavior_policy_and_image_lock_are_placeholders",
        ],
        "redaction": {"raw_host_paths_redacted": True, "secret_like_values_redacted": True},
    }
    report = _redact_value(report, root)
    validate_unknown_repo_approval_draft(report)
    return report
