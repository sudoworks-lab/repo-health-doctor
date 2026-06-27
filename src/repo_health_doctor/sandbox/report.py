from __future__ import annotations

import json


def format_sandbox_json(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"


def format_unknown_repo_profile_json(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"


def format_unknown_repo_approval_draft_json(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"


def format_sandbox_run_json(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"


def format_sandbox_run_text(report: dict) -> str:
    lines = [
        f"Repo Health Doctor Sandbox-Run: {report['result']['status'].upper()}",
        f"Schema: {report['schema_version']}",
        f"Experimental: {str(report['experimental']).lower()}",
        f"Approval matched: {str(report['approval']['matched']).lower()}",
        f"Profile: {report['sandbox_profile']['name']}",
        f"Docker image: {report['docker']['image']}",
        f"Docker invoked: {str(report['docker']['docker_invoked']).lower()}",
        f"Exit code: {report['result']['exit_code']}",
        "",
        "Refusal reasons:",
        *[f"- {item}" for item in report["approval"]["refusal_reasons"]],
        "",
        "Workspace diff:",
        f"- Created: {report['workspace_diff']['created_count']}",
        f"- Modified: {report['workspace_diff']['modified_count']}",
        f"- Deleted: {report['workspace_diff']['deleted_count']}",
        "",
        "Safety statement:",
        f"- {report['safety_statement']}",
        "",
        "Next actions:",
        *[f"- {item}" for item in report["next_actions"]],
    ]
    return "\n".join(lines).rstrip() + "\n"


def format_sandbox_run_markdown(report: dict) -> str:
    return "\n".join(
        [
            "# Repo Health Doctor Sandbox-Run",
            "",
            f"- Status: `{report['result']['status']}`",
            f"- Schema Version: `{report['schema_version']}`",
            f"- Experimental: `{str(report['experimental']).lower()}`",
            f"- Approval Matched: `{str(report['approval']['matched']).lower()}`",
            f"- Profile: `{report['sandbox_profile']['name']}`",
            f"- Docker Image: `{report['docker']['image']}`",
            f"- Docker Invoked: `{str(report['docker']['docker_invoked']).lower()}`",
            "",
            "## Refusal Reasons",
            "",
            *[f"- `{item}`" for item in report["approval"]["refusal_reasons"]],
            "",
            "## Safety Statement",
            "",
            report["safety_statement"],
            "",
            "## Next Actions",
            "",
            *[f"- {item}" for item in report["next_actions"]],
            "",
        ]
    )


def format_unknown_repo_approval_draft_text(report: dict) -> str:
    candidate = report["candidate"]
    candidate_summary = "not generated"
    if candidate is not None:
        candidate_summary = f"{candidate['phase']} / {candidate['kind']}"
    lines = [
        "Repo Health Doctor Unknown Repository Approval Draft",
        f"Schema: {report['schema_version']}",
        f"Status: {report['status']}",
        f"Risk Tier: {report['source_risk_tier']}",
        f"Candidate: {candidate_summary}",
        f"Approved: {report['approved']}",
        f"Execution Permitted: {report['execution_permitted']}",
        "",
        "Blockers:",
        *[f"- {item}" for item in report["blockers"]],
        "",
        "Limitations:",
        *[f"- {item}" for item in report["limitations"]],
    ]
    return "\n".join(lines).rstrip() + "\n"


def format_unknown_repo_approval_draft_markdown(report: dict) -> str:
    candidate = report["candidate"]
    candidate_summary = "`not generated`"
    if candidate is not None:
        candidate_summary = f"`{candidate['phase']}` / `{candidate['kind']}`"
    return "\n".join(
        [
            "# Repo Health Doctor Unknown Repository Approval Draft",
            "",
            f"- Schema Version: `{report['schema_version']}`",
            f"- Status: `{report['status']}`",
            f"- Risk Tier: `{report['source_risk_tier']}`",
            f"- Candidate: {candidate_summary}",
            f"- Approved: `{report['approved']}`",
            f"- Execution Permitted: `{report['execution_permitted']}`",
            "",
            "## Blockers",
            "",
            *[f"- `{item}`" for item in report["blockers"]],
            "",
            "## Limitations",
            "",
            *[f"- {item}" for item in report["limitations"]],
            "",
        ]
    )


def format_unknown_repo_profile_text(report: dict) -> str:
    profile = report["profile"]
    risk = report["risk"]
    lines = [
        f"Repo Health Doctor Unknown Repository Profile: {report['overall_status'].upper()}",
        f"Target: {report['repo_path']}",
        f"Schema: {report['schema_version']}",
        f"Mode: {report['mode']}",
        f"Risk Tier: {risk['tier']}",
        f"Disposition: {risk['disposition']}",
        f"Execution Permitted: {report['execution_permitted']}",
        f"Approval Status: {report['approval_status']}",
        "",
        "Profile:",
        f"- Package Managers: {', '.join(profile['package_managers']) or 'none'}",
        f"- Manifests: {len(profile['manifest_files'])}",
        f"- Package Scripts: {len(profile['package_scripts'])}",
        f"- Lifecycle Scripts: {len(profile['lifecycle_scripts'])}",
        f"- Direct URL Dependencies: {profile['dependency_sources']['direct_url_count']}",
        f"- VCS Dependencies: {profile['dependency_sources']['vcs_count']}",
        f"- Native Binaries: {profile['native_binaries']['count']}",
        f"- Symlink Risks: {profile['symlink_risks']['count']}",
        f"- Network References: {profile['network_related_references']['count']}",
        f"- Obfuscation Indicators: {profile['obfuscation_indicators']['count']}",
        "",
        "Limitations:",
    ]
    lines.extend(f"- {item}" for item in report["limitations"])
    return "\n".join(lines).rstrip() + "\n"


def format_unknown_repo_profile_markdown(report: dict) -> str:
    profile = report["profile"]
    risk = report["risk"]
    return "\n".join(
        [
            "# Repo Health Doctor Unknown Repository Profile",
            "",
            f"- Target: `{report['repo_path']}`",
            f"- Schema Version: `{report['schema_version']}`",
            f"- Mode: `{report['mode']}`",
            f"- Risk Tier: `{risk['tier']}`",
            f"- Disposition: `{risk['disposition']}`",
            f"- Execution Permitted: `{report['execution_permitted']}`",
            f"- Approval Status: `{report['approval_status']}`",
            "",
            "## Profile Summary",
            "",
            "| Package managers | Manifests | Scripts | Lifecycle scripts |",
            "| --- | --- | --- | --- |",
            f"| {len(profile['package_managers'])} | {len(profile['manifest_files'])} | {len(profile['package_scripts'])} | {len(profile['lifecycle_scripts'])} |",
            "",
            "## Risk Reasons",
            "",
            *[f"- `{reason}`" for reason in risk["reasons"]],
            "",
            "## Limitations",
            "",
            *[f"- {item}" for item in report["limitations"]],
            "",
        ]
    )


def format_sandbox_text(report: dict) -> str:
    dynamic_evidence = report["sandbox"]["dynamic_evidence"]
    lines = [
        f"Repo Health Doctor Sandbox: {report['overall_status'].upper()}",
        f"Target: {report['repo_path']}",
        f"Schema: {report['schema_version']}",
        f"Mode: {report['execution_plan']['mode']}",
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
        lines.append(
            f"- [{check['status'].upper()}] {check['id']}: {check['summary']} "
            f"(detail={check['severity_detail']}, confidence={check['confidence']})"
        )
        if check["limitations"]:
            lines.append(f"    limitations: {', '.join(check['limitations'])}")
    lines.extend(
        [
        "",
        "Execution Plan:",
        f"- Detected Languages: {', '.join(report['execution_plan']['detected_languages']) or 'none'}",
        f"- Command Candidates: {len(report['execution_plan']['commands'])}",
        f"- Skipped Commands: {len(report['execution_plan']['skipped_commands'])}",
        f"- Phase Entries: {len(report['phase_plan'])}",
        f"- Docker Spec Argv Count: {len(report['sandbox']['docker_spec']['argv'])}",
        f"- Workspace Materialization: {report['sandbox']['disposable_workspace']['materialization_status']}",
        f"- Workspace Cleanup: {report['sandbox']['disposable_workspace']['cleanup_status']}",
        f"- Observation Mode: {report['sandbox']['observation_mode']}",
        f"- Dynamic Evidence Confidence: {dynamic_evidence['confidence']}",
        f"- Dynamic Degraded Reasons: {len(dynamic_evidence['degraded_reasons'])}",
        f"- Docker Preflight: {report['sandbox']['preflight']['status']}",
        f"- Phase 1 Fetch: {report['sandbox']['phase1_fetch']['status']}",
        f"- Phase 1.5 Rescan: {report['sandbox']['phase1_5_rescan']['status']}",
        f"- Phase 2 Install Probes: {report['sandbox']['phase2_install_probes']['status']}",
        f"- Phase 3 Runtime Probes: {report['sandbox']['phase3_runtime_probes']['status']}",
        "",
        "Residual Risks:",
    ]
    )
    for risk in report["residual_risks"]:
        lines.append(f"- {risk}")
    return "\n".join(lines).rstrip() + "\n"


def format_sandbox_markdown(report: dict) -> str:
    dynamic_evidence = report["sandbox"]["dynamic_evidence"]
    lines = [
        "# Repo Health Doctor Sandbox Report",
        "",
        f"- Target Repo Path: `{report['repo_path']}`",
        f"- Overall Status: `{report['overall_status'].upper()}`",
        f"- Schema Version: `{report['schema_version']}`",
        f"- Execution Mode: `{report['execution_plan']['mode']}`",
        "",
        "## Summary Counts",
        "",
        "| PASS | WARN | BLOCK |",
        "| --- | --- | --- |",
        f"| {report['summary']['pass']} | {report['summary']['warn']} | {report['summary']['block']} |",
        "",
        "## Checks",
        "",
        "| Status | ID | Detail | Confidence | Summary |",
        "| --- | --- | --- | --- | --- |",
    ]
    for check in report["checks"]:
        lines.append(
            f"| `{check['status'].upper()}` | `{check['id']}` | `{check['severity_detail']}` | "
            f"`{check['confidence']}` | {check['summary']} |"
        )
    lines.extend(
        [
            "",
            "## Execution Plan",
            "",
            f"- Detected Languages: {', '.join(f'`{value}`' for value in report['execution_plan']['detected_languages']) or '`none`'}",
            f"- Command Candidates: `{len(report['execution_plan']['commands'])}`",
            f"- Skipped Commands: `{len(report['execution_plan']['skipped_commands'])}`",
            f"- Phase Entries: `{len(report['phase_plan'])}`",
            f"- Docker Spec Argv Count: `{len(report['sandbox']['docker_spec']['argv'])}`",
            f"- Workspace Materialization: `{report['sandbox']['disposable_workspace']['materialization_status']}`",
            f"- Workspace Cleanup: `{report['sandbox']['disposable_workspace']['cleanup_status']}`",
            f"- Observation Mode: `{report['sandbox']['observation_mode']}`",
            f"- Dynamic Evidence Confidence: `{dynamic_evidence['confidence']}`",
            f"- Dynamic Degraded Reasons: `{len(dynamic_evidence['degraded_reasons'])}`",
            f"- Docker Preflight: `{report['sandbox']['preflight']['status']}`",
            f"- Phase 1 Fetch: `{report['sandbox']['phase1_fetch']['status']}`",
            f"- Phase 1.5 Rescan: `{report['sandbox']['phase1_5_rescan']['status']}`",
            f"- Phase 2 Install Probes: `{report['sandbox']['phase2_install_probes']['status']}`",
            f"- Phase 3 Runtime Probes: `{report['sandbox']['phase3_runtime_probes']['status']}`",
            "",
            "## Residual Risks",
            "",
        ]
    )
    for risk in report["residual_risks"]:
        lines.append(f"- `{risk}`")
    return "\n".join(lines).rstrip() + "\n"
