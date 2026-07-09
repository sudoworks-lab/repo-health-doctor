"""External scanner result validation.

This package validates supplied JSON-compatible scanner result mappings only.
It never installs or runs scanners, contacts a network, starts Docker, calls a
remote API, executes target code, captures observers, or authorizes execution.
"""

from .result_validator import (
    EXTERNAL_SCANNER_RESULT_SCHEMA_VERSION,
    REPORT_KIND_EXTERNAL_SCANNER_RESULT,
    ExternalScannerValidationResult,
    load_external_scanner_result_schema,
    validate_external_scanner_result,
)
from .imported_report_validator import (
    ImportedExternalReportValidationResult,
    validate_imported_external_report,
)
from .plan_validator import (
    EXTERNAL_SCANNER_PLAN_SCHEMA_VERSION,
    PLAN_KIND_EXTERNAL_SCANNER_NO_NETWORK,
    ExternalScannerPlanValidationResult,
    load_external_scanner_plan_schema,
    validate_external_scanner_plan,
)
from .risk_mapper import (
    ExternalScannerRiskMappingResult,
    FiredRiskRule,
    map_external_scanner_risk,
)
from .risk_policy import (
    EXTERNAL_SCANNER_RISK_POLICY_KIND,
    EXTERNAL_SCANNER_RISK_POLICY_SCHEMA_VERSION,
    EXTERNAL_SCANNER_RISK_POLICY_VERSION,
    RISK_RULE_IDS,
    load_external_scanner_risk_policy,
)
from .execution_readiness import (
    ScannerExecutionReadinessResult,
    evaluate_scanner_execution_readiness,
)
from .zizmor_docker import (
    DEFAULT_ZIZMOR_DOCKER_IMAGE,
    DockerCommandResult,
    DockerScannerExecutionPlan,
    ExternalScannerDockerRunResult,
    build_zizmor_docker_execution_plan,
    run_zizmor_in_docker,
)
from .adapters import (
    GITLEAKS_SCANNER_NAME,
    ZIZMOR_STYLE_OUTPUT_KIND,
    ZIZMOR_STYLE_SCANNER_NAME,
    ExternalScannerAdapterCapability,
    ExternalScannerCommandPlan,
    GitleaksAdapter,
    GitleaksCommandResult,
    GitleaksExitInterpretation,
    GitleaksRunResult,
    ZizmorStyleAdapter,
    ZizmorStyleFinding,
    ZizmorStyleParsedOutput,
    build_gitleaks_scan_argv,
    default_gitleaks_adapter,
    default_zizmor_style_adapter,
    interpret_gitleaks_exit_code,
    normalize_gitleaks_json_array,
    run_gitleaks_scan,
)

__all__ = [
    "EXTERNAL_SCANNER_RESULT_SCHEMA_VERSION",
    "EXTERNAL_SCANNER_PLAN_SCHEMA_VERSION",
    "EXTERNAL_SCANNER_RISK_POLICY_KIND",
    "EXTERNAL_SCANNER_RISK_POLICY_SCHEMA_VERSION",
    "EXTERNAL_SCANNER_RISK_POLICY_VERSION",
    "REPORT_KIND_EXTERNAL_SCANNER_RESULT",
    "PLAN_KIND_EXTERNAL_SCANNER_NO_NETWORK",
    "ExternalScannerValidationResult",
    "ExternalScannerRiskMappingResult",
    "ExternalScannerPlanValidationResult",
    "ExternalScannerAdapterCapability",
    "ExternalScannerDockerRunResult",
    "ExternalScannerCommandPlan",
    "DockerCommandResult",
    "DockerScannerExecutionPlan",
    "FiredRiskRule",
    "ImportedExternalReportValidationResult",
    "RISK_RULE_IDS",
    "ScannerExecutionReadinessResult",
    "DEFAULT_ZIZMOR_DOCKER_IMAGE",
    "GITLEAKS_SCANNER_NAME",
    "ZIZMOR_STYLE_OUTPUT_KIND",
    "ZIZMOR_STYLE_SCANNER_NAME",
    "GitleaksAdapter",
    "GitleaksCommandResult",
    "GitleaksExitInterpretation",
    "GitleaksRunResult",
    "ZizmorStyleAdapter",
    "ZizmorStyleFinding",
    "ZizmorStyleParsedOutput",
    "default_zizmor_style_adapter",
    "build_gitleaks_scan_argv",
    "build_zizmor_docker_execution_plan",
    "default_gitleaks_adapter",
    "evaluate_scanner_execution_readiness",
    "interpret_gitleaks_exit_code",
    "load_external_scanner_plan_schema",
    "load_external_scanner_result_schema",
    "load_external_scanner_risk_policy",
    "map_external_scanner_risk",
    "normalize_gitleaks_json_array",
    "validate_external_scanner_plan",
    "validate_external_scanner_result",
    "validate_imported_external_report",
    "run_gitleaks_scan",
    "run_zizmor_in_docker",
]
