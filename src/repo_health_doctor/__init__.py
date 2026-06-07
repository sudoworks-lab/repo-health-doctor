"""repo-health-doctor package."""

from .doctor import TOOL_VERSION, diagnose_repo, list_policy_allows, validate_policy

__version__ = TOOL_VERSION

__all__ = ["__version__", "diagnose_repo", "list_policy_allows", "validate_policy"]
