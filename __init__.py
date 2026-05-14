"""GitHub Security Auditor - Automated security scanning for GitHub organizations."""

__version__ = "1.0.0"
__author__ = "GitHub Security Team"

from gh_audit.models.finding import Finding, Severity, FindingType
from gh_audit.scanners.secret_scanner import SecretScanner
from gh_audit.scanners.dependency_scanner import DependencyScanner
from gh_audit.scanners.config_scanner import ConfigAuditor

__all__ = [
    "__version__",
    "Finding",
    "Severity",
    "FindingType",
    "SecretScanner",
    "DependencyScanner",
    "ConfigAuditor",
]