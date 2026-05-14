# gh_audit/scanners/__init__.py
"""Scanner module initializer.

This module contains all security scanners for:
- Secret detection (secrets in code, commits, and history)
- Dependency vulnerability scanning (CVE detection)
- Configuration security auditing (branch protection, 2FA, etc.)
"""

from gh_audit.scanners.secret_scanner import SecretScanner
from gh_audit.scanners.dependency_scanner import DependencyScanner
from gh_audit.scanners.config_scanner import ConfigScanner

__all__ = [
    "SecretScanner",
    "DependencyScanner",
    "ConfigScanner"
]