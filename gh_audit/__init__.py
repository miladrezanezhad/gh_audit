# gh_audit/__init__.py
"""GitHub Security Auditor - Professional CLI tool for security auditing.

This package provides comprehensive security scanning for GitHub repositories
including secret detection, dependency vulnerability scanning, and security
settings auditing with auto-fix capabilities.
"""

__version__ = "1.0.0"
__author__ = "GH Security Auditor Team"
__license__ = "MIT"

from gh_audit.cli import main

__all__ = ["main"]