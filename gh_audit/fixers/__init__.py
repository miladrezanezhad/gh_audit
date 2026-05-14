# gh_audit/fixers/__init__.py
"""Fixer module initializer.

This module provides auto-fix capabilities for:
- .gitignore updates
- Branch protection rules
- Secret rotation (with manual intervention)
- Dependency updates (version bumps)
"""

from gh_audit.fixers.auto_fix import AutoFixer

__all__ = [
    "AutoFixer"
]