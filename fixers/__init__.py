"""Auto-fix modules for GitHub Security Auditor."""

from gh_audit.fixers.auto_fix import AutoFixer
from gh_audit.fixers.fix_strategies import FixStrategies

__all__ = ["AutoFixer", "FixStrategies"]