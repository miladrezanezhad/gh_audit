"""Auto-fix capabilities for security issues."""

from typing import List, Optional, Callable, Dict, Any
from rich.console import Console
from rich.prompt import Confirm
import logging

from gh_audit.models.finding import Finding, FindingType
from gh_audit.fixers.fix_strategies import FixStrategies
from gh_audit.utils.github_client import GitHubClient

logger = logging.getLogger(__name__)
console = Console()


class AutoFixer:
    """Handle automatic fixing of security issues."""
    
    def __init__(
        self,
        github_client: GitHubClient,
        interactive: bool = False,
        dry_run: bool = False
    ):
        """
        Initialize auto-fixer.
        
        Args:
            github_client: GitHub client instance
            interactive: Whether to ask before applying fixes
            dry_run: Whether to simulate fixes without applying
        """
        self.github_client = github_client
        self.interactive = interactive
        self.dry_run = dry_run
        self.fix_strategies = FixStrategies(github_client)
        
        # Map finding types to fix strategies
        self.strategy_map = {
            FindingType.SECRET: self.fix_strategies.fix_secret_exposure,
            FindingType.VULNERABILITY: self.fix_strategies.fix_vulnerable_dependency,
            FindingType.CONFIG_ISSUE: self.fix_strategies.fix_configuration_issue,
            FindingType.POLICY_VIOLATION: self.fix_strategies.fix_policy_violation,
        }
    
    def apply_fixes(
        self,
        findings: List[Finding],
        repo_map: Dict[str, Any]  # Maps repo full name to repository object
    ) -> List[str]:
        """
        Apply fixes for all fixable findings.
        
        Args:
            findings: List of findings to fix
            repo_map: Mapping of repository full names to repository objects
            
        Returns:
            List of fix IDs that were applied
        """
        fixed_findings = []
        
        # Group findings by fixability and type
        fixable_findings = [f for f in findings if f.fixable]
        
        if not fixable_findings:
            console.print("[yellow]No fixable findings found.[/yellow]")
            return fixed_findings
        
        console.print(f"\n[bold cyan]Found {len(fixable_findings)} fixable issues[/bold cyan]\n")
        
        for finding in fixable_findings:
            # Get repository object
            repo = repo_map.get(finding.repository)
            if not repo:
                logger.warning(f"Repository {finding.repository} not found for fixing")
                continue
            
            # Apply fix
            applied = self._apply_fix(finding, repo)
            if applied:
                fixed_findings.append(finding.id)
        
        return fixed_findings
    
    def _apply_fix(self, finding: Finding, repo: Any) -> bool:
        """
        Apply fix for a single finding.
        
        Args:
            finding: Finding to fix
            repo: GitHub repository object
            
        Returns:
            True if fix was applied successfully
        """
        # Check if we should apply this fix
        if not self._should_apply_fix(finding):
            return False
        
        # Get the fix strategy
        fix_func = self.strategy_map.get(finding.type)
        if not fix_func:
            logger.warning(f"No fix strategy for finding type {finding.type}")
            return False
        
        # Apply the fix
        if self.dry_run:
            console.print(f"[yellow][DRY RUN] Would fix: {finding.title}[/yellow]")
            return True
        
        try:
            console.print(f"[green]Applying fix for: {finding.title}[/green]")
            success = fix_func(finding, repo)
            
            if success:
                console.print(f"[bold green]✓ Fixed: {finding.title}[/bold green]")
            else:
                console.print(f"[bold red]✗ Failed to fix: {finding.title}[/bold red]")
            
            return success
            
        except Exception as e:
            logger.error(f"Error applying fix for {finding.id}: {e}")
            console.print(f"[red]Error fixing {finding.title}: {e}[/red]")
            return False
    
    def _should_apply_fix(self, finding: Finding) -> bool:
        """Determine if a fix should be applied."""
        if self.interactive:
            return Confirm.ask(
                f"Apply fix for: {finding.title}?",
                default=True
            )
        return True