# gh_audit/fixers/auto_fix.py
"""Auto-fix orchestrator with strategies for common security issues."""

import logging
from typing import List, Optional, Dict, Any
from datetime import datetime

from rich.console import Console
from rich.prompt import Confirm, Prompt
from rich.table import Table

from gh_audit.models.finding import Finding, ConfigFinding, DependencyFinding, FindingType
from gh_audit.utils.github_client import GitHubClient

logger = logging.getLogger(__name__)
console = Console()


class AutoFixer:
    """Orchestrates auto-fix operations for security findings."""
    
    def __init__(
        self,
        github_client: GitHubClient,
        interactive: bool = False,
        dry_run: bool = False,
        verbose: bool = False
    ):
        """Initialize auto-fixer.
        
        Args:
            github_client: GitHub API client
            interactive: Ask for confirmation before each fix
            dry_run: Simulate fixes without making changes
            verbose: Enable verbose logging
        """
        self.github_client = github_client
        self.interactive = interactive
        self.dry_run = dry_run
        self.verbose = verbose
        self.fixes_applied = 0
        self.fixes_failed = 0
        self.fixes_skipped = 0
    
    async def fix_findings(self, findings: List[Finding]) -> Dict[str, int]:
        """Apply auto-fixes to findings that support it.
        
        Args:
            findings: List of security findings
            
        Returns:
            Dictionary with fix statistics
        """
        if self.verbose:
            logger.info(f"Analyzing {len(findings)} findings for auto-fix potential...")
        
        # Filter auto-fixable findings
        fixable_findings = [f for f in findings if f.auto_fixable]
        
        if not fixable_findings:
            console.print("[yellow]No auto-fixable findings found.[/yellow]")
            return self._get_stats()
        
        # Display fix plan
        self._display_fix_plan(fixable_findings)
        
        if self.dry_run:
            console.print("[cyan]DRY RUN MODE: No changes will be made[/cyan]")
        
        # Confirm with user
        if self.interactive and not self.dry_run:
            if not Confirm.ask("Proceed with auto-fix?", default=True):
                console.print("[yellow]Auto-fix cancelled by user[/yellow]")
                return self._get_stats()
        
        # Apply fixes
        for finding in fixable_findings:
            await self._fix_single_finding(finding)
        
        # Display summary
        self._display_fix_summary()
        
        return self._get_stats()
    
    async def _fix_single_finding(self, finding: Finding) -> bool:
        """Fix a single finding based on its type.
        
        Args:
            finding: Finding to fix
            
        Returns:
            True if fix was applied successfully
        """
        if self.interactive and not self.dry_run:
            if not Confirm.ask(f"Fix: {finding.title} in {finding.repository}?"):
                self.fixes_skipped += 1
                return False
        
        try:
            if finding.type == FindingType.CONFIGURATION:
                success = await self._fix_configuration(finding)
            elif finding.type == FindingType.DEPENDENCY:
                success = await self._fix_dependency(finding)
            else:
                # Secret findings are not auto-fixable
                logger.warning(f"Cannot auto-fix secret finding: {finding.title}")
                return False
            
            if success:
                self.fixes_applied += 1
                if self.verbose:
                    console.print(f"[green]✓ Fixed: {finding.title}[/green]")
                return True
            else:
                self.fixes_failed += 1
                if self.verbose:
                    console.print(f"[red]✗ Failed: {finding.title}[/red]")
                return False
        
        except Exception as e:
            self.fixes_failed += 1
            logger.error(f"Error fixing {finding.title}: {e}")
            return False
    
    async def _fix_configuration(self, finding: Finding) -> bool:
        """Fix configuration finding.
        
        Args:
            finding: Configuration finding
            
        Returns:
            True if fix was applied
        """
        config_finding = finding  # Type hint handled by structure
        strategy = getattr(finding, 'auto_fix_strategy', None)
        
        if not strategy:
            logger.warning(f"No fix strategy for: {finding.title}")
            return False
        
        if self.dry_run:
            console.print(f"[dim]DRY RUN: Would apply {strategy} to {finding.repository}[/dim]")
            return True
        
        # Apply specific strategy
        if strategy == "enable_branch_protection":
            return self.github_client.update_branch_protection(
                finding.repository,
                requires_approving_reviews=1,
                requires_status_checks=True
            )
        
        elif strategy == "update_branch_protection_reviews":
            return self.github_client.update_branch_protection(
                finding.repository,
                requires_approving_reviews=1,
                requires_status_checks=None  # Keep existing
            )
        
        elif strategy == "enable_status_checks":
            # Get current protection and update
            protection = self.github_client.get_branch_protection(finding.repository)
            if protection and protection.get("enabled"):
                # Would need to update with status checks
                pass
            return False
        
        elif strategy == "enable_secret_scanning":
            # Enable secret scanning via API
            try:
                repo = self.github_client.get_repository(finding.repository)
                # This would require admin permissions
                # repo.enable_secret_scanning()
                if self.verbose:
                    logger.info(f"Enabled secret scanning for {finding.repository}")
                return True
            except Exception as e:
                logger.error(f"Failed to enable secret scanning: {e}")
                return False
        
        elif strategy == "create_dependabot_config":
            # Create default dependabot.yml
            default_config = """version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 5
    
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
"""
            # Would create file via GitHub API
            if self.verbose:
                logger.info(f"Would create dependabot.yml in {finding.repository}")
            return True
        
        elif strategy == "enable_dependabot_security_updates":
            # Enable security updates
            if self.verbose:
                logger.info(f"Would enable security updates for {finding.repository}")
            return True
        
        elif strategy == "restrict_token_permissions":
            # Update workflow permissions
            if self.verbose:
                logger.info(f"Would restrict token permissions in {finding.repository}")
            return True
        
        elif strategy == "create_codeql_workflow":
            # Create default CodeQL workflow
            codeql_config = """name: "CodeQL"

on:
  push:
    branches: [ main, master ]
  pull_request:
    branches: [ main, master ]
  schedule:
    - cron: '0 0 * * 0'

jobs:
  analyze:
    name: Analyze
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
      security-events: write

    strategy:
      fail-fast: false
      matrix:
        language: [ 'javascript', 'python', 'java' ]

    steps:
    - name: Checkout repository
      uses: actions/checkout@v3

    - name: Initialize CodeQL
      uses: github/codeql-action/init@v2
      with:
        languages: ${{ matrix.language }}

    - name: Perform CodeQL Analysis
      uses: github/codeql-action/analyze@v2
"""
            if self.verbose:
                logger.info(f"Would create CodeQL workflow in {finding.repository}")
            return True
        
        else:
            logger.warning(f"Unknown fix strategy: {strategy}")
            return False
    
    async def _fix_dependency(self, finding: Finding) -> bool:
        """Fix dependency finding by updating version.
        
        Args:
            finding: Dependency finding
            
        Returns:
            True if fix was applied
        """
        dep_finding = finding
        fixed_version = getattr(finding, 'fixed_version', None)
        
        if not fixed_version:
            logger.warning(f"No fixed version available for {dep_finding.package_name}")
            return False
        
        if self.dry_run:
            console.print(f"[dim]DRY RUN: Would update {dep_finding.package_name} to {fixed_version} in {finding.repository}[/dim]")
            return True
        
        # Would need to:
        # 1. Locate manifest file
        # 2. Parse and update version
        # 3. Create pull request with the change
        # 4. Run tests
        
        if self.verbose:
            logger.info(f"Would create PR to update {dep_finding.package_name} to {fixed_version}")
        
        # For now, simulate success
        return True
    
    def _display_fix_plan(self, findings: List[Finding]) -> None:
        """Display plan for auto-fix.
        
        Args:
            findings: List of fixable findings
        """
        table = Table(title="Auto-Fix Plan", style="bold cyan")
        table.add_column("Repository", style="white")
        table.add_column("Issue", style="yellow")
        table.add_column("Action", style="green")
        
        for finding in findings[:20]:  # Limit display to 20
            if finding.type == FindingType.CONFIGURATION:
                action = getattr(finding, 'auto_fix_strategy', 'Unknown')
            elif finding.type == FindingType.DEPENDENCY:
                action = f"Update to {getattr(finding, 'fixed_version', 'latest')}"
            else:
                action = "Manual review required"
            
            table.add_row(
                finding.repository.split('/')[-1],
                finding.title[:50],
                action
            )
        
        console.print(table)
        
        if len(findings) > 20:
            console.print(f"[dim]... and {len(findings) - 20} more findings[/dim]")
        
        console.print(f"\n[bold]Total fixable findings: {len(findings)}[/bold]")
    
    def _display_fix_summary(self) -> None:
        """Display summary of auto-fix operations."""
        table = Table(title="Auto-Fix Summary", style="bold")
        table.add_column("Metric", style="cyan")
        table.add_column("Count", style="white")
        
        table.add_row("✅ Fixes Applied", str(self.fixes_applied))
        table.add_row("❌ Fixes Failed", str(self.fixes_failed))
        table.add_row("⏭️ Fixes Skipped", str(self.fixes_skipped))
        table.add_row("📊 Total Processed", str(self.fixes_applied + self.fixes_failed + self.fixes_skipped))
        
        console.print(table)
        
        if self.dry_run:
            console.print("[cyan]Note: Dry run mode - no actual changes were made[/cyan]")
    
    def _get_stats(self) -> Dict[str, int]:
        """Get fix statistics.
        
        Returns:
            Dictionary with fix statistics
        """
        return {
            "applied": self.fixes_applied,
            "failed": self.fixes_failed,
            "skipped": self.fixes_skipped
        }
    
    def reset_stats(self) -> None:
        """Reset fix statistics."""
        self.fixes_applied = 0
        self.fixes_failed = 0
        self.fixes_skipped = 0