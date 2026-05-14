"""Main CLI entry point for GitHub Security Auditor."""

import os
import sys
import asyncio
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional, List
import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.logging import RichHandler
from dotenv import load_dotenv

from gh_audit.utils.github_client import GitHubClient
from gh_audit.utils.parallel_processor import ParallelProcessor
from gh_audit.scanners.secret_scanner import SecretScanner
from gh_audit.scanners.dependency_scanner import DependencyScanner
from gh_audit.scanners.config_scanner import ConfigAuditor
from gh_audit.fixers.auto_fix import AutoFixer
from gh_audit.reporters.html_reporter import HTMLReporter
from gh_audit.reporters.json_reporter import JSONReporter
from gh_audit.models.finding import AuditReport, Finding

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[RichHandler(rich_tracebacks=True, markup=True)]
)
logger = logging.getLogger(__name__)
console = Console()


class GitHubSecurityAuditor:
    """Main orchestrator for GitHub security auditing."""
    
    def __init__(self, config: dict):
        """
        Initialize the auditor.
        
        Args:
            config: Configuration dictionary from CLI
        """
        self.config = config
        self.github_client = None
        self.parallel_processor = None
        self.findings = []
        
    def setup(self):
        """Setup GitHub client and parallel processor."""
        self.github_client = GitHubClient(
            token=self.config.get('token'),
            base_url=self.config.get('base_url', 'https://api.github.com')
        )
        self.parallel_processor = ParallelProcessor(
            max_workers=self.config.get('parallel', 5)
        )
    
    def run_audit(self) -> AuditReport:
        """Run the complete security audit."""
        console.print("[bold cyan]🔒 GitHub Security Auditor[/bold cyan]")
        console.print(f"[dim]Starting audit at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]\n")
        
        # Parse organizations
        orgs = self._parse_organizations()
        if not orgs:
            raise ValueError("No organizations specified")
        
        console.print(f"[green]📊 Auditing {len(orgs)} organization(s)[/green]\n")
        
        # Collect all repositories
        all_repos = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Fetching repositories...", total=None)
            for org_name in orgs:
                try:
                    repos = self.github_client.get_organization_repos(org_name)
                    for repo in repos:
                        all_repos.append({
                            'org': org_name,
                            'repo': repo,
                            'full_name': repo.full_name
                        })
                    console.print(f"[green]✓ Found {len(repos)} repos in {org_name}[/green]")
                except Exception as e:
                    console.print(f"[red]✗ Failed to fetch repos for {org_name}: {e}[/red]")
            progress.update(task, completed=True)
        
        if not all_repos:
            raise ValueError("No repositories found to scan")
        
        console.print(f"\n[bold]Scanning {len(all_repos)} repositories...[/bold]\n")
        
        # Run scanners
        all_findings = []
        
        # 1. Configuration Audit (fastest, run first)
        console.print("[cyan]🔧 Running configuration audit...[/cyan]")
        config_scanner = ConfigAuditor(self.github_client)
        
        config_findings = self.parallel_processor.process_items(
            all_repos,
            lambda item: config_scanner.scan_repository(item['repo']),
            "Configuration audit",
            show_progress=True
        )
        for findings in config_findings:
            all_findings.extend(findings)
        
        # 2. Secret Scanning (medium)
        console.print("\n[cyan]🔑 Running secret scanning...[/cyan]")
        secret_scanner = SecretScanner(
            self.github_client,
            since_date=self.config.get('since')
        )
        
        secret_findings = self.parallel_processor.process_items(
            all_repos,
            lambda item: secret_scanner.scan_repository(item['repo']),
            "Secret scanning",
            show_progress=True
        )
        for findings in secret_findings:
            all_findings.extend(findings)
        
        # 3. Dependency Scanning (slowest, run last)
        console.print("\n[cyan]📦 Running dependency vulnerability scanning...[/cyan]")
        dep_scanner = DependencyScanner(
            self.github_client,
            severity_filter=self.config.get('severity', 'all')
        )
        
        dep_findings = self.parallel_processor.process_items(
            all_repos,
            lambda item: dep_scanner.scan_repository(item['repo']),
            "Dependency scanning",
            show_progress=True
        )
        for findings in dep_findings:
            all_findings.extend(findings)
        
        # Calculate security score
        security_score = config_scanner.calculate_security_score(all_findings)
        
        # Create report
        report = AuditReport(
            scan_timestamp=datetime.utcnow(),
            organizations=orgs,
            findings=all_findings,
            score=security_score
        )
        
        # Apply fixes if requested
        if self.config.get('fix'):
            console.print("\n[bold yellow]🔧 Applying auto-fixes...[/bold yellow]")
            repo_map = {item['full_name']: item['repo'] for item in all_repos}
            fixer = AutoFixer(
                self.github_client,
                interactive=self.config.get('interactive', False),
                dry_run=self.config.get('dry_run', False)
            )
            fixed_ids = fixer.apply_fixes(all_findings, repo_map)
            report.fixes_applied = fixed_ids
            
            # Recalculate score after fixes
            if fixed_ids:
                remaining_findings = [f for f in all_findings if f.id not in fixed_ids]
                report.score = config_scanner.calculate_security_score(remaining_findings)
        
        return report
    
    def _parse_organizations(self) -> List[str]:
        """Parse organizations from CLI argument or file."""
        orgs = []
        
        if self.config.get('orgs_file'):
            org_file = Path(self.config['orgs_file'])
            if org_file.exists():
                with open(org_file, 'r') as f:
                    orgs = [line.strip() for line in f if line.strip()]
            else:
                raise ValueError(f"Organizations file not found: {org_file}")
        elif self.config.get('org'):
            orgs = [o.strip() for o in self.config['org'].split(',')]
        
        return orgs
    
    def generate_reports(self, report: AuditReport):
        """Generate reports in specified formats."""
        output_base = Path(self.config['output'])
        output_base.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        format_type = self.config.get('format', 'html')
        
        # Generate HTML report
        if format_type in ['html', 'both']:
            html_reporter = HTMLReporter()
            html_path = output_base / f"audit_report_{timestamp}.html"
            html_reporter.generate_report(report, str(html_path))
            console.print(f"[green]✓ HTML report generated: {html_path}[/green]")
        
        # Generate JSON report
        if format_type in ['json', 'both']:
            json_reporter = JSONReporter()
            json_path = output_base / f"audit_report_{timestamp}.json"
            json_reporter.generate_report(report, str(json_path))
            console.print(f"[green]✓ JSON report generated: {json_path}[/green]")
            
            # Generate summary
            summary = json_reporter.generate_summary(report)
            summary_path = output_base / f"executive_summary_{timestamp}.json"
            with open(summary_path, 'w') as f:
                import json
                json.dump(summary, f, indent=2)
            console.print(f"[green]✓ Executive summary generated: {summary_path}[/green]")
    
    def print_summary(self, report: AuditReport):
        """Print summary to console."""
        console.print("\n[bold cyan]📊 Audit Summary[/bold cyan]")
        
        # Create summary table
        table = Table(title="Security Audit Results")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Security Score", f"{report.score}/100")
        table.add_row("Total Findings", str(len(report.findings)))
        table.add_row("Critical Issues", str(report.findings_by_severity.get('critical', 0)))
        table.add_row("High Severity", str(report.findings_by_severity.get('high', 0)))
        table.add_row("Medium Severity", str(report.findings_by_severity.get('medium', 0)))
        table.add_row("Low Severity", str(report.findings_by_severity.get('low', 0)))
        table.add_row("Fixable Issues", str(len(report.fixable_findings)))
        table.add_row("Fixes Applied", str(len(report.fixes_applied)))
        
        console.print(table)
        
        # Show top critical issues
        if report.critical_findings:
            console.print("\n[bold red]🔥 Top Critical Issues:[/bold red]")
            for i, finding in enumerate(report.critical_findings[:5], 1):
                console.print(f"  {i}. {finding.title} - {finding.repository}")
    
    def cleanup(self):
        """Cleanup resources."""
        if self.parallel_processor:
            self.parallel_processor.shutdown()
        if self.github_client:
            self.github_client.close()


@click.command()
@click.option('--org', help='GitHub organization name(s), comma-separated')
@click.option('--orgs-from-file', type=click.Path(exists=True), help='File containing organization names (one per line)')
@click.option('--token', envvar='GH_TOKEN', help='GitHub personal access token')
@click.option('--output', default='./audit-report', help='Output path for reports')
@click.option('--format', type=click.Choice(['html', 'json', 'both']), default='html', help='Report format')
@click.option('--fix', is_flag=True, help='Auto-fix simple security issues')
@click.option('--parallel', default=5, help='Number of concurrent scans')
@click.option('--severity', type=click.Choice(['all', 'critical', 'high', 'medium', 'low']), default='all', help='Minimum severity to report')
@click.option('--since', help='Scan commits since date (YYYY-MM-DD)')
@click.option('--interactive', is_flag=True, help='Ask before applying fixes')
@click.option('--dry-run', is_flag=True, help='Show what would be fixed without applying')
@click.option('--base-url', default='https://api.github.com', help='GitHub API base URL (for GitHub Enterprise)')
@click.option('--verbose', is_flag=True, help='Enable verbose logging')
@click.option('--quiet', is_flag=True, help='Suppress output')
def main(
    org: Optional[str],
    orgs_from_file: Optional[str],
    token: Optional[str],
    output: str,
    format: str,
    fix: bool,
    parallel: int,
    severity: str,
    since: Optional[str],
    interactive: bool,
    dry_run: bool,
    base_url: str,
    verbose: bool,
    quiet: bool
):
    """
    GitHub Security Auditor - Automated security scanning for GitHub organizations.
    
    Examples:
    
    \b
    # Basic audit of an organization
    gh-audit --org mycompany --token ghp_xxx
    
    \b
    # Full audit with auto-fix and HTML report
    gh-audit --org mycompany --fix --format html --output ./reports
    
    \b
    # Scan multiple organizations from file
    gh-audit --orgs-from-file orgs.txt --parallel 10
    
    \b
    # Dry run to see what would be fixed
    gh-audit --org mycompany --fix --dry-run --interactive
    """
    
    # Configure logging
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    elif quiet:
        logging.getLogger().setLevel(logging.ERROR)
    
    # Validate inputs
    if not org and not orgs_from_file:
        console.print("[red]Error: Either --org or --orgs-from-file must be specified[/red]")
        sys.exit(1)
    
    if not token:
        console.print("[red]Error: GitHub token required. Set GH_TOKEN environment variable or use --token[/red]")
        sys.exit(1)
    
    # Prepare configuration
    config = {
        'org': org,
        'orgs_file': orgs_from_file,
        'token': token,
        'output': output,
        'format': format,
        'fix': fix,
        'parallel': parallel,
        'severity': severity,
        'since': since,
        'interactive': interactive,
        'dry_run': dry_run,
        'base_url': base_url,
    }
    
    # Run auditor
    auditor = GitHubSecurityAuditor(config)
    
    try:
        auditor.setup()
        report = auditor.run_audit()
        auditor.generate_reports(report)
        auditor.print_summary(report)
        auditor.cleanup()
        
        # Exit with appropriate code
        if report.critical_findings:
            sys.exit(2)  # Critical findings found
        elif report.findings:
            sys.exit(1)  # Non-critical findings found
        else:
            sys.exit(0)  # No findings
            
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        logger.exception("Fatal error during audit")
        sys.exit(1)


if __name__ == '__main__':
    main()