# gh_audit/cli.py
"""Main CLI entry point using Click with comprehensive command-line options."""

import os
import sys
import json
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Tuple
import asyncio

import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from dotenv import load_dotenv

from gh_audit.utils.github_client import GitHubClient
from gh_audit.utils.parallel_processor import ParallelProcessor
from gh_audit.scanners.secret_scanner import SecretScanner
from gh_audit.scanners.dependency_scanner import DependencyScanner
from gh_audit.scanners.config_scanner import ConfigScanner
from gh_audit.fixers.auto_fix import AutoFixer
from gh_audit.reporters.html_reporter import HTMLReporter
from gh_audit.reporters.json_reporter import JSONReporter

# Load environment variables from .env file
load_dotenv()

console = Console()


class CLIState:
    """Manages CLI application state and shared resources."""
    
    def __init__(
        self,
        token: str,
        org: str,
        fix: bool = False,
        format_type: str = "html",
        parallel: int = 5,
        severity: str = "all",
        since: Optional[str] = None,
        interactive: bool = False,
        dry_run: bool = False,
        verbose: bool = False,
        enterprise_url: Optional[str] = None
    ):
        self.token = token
        self.org = org
        self.fix = fix
        self.format_type = format_type
        self.parallel = parallel
        self.severity = severity
        self.since = since
        self.interactive = interactive
        self.dry_run = dry_run
        self.verbose = verbose
        self.enterprise_url = enterprise_url
        self.github_client: Optional[GitHubClient] = None
        self.parallel_processor: Optional[ParallelProcessor] = None
        self.findings: List = []
        self.org_scores: dict = {}


@click.command()
@click.option(
    "--org", "-o",
    required=True,
    help="GitHub organization name to audit"
)
@click.option(
    "--token", "-t",
    help="GitHub personal access token (or set GH_TOKEN env var)"
)
@click.option(
    "--fix", "-f",
    is_flag=True,
    help="Enable auto-fix for security issues (use with caution)"
)
@click.option(
    "--format", "-fmt",
    type=click.Choice(["html", "json", "both"], case_sensitive=False),
    default="html",
    help="Output format: html, json, or both"
)
@click.option(
    "--parallel", "-p",
    default=5,
    help="Number of parallel repository scans (default: 5)"
)
@click.option(
    "--severity", "-s",
    type=click.Choice(["all", "high", "medium", "low"], case_sensitive=False),
    default="all",
    help="Minimum severity level to report"
)
@click.option(
    "--since",
    help="Scan commits since date (YYYY-MM-DD format)"
)
@click.option(
    "--interactive", "-i",
    is_flag=True,
    help="Interactive mode - confirm each fix before applying"
)
@click.option(
    "--dry-run", "-d",
    is_flag=True,
    help="Dry run - show what would be fixed without making changes"
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    help="Enable verbose logging output"
)
@click.option(
    "--enterprise-url",
    help="GitHub Enterprise Server URL (if using GH Enterprise)"
)
@click.version_option(version="1.0.0", prog_name="gh-security-auditor")
def main(
    org: str,
    token: Optional[str],
    fix: bool,
    format: str,
    parallel: int,
    severity: str,
    since: Optional[str],
    interactive: bool,
    dry_run: bool,
    verbose: bool,
    enterprise_url: Optional[str]
):
    """Professional GitHub Security Auditor - Scan, detect, and fix security issues."""
    
    # Validate and get token
    token = token or os.getenv("GH_TOKEN") or os.getenv("GITHUB_TOKEN")
    if not token:
        console.print("[bold red]Error:[/] GitHub token required. Provide --token or set GH_TOKEN env var")
        sys.exit(1)
    
    # Validate since date if provided
    if since:
        try:
            datetime.strptime(since, "%Y-%m-%d")
        except ValueError:
            console.print("[bold red]Error:[/] --since must be in YYYY-MM-DD format")
            sys.exit(1)
    
    # Create state object
    state = CLIState(
        token=token,
        org=org,
        fix=fix,
        format_type=format,
        parallel=parallel,
        severity=severity,
        since=since,
        interactive=interactive,
        dry_run=dry_run,
        verbose=verbose,
        enterprise_url=enterprise_url
    )
    
    # Display banner
    _display_banner()
    
    # Run the audit
    try:
        asyncio.run(_run_audit(state))
    except KeyboardInterrupt:
        console.print("\n[yellow]Audit interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]Fatal error:[/] {str(e)}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


async def _run_audit(state: CLIState):
    """Execute the complete audit workflow."""
    
    # Initialize GitHub client
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("Initializing GitHub client...", total=None)
        state.github_client = GitHubClient(
            token=state.token,
            enterprise_url=state.enterprise_url,
            verbose=state.verbose
        )
        progress.remove_task(task)
    
    # Fetch all repositories in organization
    console.print(f"\n[bold cyan]📊 Auditing organization:[/] {state.org}")
    
    repos = []
    try:
        repos = state.github_client.get_organization_repos(state.org)
        console.print(f"[green]✓ Found {len(repos)} repositories[/green]")
    except Exception as e:
        console.print(f"[bold red]✗ Failed to fetch repositories: {e}[/bold red]")
        raise
    
    if not repos:
        console.print("[yellow]No repositories found in organization[/yellow]")
        return
    
    # Initialize parallel processor
    state.parallel_processor = ParallelProcessor(
        max_concurrent=state.parallel,
        verbose=state.verbose
    )
    
    # Initialize scanners
    secret_scanner = SecretScanner(
        github_client=state.github_client,
        severity=state.severity,
        since=state.since,
        verbose=state.verbose
    )
    
    dependency_scanner = DependencyScanner(
        severity=state.severity,
        verbose=state.verbose
    )
    
    config_scanner = ConfigScanner(
        github_client=state.github_client,
        verbose=state.verbose
    )
    
    # Run scans
    console.print("\n[bold]🔍 Starting security scans...[/bold]\n")
    
    all_findings = []
    org_scores = {}
    
    # Use parallel processing for repositories
    scan_tasks = []
    for repo in repos:
        task_coro = _scan_single_repository(
            repo,
            secret_scanner,
            dependency_scanner,
            config_scanner,
            state
        )
        scan_tasks.append(task_coro)
    
    # Execute parallel scans
    results = await state.parallel_processor.process(scan_tasks)
    
    # Aggregate results
    for repo_name, findings_list, score in results:
        all_findings.extend(findings_list)
        org_scores[repo_name] = score
    
    # Display summary
    _display_summary(all_findings, org_scores, state)
    
    # Auto-fix if enabled
    if state.fix and all_findings:
        await _handle_auto_fix(all_findings, state)
    
    # Generate reports
    await _generate_reports(all_findings, org_scores, state)
    
    console.print("\n[bold green]✅ Audit completed successfully![/bold green]")


async def _scan_single_repository(
    repo_name: str,
    secret_scanner: SecretScanner,
    dependency_scanner: DependencyScanner,
    config_scanner: ConfigScanner,
    state: CLIState
) -> Tuple[str, List, dict]:
    """Scan a single repository with all scanners."""
    
    findings = []
    
    if state.verbose:
        console.print(f"[dim]Scanning: {repo_name}[/dim]")
    
    # Secret scanning
    try:
        secret_findings = await secret_scanner.scan_repository(repo_name)
        findings.extend(secret_findings)
    except Exception as e:
        if state.verbose:
            console.print(f"[red]Secret scan failed for {repo_name}: {e}[/red]")
    
    # Dependency scanning
    try:
        dep_findings = await dependency_scanner.scan_repository(repo_name)
        findings.extend(dep_findings)
    except Exception as e:
        if state.verbose:
            console.print(f"[red]Dependency scan failed for {repo_name}: {e}[/red]")
    
    # Config scanning
    try:
        config_score = await config_scanner.scan_repository(repo_name)
    except Exception as e:
        config_score = {"score": 0, "findings": []}
        if state.verbose:
            console.print(f"[red]Config scan failed for {repo_name}: {e}[/red]")
    
    findings.extend(config_score.get("findings", []))
    
    return (repo_name, findings, config_score.get("score", 0))


def _display_banner():
    """Display application banner."""
    banner = """
    ╔═══════════════════════════════════════════════╗
    ║     GitHub Security Auditor v1.0.0           ║
    ║     Professional Security Scanning Tool      ║
    ╚═══════════════════════════════════════════════╝
    """
    console.print(f"[bold cyan]{banner}[/bold cyan]")


def _display_summary(findings: List, org_scores: dict, state: CLIState):
    """Display scan summary table."""
    
    table = Table(title="Audit Summary", style="bold")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")
    
    table.add_row("Total Findings", str(len(findings)))
    table.add_row("Repositories Scanned", str(len(org_scores)))
    table.add_row("Average Security Score", f"{sum(org_scores.values()) / len(org_scores):.1f}/100")
    table.add_row("Auto-fix Enabled", "✓" if state.fix else "✗")
    table.add_row("Interactive Mode", "✓" if state.interactive else "✗")
    
    console.print(table)
    
    # Show top 5 lowest scored repos
    if org_scores:
        sorted_scores = sorted(org_scores.items(), key=lambda x: x[1])
        console.print("\n[bold yellow]⚠️  Repositories needing attention:[/bold yellow]")
        for repo, score in sorted_scores[:5]:
            console.print(f"  • {repo}: [red]{score}/100[/red]")


async def _handle_auto_fix(findings: List, state: CLIState):
    """Handle auto-fix workflow."""
    
    console.print("\n[bold yellow]🔧 Auto-fix mode enabled[/bold yellow]")
    
    if state.dry_run:
        console.print("[cyan]DRY RUN MODE: No changes will be made[/cyan]")
    
    fixer = AutoFixer(
        github_client=state.github_client,
        interactive=state.interactive,
        dry_run=state.dry_run,
        verbose=state.verbose
    )
    
    await fixer.fix_findings(findings)


async def _generate_reports(findings: List, org_scores: dict, state: CLIState):
    """Generate output reports."""
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    org_name_safe = state.org.replace("/", "_")
    
    if state.format_type in ["html", "both"]:
        html_reporter = HTMLReporter()
        html_path = f"security_audit_{org_name_safe}_{timestamp}.html"
        html_reporter.generate(findings, org_scores, html_path, state.org)
        console.print(f"[green]✓ HTML report generated: {html_path}[/green]")
    
    if state.format_type in ["json", "both"]:
        json_reporter = JSONReporter()
        json_path = f"security_audit_{org_name_safe}_{timestamp}.json"
        json_reporter.generate(findings, org_scores, json_path, state.org)
        console.print(f"[green]✓ JSON report generated: {json_path}[/green]")


if __name__ == "__main__":
    main()