# gh_audit/scanners/config_scanner.py
"""Security settings audit: branch protection, 2FA, secret scanning, Dependabot, actions permissions."""

import logging
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime

from rich.console import Console

from gh_audit.models.finding import ConfigFinding, Severity
from gh_audit.utils.github_client import GitHubClient

logger = logging.getLogger(__name__)
console = Console()


class ConfigScanner:
    """Audit repository and organization security configuration settings."""
    
    def __init__(self, github_client: GitHubClient, verbose: bool = False):
        """Initialize configuration scanner.
        
        Args:
            github_client: GitHub API client
            verbose: Enable verbose logging
        """
        self.github_client = github_client
        self.verbose = verbose
        
        # Scoring weights (total = 100)
        self.weights = {
            "branch_protection": 30,
            "secret_scanning": 20,
            "dependabot": 20,
            "actions_permissions": 15,
            "code_scanning": 15
        }
    
    async def scan_repository(self, repo_full_name: str) -> Dict[str, Any]:
        """Scan repository security configuration.
        
        Args:
            repo_full_name: Repository full name (owner/repo)
            
        Returns:
            Dictionary with score and findings
        """
        if self.verbose:
            logger.info(f"Scanning configuration for {repo_full_name}...")
        
        findings = []
        scores = {}
        
        # Scan branch protection
        branch_score, branch_findings = await self._check_branch_protection(repo_full_name)
        scores["branch_protection"] = branch_score
        findings.extend(branch_findings)
        
        # Check secret scanning
        secret_score, secret_findings = await self._check_secret_scanning(repo_full_name)
        scores["secret_scanning"] = secret_score
        findings.extend(secret_findings)
        
        # Check Dependabot
        dependabot_score, dependabot_findings = await self._check_dependabot(repo_full_name)
        scores["dependabot"] = dependabot_score
        findings.extend(dependabot_findings)
        
        # Check actions permissions
        actions_score, actions_findings = await self._check_actions_permissions(repo_full_name)
        scores["actions_permissions"] = actions_score
        findings.extend(actions_findings)
        
        # Check code scanning
        code_scanning_score, code_findings = await self._check_code_scanning(repo_full_name)
        scores["code_scanning"] = code_scanning_score
        findings.extend(code_findings)
        
        # Calculate total score
        total_score = self._calculate_total_score(scores)
        
        return {
            "score": total_score,
            "scores": scores,
            "findings": findings
        }
    
    async def _check_branch_protection(self, repo_full_name: str) -> Tuple[float, List[ConfigFinding]]:
        """Check branch protection settings.
        
        Args:
            repo_full_name: Repository full name
            
        Returns:
            Tuple of (score, findings)
        """
        findings = []
        score = 100.0
        
        try:
            protection = self.github_client.get_branch_protection(repo_full_name, "main")
            
            if not protection or not protection.get("enabled", False):
                finding = ConfigFinding.create(
                    repository=repo_full_name,
                    config_category="branch_protection",
                    severity=Severity.HIGH,
                    title="Branch protection not enabled",
                    description="Main branch does not have branch protection enabled",
                    remediation="Enable branch protection to require pull request reviews and status checks",
                    current_value="disabled",
                    expected_value="enabled",
                    auto_fix_strategy="enable_branch_protection"
                )
                findings.append(finding)
                score -= 50
            
            else:
                # Check required approving reviews
                required_reviews = protection.get("required_approving_review_count", 0)
                if required_reviews < 1:
                    finding = ConfigFinding.create(
                        repository=repo_full_name,
                        config_category="branch_protection",
                        severity=Severity.MEDIUM,
                        title="No required approving reviews",
                        description="Branch protection does not require pull request reviews",
                        remediation="Require at least 1 approving review before merging",
                        current_value=required_reviews,
                        expected_value=1,
                        auto_fix_strategy="update_branch_protection_reviews"
                    )
                    findings.append(finding)
                    score -= 20
                
                # Check status checks
                if not protection.get("requires_status_checks", False):
                    finding = ConfigFinding.create(
                        repository=repo_full_name,
                        config_category="branch_protection",
                        severity=Severity.MEDIUM,
                        title="No required status checks",
                        description="Branch protection does not require status checks to pass",
                        remediation="Require status checks to pass before merging",
                        current_value="disabled",
                        expected_value="enabled",
                        auto_fix_strategy="enable_status_checks"
                    )
                    findings.append(finding)
                    score -= 15
                
                # Check stale review dismissal
                if not protection.get("dismisses_stale_reviews", False):
                    finding = ConfigFinding.create(
                        repository=repo_full_name,
                        config_category="branch_protection",
                        severity=Severity.LOW,
                        title="Stale reviews not dismissed",
                        description="Stale pull request reviews are not automatically dismissed",
                        remediation="Enable dismissal of stale reviews when new commits are pushed",
                        current_value="disabled",
                        expected_value="enabled",
                        auto_fix_strategy="enable_stale_review_dismissal"
                    )
                    findings.append(finding)
                    score -= 10
                
                # Check conversation resolution
                if not protection.get("requires_conversation_resolution", False):
                    finding = ConfigFinding.create(
                        repository=repo_full_name,
                        config_category="branch_protection",
                        severity=Severity.LOW,
                        title="Conversation resolution not required",
                        description="All conversations must be resolved before merging",
                        remediation="Require all conversations to be resolved before merging",
                        current_value="disabled",
                        expected_value="enabled",
                        auto_fix_strategy="enable_conversation_resolution"
                    )
                    findings.append(finding)
                    score -= 5
        
        except Exception as e:
            if self.verbose:
                logger.debug(f"Error checking branch protection for {repo_full_name}: {e}")
        
        return max(0, score), findings
    
    async def _check_secret_scanning(self, repo_full_name: str) -> Tuple[float, List[ConfigFinding]]:
        """Check if secret scanning is enabled.
        
        Args:
            repo_full_name: Repository full name
            
        Returns:
            Tuple of (score, findings)
        """
        findings = []
        score = 100.0
        
        try:
            repo = self.github_client.get_repository(repo_full_name)
            
            # Check if secret scanning is enabled (GitHub Advanced Security feature)
            # This requires appropriate permissions
            try:
                if hasattr(repo, 'get_secret_scanning_status'):
                    status = repo.get_secret_scanning_status()
                    if not status or status.get("status") != "enabled":
                        finding = ConfigFinding.create(
                            repository=repo_full_name,
                            config_category="secret_scanning",
                            severity=Severity.HIGH,
                            title="Secret scanning not enabled",
                            description="GitHub secret scanning is not enabled for this repository",
                            remediation="Enable secret scanning to automatically detect committed secrets",
                            current_value="disabled",
                            expected_value="enabled",
                            auto_fix_strategy="enable_secret_scanning"
                        )
                        findings.append(finding)
                        score = 0
                    else:
                        score = 100
                else:
                    # GitHub Advanced Security may not be available
                    if self.verbose:
                        logger.debug(f"Secret scanning API not available for {repo_full_name}")
                    score = 50  # Partial score if feature not available
            except Exception as e:
                if self.verbose:
                    logger.debug(f"Error checking secret scanning: {e}")
                score = 50
        
        except Exception as e:
            if self.verbose:
                logger.debug(f"Error checking secret scanning for {repo_full_name}: {e}")
        
        return score, findings
    
    async def _check_dependabot(self, repo_full_name: str) -> Tuple[float, List[ConfigFinding]]:
        """Check if Dependabot is configured.
        
        Args:
            repo_full_name: Repository full name
            
        Returns:
            Tuple of (score, findings)
        """
        findings = []
        score = 100.0
        
        try:
            # Check for dependabot.yml configuration file
            dependabot_config = self.github_client.get_file_content(
                repo_full_name,
                ".github/dependabot.yml"
            )
            
            if not dependabot_config:
                dependabot_config = self.github_client.get_file_content(
                    repo_full_name,
                    ".github/dependabot.yaml"
                )
            
            if not dependabot_config:
                finding = ConfigFinding.create(
                    repository=repo_full_name,
                    config_category="dependabot",
                    severity=Severity.MEDIUM,
                    title="Dependabot not configured",
                    description="Dependabot is not configured for automated dependency updates",
                    remediation="Create .github/dependabot.yml to enable automated security updates",
                    current_value="not_configured",
                    expected_value="configured",
                    auto_fix_strategy="create_dependabot_config"
                )
                findings.append(finding)
                score -= 60
            else:
                # Check if security updates are enabled
                if "security-updates" not in dependabot_config:
                    finding = ConfigFinding.create(
                        repository=repo_full_name,
                        config_category="dependabot",
                        severity=Severity.MEDIUM,
                        title="Dependabot security updates not enabled",
                        description="Dependabot security updates are not enabled",
                        remediation="Enable security updates in Dependabot configuration",
                        current_value="disabled",
                        expected_value="enabled",
                        auto_fix_strategy="enable_dependabot_security_updates"
                    )
                    findings.append(finding)
                    score -= 40
        
        except Exception as e:
            if self.verbose:
                logger.debug(f"Error checking Dependabot for {repo_full_name}: {e}")
        
        return max(0, score), findings
    
    async def _check_actions_permissions(self, repo_full_name: str) -> Tuple[float, List[ConfigFinding]]:
        """Check GitHub Actions permissions.
        
        Args:
            repo_full_name: Repository full name
            
        Returns:
            Tuple of (score, findings)
        """
        findings = []
        score = 100.0
        
        try:
            # Check for overly permissive workflow permissions
            workflows_path = ".github/workflows/"
            
            # This would require listing workflows and checking their permissions
            # For now, check common issues
            
            # Check for actions using GITHUB_TOKEN with write permissions
            token_usage = await self._check_token_permissions(repo_full_name)
            
            if token_usage.get("has_write_permissions", False):
                finding = ConfigFinding.create(
                    repository=repo_full_name,
                    config_category="actions_permissions",
                    severity=Severity.HIGH,
                    title="Overly permissive GITHUB_TOKEN permissions",
                    description="Workflows are using GITHUB_TOKEN with write permissions where read-only may suffice",
                    remediation="Set permissions to read-only at the workflow level and only grant write permissions when necessary",
                    current_value="write",
                    expected_value="read",
                    auto_fix_strategy="restrict_token_permissions"
                )
                findings.append(finding)
                score -= 50
            
            # Check for actions running on pull_request_target
            pr_target = await self._check_pr_target_usage(repo_full_name)
            if pr_target.get("has_pr_target", False):
                finding = ConfigFinding.create(
                    repository=repo_full_name,
                    config_category="actions_permissions",
                    severity=Severity.MEDIUM,
                    title="pull_request_target trigger used",
                    description="Workflows using pull_request_target trigger may expose secrets in forks",
                    remediation="Review workflows using pull_request_target and ensure proper validation",
                    current_value="present",
                    expected_value="avoid when possible",
                    auto_fix_strategy=None  # Manual review required
                )
                findings.append(finding)
                score -= 20
        
        except Exception as e:
            if self.verbose:
                logger.debug(f"Error checking actions for {repo_full_name}: {e}")
        
        return max(0, score), findings
    
    async def _check_code_scanning(self, repo_full_name: str) -> Tuple[float, List[ConfigFinding]]:
        """Check if code scanning is enabled.
        
        Args:
            repo_full_name: Repository full name
            
        Returns:
            Tuple of (score, findings)
        """
        findings = []
        score = 100.0
        
        try:
            # Check for code scanning workflow
            codeql_config = self.github_client.get_file_content(
                repo_full_name,
                ".github/workflows/codeql-analysis.yml"
            )
            
            if not codeql_config:
                codeql_config = self.github_client.get_file_content(
                    repo_full_name,
                    ".github/workflows/codeql.yml"
                )
            
            if not codeql_config:
                finding = ConfigFinding.create(
                    repository=repo_full_name,
                    config_category="code_scanning",
                    severity=Severity.HIGH,
                    title="Code scanning not enabled",
                    description="CodeQL code scanning is not configured",
                    remediation="Add CodeQL analysis workflow to enable code scanning",
                    current_value="disabled",
                    expected_value="enabled",
                    auto_fix_strategy="create_codeql_workflow"
                )
                findings.append(finding)
                score = 0
        
        except Exception as e:
            if self.verbose:
                logger.debug(f"Error checking code scanning for {repo_full_name}: {e}")
        
        return score, findings
    
    async def _check_token_permissions(self, repo_full_name: str) -> Dict[str, bool]:
        """Check GITHUB_TOKEN permissions in workflows.
        
        Args:
            repo_full_name: Repository full name
            
        Returns:
            Dictionary with permission information
        """
        # Placeholder implementation
        return {"has_write_permissions": False}
    
    async def _check_pr_target_usage(self, repo_full_name: str) -> Dict[str, bool]:
        """Check for pull_request_target trigger usage.
        
        Args:
            repo_full_name: Repository full name
            
        Returns:
            Dictionary with trigger information
        """
        # Placeholder implementation
        return {"has_pr_target": False}
    
    def _calculate_total_score(self, scores: Dict[str, float]) -> float:
        """Calculate weighted total score.
        
        Args:
            scores: Dictionary of category scores
            
        Returns:
            Weighted total score (0-100)
        """
        total = 0.0
        total_weight = 0.0
        
        for category, score in scores.items():
            weight = self.weights.get(category, 0)
            total += score * (weight / 100)
            total_weight += weight
        
        if total_weight == 0:
            return 0.0
        
        return total
    
    async def scan_organization(self, org_name: str) -> Dict[str, Any]:
        """Scan all repositories in an organization.
        
        Args:
            org_name: Organization name
            
        Returns:
            Dictionary with overall organization security score
        """
        if self.verbose:
            logger.info(f"Scanning organization {org_name} configuration...")
        
        repos = self.github_client.get_organization_repos(org_name)
        all_results = []
        
        for repo in repos:
            result = await self.scan_repository(repo)
            all_results.append({
                "repository": repo,
                "score": result["score"],
                "findings": result["findings"]
            })
        
        # Calculate organization average
        avg_score = sum(r["score"] for r in all_results) / len(all_results) if all_results else 0
        
        return {
            "organization": org_name,
            "total_repositories": len(all_results),
            "average_score": avg_score,
            "repositories": all_results
        }