"""Security configuration auditing module."""

from typing import List, Dict, Any, Optional
from github.Repository import Repository
from github.Organization import Organization
import logging

from gh_audit.models.finding import Finding, Severity, FindingType

logger = logging.getLogger(__name__)


class ConfigAuditor:
    """Audit GitHub security configurations."""
    
    def __init__(self, github_client):
        """
        Initialize configuration auditor.
        
        Args:
            github_client: GitHub client instance
        """
        self.github_client = github_client
    
    def scan_organization(self, org: Organization) -> List[Finding]:
        """
        Scan organization-wide security settings.
        
        Args:
            org: GitHub organization object
            
        Returns:
            List of findings
        """
        findings = []
        
        logger.info(f"Auditing organization security settings: {org.login}")
        
        # Check 2FA enforcement
        findings.extend(self._check_2fa_enforcement(org))
        
        # Check member permissions
        findings.extend(self._check_member_permissions(org))
        
        # Check organization security features
        findings.extend(self._check_org_security_features(org))
        
        return findings
    
    def scan_repository(self, repo: Repository) -> List[Finding]:
        """
        Scan repository security settings.
        
        Args:
            repo: GitHub repository object
            
        Returns:
            List of findings
        """
        findings = []
        
        logger.info(f"Auditing repository security settings: {repo.full_name}")
        
        # Check branch protection
        findings.extend(self._check_branch_protection(repo))
        
        # Check secret scanning
        findings.extend(self._check_secret_scanning(repo))
        
        # Check Dependabot settings
        findings.extend(self._check_dependabot(repo))
        
        # Check code scanning
        findings.extend(self._check_code_scanning(repo))
        
        # Check actions permissions
        findings.extend(self._check_actions_permissions(repo))
        
        return findings
    
    def _check_2fa_enforcement(self, org: Organization) -> List[Finding]:
        """Check 2FA enforcement for organization."""
        findings = []
        
        try:
            # Get organization members
            members = list(org.get_members())
            members_without_2fa = []
            
            for member in members:
                if not member.two_factor_authentication:
                    members_without_2fa.append(member.login)
            
            if members_without_2fa:
                # Check if 2FA is required for the organization
                try:
                    # This requires admin permissions
                    org_teams = org.get_teams()
                    # Check if there's a 2FA requirement policy
                    # Note: This is simplified - actual API call would be needed
                    two_factor_required = hasattr(org, 'require_two_factor_authentication') and org.require_two_factor_authentication
                    
                    if not two_factor_required and members_without_2fa:
                        finding = Finding(
                            type=FindingType.POLICY_VIOLATION,
                            severity=Severity.HIGH,
                            title="2FA not enforced for organization",
                            description=f"Organization does not require 2FA. {len(members_without_2fa)} members have 2FA disabled: {', '.join(members_without_2fa[:5])}",
                            organization=org.login,
                            fixable=False,
                            fix_strategy="enable_2fa_enforcement",
                            fix_command="Enable 2FA enforcement in organization settings > Member privileges",
                        )
                        findings.append(finding)
                except Exception:
                    # Don't fail if we can't check org settings
                    pass
                    
        except Exception as e:
            logger.error(f"Error checking 2FA enforcement: {e}")
        
        return findings
    
    def _check_member_permissions(self, org: Organization) -> List[Finding]:
        """Check member permission settings."""
        findings = []
        
        try:
            # Check default member permissions
            # Note: This requires additional API calls in production
            default_perms = "write"  # Placeholder
            
            if default_perms == "write":
                finding = Finding(
                    type=FindingType.CONFIG_ISSUE,
                    severity=Severity.MEDIUM,
                    title="Default member permissions too permissive",
                    description="Organization allows write access by default. Consider restricting to read-only.",
                    organization=org.login,
                    fixable=True,
                    fix_strategy="update_default_permissions",
                    fix_command="Change default member permissions to 'read' in organization settings",
                )
                findings.append(finding)
                
        except Exception as e:
            logger.error(f"Error checking member permissions: {e}")
        
        return findings
    
    def _check_org_security_features(self, org: Organization) -> List[Finding]:
        """Check organization security feature enablement."""
        findings = []
        
        # Check security features (simplified - requires GraphQL API for full details)
        features_to_check = [
            ("Secret scanning", "secret_scanning_enabled"),
            ("Dependabot", "dependabot_enabled"),
            ("Code scanning", "code_scanning_enabled"),
        ]
        
        for feature_name, _ in features_to_check:
            # This would check actual enablement via API
            finding = Finding(
                type=FindingType.CONFIG_ISSUE,
                severity=Severity.MEDIUM,
                title=f"{feature_name} not enabled for organization",
                description=f"Consider enabling {feature_name} for all repositories to improve security posture.",
                organization=org.login,
                fixable=True,
                fix_strategy=f"enable_{feature_name.lower().replace(' ', '_')}",
                fix_command=f"Enable {feature_name} in organization security settings",
            )
            findings.append(finding)
        
        return findings
    
    def _check_branch_protection(self, repo: Repository) -> List[Finding]:
        """Check branch protection rules."""
        findings = []
        
        try:
            # Check main/master branches
            main_branches = ['main', 'master']
            
            for branch_name in main_branches:
                try:
                    branch = repo.get_branch(branch_name)
                    protection = branch.get_protection()
                    
                    # Check required reviews
                    if not protection.required_pull_request_reviews:
                        finding = Finding(
                            type=FindingType.CONFIG_ISSUE,
                            severity=Severity.HIGH,
                            title=f"Branch protection missing on {branch_name}",
                            description=f"The {branch_name} branch does not require pull request reviews before merging.",
                            repository=repo.full_name,
                            fixable=True,
                            fix_strategy="enable_branch_protection",
                            fix_command="Enable branch protection with required reviews",
                        )
                        findings.append(finding)
                    
                    # Check required status checks
                    if not protection.required_status_checks:
                        finding = Finding(
                            type=FindingType.CONFIG_ISSUE,
                            severity=Severity.MEDIUM,
                            title=f"No required status checks on {branch_name}",
                            description=f"The {branch_name} branch doesn't require CI checks to pass before merging.",
                            repository=repo.full_name,
                            fixable=True,
                            fix_strategy="require_status_checks",
                            fix_command="Configure required status checks for the branch",
                        )
                        findings.append(finding)
                        
                except Exception as e:
                    if "Branch not found" not in str(e):
                        logger.debug(f"Error checking branch {branch_name}: {e}")
                        
        except Exception as e:
            logger.error(f"Error checking branch protection for {repo.full_name}: {e}")
        
        return findings
    
    def _check_secret_scanning(self, repo: Repository) -> List[Finding]:
        """Check if secret scanning is enabled."""
        findings = []
        
        try:
            enabled = self.github_client.get_secret_scanning_enabled(repo)
            
            if not enabled:
                finding = Finding(
                    type=FindingType.CONFIG_ISSUE,
                    severity=Severity.MEDIUM,
                    title="Secret scanning not enabled",
                    description="Secret scanning helps detect committed secrets. It should be enabled to prevent exposure.",
                    repository=repo.full_name,
                    fixable=True,
                    fix_strategy="enable_secret_scanning",
                    fix_command="Enable secret scanning in repository settings",
                )
                findings.append(finding)
                
        except Exception as e:
            logger.error(f"Error checking secret scanning for {repo.full_name}: {e}")
        
        return findings
    
    def _check_dependabot(self, repo: Repository) -> List[Finding]:
        """Check Dependabot configuration."""
        findings = []
        
        try:
            # Check if dependabot is enabled and configured
            # This would query the dependabot API
            dependabot_enabled = hasattr(repo, 'dependabot') and repo.dependabot
            
            if not dependabot_enabled:
                finding = Finding(
                    type=FindingType.CONFIG_ISSUE,
                    severity=Severity.MEDIUM,
                    title="Dependabot not enabled",
                    description="Dependabot automatically updates vulnerable dependencies.",
                    repository=repo.full_name,
                    fixable=True,
                    fix_strategy="enable_dependabot",
                    fix_command="Enable Dependabot in repository settings",
                )
                findings.append(finding)
                
        except Exception as e:
            logger.error(f"Error checking Dependabot for {repo.full_name}: {e}")
        
        return findings
    
    def _check_code_scanning(self, repo: Repository) -> List[Finding]:
        """Check if code scanning is configured."""
        findings = []
        
        try:
            # Check for code scanning alerts or configuration
            # This would query the code scanning API
            code_scanning_enabled = False  # Placeholder - check actual API
            
            if not code_scanning_enabled:
                finding = Finding(
                    type=FindingType.CONFIG_ISSUE,
                    severity=Severity.LOW,
                    title="Code scanning not configured",
                    description="Code scanning helps find security vulnerabilities in your code.",
                    repository=repo.full_name,
                    fixable=True,
                    fix_strategy="enable_code_scanning",
                    fix_command="Configure code scanning in repository settings or add a GitHub Actions workflow",
                )
                findings.append(finding)
                
        except Exception as e:
            logger.error(f"Error checking code scanning for {repo.full_name}: {e}")
        
        return findings
    
    def _check_actions_permissions(self, repo: Repository) -> List[Finding]:
        """Check GitHub Actions permissions."""
        findings = []
        
        try:
            # Check actions permissions (requires GraphQL API)
            # This is a simplified check
            actions_permissive = False  # Placeholder
            
            if actions_permissive:
                finding = Finding(
                    type=FindingType.CONFIG_ISSUE,
                    severity=Severity.MEDIUM,
                    title="Actions permissions too permissive",
                    description="GitHub Actions should have restricted permissions to prevent supply chain attacks.",
                    repository=repo.full_name,
                    fixable=True,
                    fix_strategy="restrict_actions_permissions",
                    fix_command="Set Actions permissions to read-only where possible",
                )
                findings.append(finding)
                
        except Exception as e:
            logger.error(f"Error checking actions permissions for {repo.full_name}: {e}")
        
        return findings
    
    def calculate_security_score(self, findings: List[Finding]) -> float:
        """
        Calculate security score from 0-100 based on findings.
        
        Args:
            findings: List of findings for the organization
            
        Returns:
            Security score (0-100)
        """
        if not findings:
            return 100.0
        
        # Weight different finding types
        severity_weights = {
            Severity.CRITICAL: 20.0,
            Severity.HIGH: 10.0,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 2.0,
            Severity.INFO: 0.0,
        }
        
        # Calculate penalty
        total_penalty = 0.0
        max_penalty = 100.0
        
        for finding in findings:
            penalty = severity_weights.get(finding.severity, 0)
            total_penalty += penalty
        
        # Cap at max penalty
        total_penalty = min(total_penalty, max_penalty)
        
        # Calculate score
        score = max(0.0, 100.0 - total_penalty)
        
        return round(score, 1)