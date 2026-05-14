# gh_audit/scanners/secret_scanner.py
"""Secret detection using detect-secrets + truffleHog hybrid approach."""

import re
import logging
import asyncio
from pathlib import Path
from typing import List, Optional, Set, Dict, Any
from datetime import datetime
import hashlib

import requests
from rich.console import Console

from gh_audit.models.finding import SecretFinding, Severity
from gh_audit.utils.github_client import GitHubClient

logger = logging.getLogger(__name__)
console = Console()


class SecretScanner:
    """Scan repositories for exposed secrets using multiple detection methods."""
    
    # Common secret patterns for regex-based detection
    SECRET_PATTERNS = {
        "AWS Access Key": {
            "pattern": r"AKIA[0-9A-Z]{16}",
            "severity": Severity.CRITICAL,
            "remediation": "Revoke AWS key in IAM, replace with new key, and remove from code"
        },
        "AWS Secret Key": {
            "pattern": r"[A-Za-z0-9/+=]{40}",
            "severity": Severity.CRITICAL,
            "remediation": "Revoke AWS secret key immediately"
        },
        "GitHub Token": {
            "pattern": r"gh[psu]_[A-Za-z0-9]{36}",
            "severity": Severity.CRITICAL,
            "remediation": "Revoke token in GitHub settings and generate new one"
        },
        "Generic API Key": {
            "pattern": r"(api[_-]?key|apikey|api_token)[\s]*[:=][\s]*['\"]?[A-Za-z0-9]{20,40}['\"]?",
            "severity": Severity.HIGH,
            "remediation": "Rotate API key and store in environment variables or secrets manager"
        },
        "Password in Code": {
            "pattern": r"(password|passwd|pwd)[\s]*[:=][\s]*['\"][^'\"]{4,}['\"]",
            "severity": Severity.CRITICAL,
            "remediation": "Remove password, use environment variables or secrets manager"
        },
        "JWT Token": {
            "pattern": r"eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",
            "severity": Severity.HIGH,
            "remediation": "Revoke JWT token immediately"
        },
        "Private Key": {
            "pattern": r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
            "severity": Severity.CRITICAL,
            "remediation": "Generate new key pair and remove private key from repository"
        },
        "Database Connection": {
            "pattern": r"(mongodb|mysql|postgresql|redis)://[^/\s]+:[^@\s]+@",
            "severity": Severity.CRITICAL,
            "remediation": "Change database credentials and use connection strings from environment"
        },
        "Slack Webhook": {
            "pattern": r"https://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+",
            "severity": Severity.HIGH,
            "remediation": "Delete webhook and create a new one"
        }
    }
    
    def __init__(
        self,
        github_client: GitHubClient,
        severity: str = "all",
        since: Optional[str] = None,
        verbose: bool = False
    ):
        """Initialize secret scanner.
        
        Args:
            github_client: GitHub API client
            severity: Minimum severity level to report
            since: Scan commits since date (YYYY-MM-DD)
            verbose: Enable verbose logging
        """
        self.github_client = github_client
        self.verbose = verbose
        self.since_date = datetime.strptime(since, "%Y-%m-%d") if since else None
        
        # Set severity threshold
        self.severity_threshold = Severity[severity.upper()] if severity != "all" else Severity.LOW
        
        # Files to ignore (common false positives)
        self.ignore_patterns = self._load_ignore_patterns()
    
    def _load_ignore_patterns(self) -> Set[str]:
        """Load .auditignore patterns for false positive filtering.
        
        Returns:
            Set of file patterns to ignore
        """
        # Default patterns to ignore
        patterns = {
            "*.lock",
            "package-lock.json",
            "yarn.lock",
            "poetry.lock",
            "Gemfile.lock",
            "*.log",
            "*.pyc",
            "__pycache__/*",
            ".git/*",
            "*.min.js",
            "*.min.css",
            "*.map",
            "test_*",
            "*_test.go",
            "*.test.js",
            "*.spec.js"
        }
        
        # Try to load .auditignore file
        try:
            auditignore_path = Path(".auditignore")
            if auditignore_path.exists():
                with open(auditignore_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            patterns.add(line)
        except Exception as e:
            if self.verbose:
                logger.debug(f"Could not load .auditignore: {e}")
        
        return patterns
    
    def _should_ignore_file(self, file_path: str) -> bool:
        """Check if file should be ignored based on patterns.
        
        Args:
            file_path: Path to file
            
        Returns:
            True if file should be ignored
        """
        for pattern in self.ignore_patterns:
            if pattern.startswith("*."):
                if file_path.endswith(pattern[1:]):
                    return True
            elif pattern.endswith("/*"):
                directory = pattern[:-2]
                if file_path.startswith(directory):
                    return True
            elif pattern in file_path:
                return True
        return False
    
    def _regex_scan_content(self, content: str, file_path: str) -> List[SecretFinding]:
        """Scan file content using regex patterns.
        
        Args:
            content: File content to scan
            file_path: Path to the file
            
        Returns:
            List of secret findings
        """
        findings = []
        
        for secret_type, config in self.SECRET_PATTERNS.items():
            pattern = config["pattern"]
            severity = config["severity"]
            remediation = config["remediation"]
            
            # Skip if severity is below threshold
            if severity.value > self.severity_threshold.value:
                continue
            
            # Find all matches
            for match in re.finditer(pattern, content, re.IGNORECASE):
                # Get line number
                line_number = content[:match.start()].count('\n') + 1
                
                # Get context (surrounding lines)
                lines = content.split('\n')
                start_line = max(0, line_number - 2)
                end_line = min(len(lines), line_number + 2)
                context = '\n'.join(lines[start_line:end_line])
                
                # Create finding
                finding = SecretFinding.create(
                    repository="",  # Will be set by caller
                    secret_type=secret_type,
                    file_path=file_path,
                    line_number=line_number,
                    severity=severity,
                    description=f"Found {secret_type} in {file_path}:{line_number}\nContext:\n{context}",
                    remediation=remediation
                )
                
                findings.append(finding)
        
        return findings
    
    async def scan_repository(self, repo_full_name: str) -> List[SecretFinding]:
        """Scan a repository for exposed secrets.
        
        Args:
            repo_full_name: Repository full name (owner/repo)
            
        Returns:
            List of secret findings
        """
        if self.verbose:
            logger.info(f"Scanning {repo_full_name} for secrets...")
        
        findings = []
        
        try:
            # Get commit history
            commits = self.github_client.get_commit_history(
                repo_full_name,
                since=self.since_date,
                max_commits=500
            )
            
            if self.verbose:
                logger.info(f"Checking {len(commits)} commits in {repo_full_name}")
            
            # Track processed files to avoid duplicates
            processed_files = set()
            
            for commit in commits:
                # Check each file in the commit
                for file_path in commit.get("files", []):
                    # Skip ignored files
                    if self._should_ignore_file(file_path):
                        continue
                    
                    # Avoid processing same file multiple times
                    file_key = f"{file_path}:{commit['hash']}"
                    if file_key in processed_files:
                        continue
                    processed_files.add(file_key)
                    
                    # Get file content
                    content = self.github_client.get_file_content(
                        repo_full_name,
                        file_path,
                        branch="main"
                    )
                    
                    if content:
                        # Run regex scan
                        regex_findings = self._regex_scan_content(content, file_path)
                        for finding in regex_findings:
                            finding.repository = repo_full_name
                            finding.commit_hash = commit["hash"]
                            finding.commit_author = commit.get("author")
                            finding.commit_date = commit.get("date")
                            findings.append(finding)
            
            # TODO: Integrate with detect-secrets and truffleHog for deeper scanning
            # This would involve shelling out to those tools or using their APIs
            
            if self.verbose:
                logger.info(f"Found {len(findings)} secrets in {repo_full_name}")
            
        except Exception as e:
            logger.error(f"Error scanning {repo_full_name} for secrets: {e}")
        
        return findings
    
    async def scan_all_repositories(self, repo_names: List[str]) -> List[SecretFinding]:
        """Scan multiple repositories for secrets.
        
        Args:
            repo_names: List of repository names
            
        Returns:
            List of all secret findings
        """
        all_findings = []
        
        for repo_name in repo_names:
            findings = await self.scan_repository(repo_name)
            all_findings.extend(findings)
        
        return all_findings
    
    def get_statistics(self, findings: List[SecretFinding]) -> Dict[str, Any]:
        """Get statistics about secret findings.
        
        Args:
            findings: List of secret findings
            
        Returns:
            Dictionary with statistics
        """
        stats = {
            "total_secrets": len(findings),
            "by_severity": {},
            "by_type": {},
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0
        }
        
        for finding in findings:
            # Count by severity
            severity = finding.severity.value
            stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1
            
            # Count by type
            secret_type = finding.secret_type
            stats["by_type"][secret_type] = stats["by_type"].get(secret_type, 0) + 1
            
            # Update counts
            if finding.severity == Severity.CRITICAL:
                stats["critical_count"] += 1
            elif finding.severity == Severity.HIGH:
                stats["high_count"] += 1
            elif finding.severity == Severity.MEDIUM:
                stats["medium_count"] += 1
            else:
                stats["low_count"] += 1
        
        return stats