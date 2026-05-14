"""Secret scanning module using detect-secrets and truffleHog."""

import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from datetime import datetime
import json
import logging
from github.Repository import Repository
from detect_secrets import SecretsCollection
from detect_secrets.settings import transient_settings
import yaml

from gh_audit.models.finding import Finding, Severity, FindingType

logger = logging.getLogger(__name__)


class SecretScanner:
    """Scan repositories for exposed secrets."""
    
    # Common secret patterns for quick scanning
    SECRET_PATTERNS = {
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "AWS Secret Key": r"[A-Za-z0-9/+=]{40}",
        "GitHub Token": r"gh[psu]_[0-9a-zA-Z]{36}",
        "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
        "Private Key": r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
        "JWT Token": r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
        "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
        "Stripe API Key": r"sk_live_[0-9a-zA-Z]{24}",
        "PayPal/Braintree": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
        "Heroku API Key": r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "SendGrid API Key": r"SG\.[0-9a-zA-Z]{22}\.[0-9a-zA-Z]{43}",
        "Twilio API Key": r"SK[0-9a-f]{32}",
    }
    
    def __init__(
        self,
        github_client,
        ignore_file: str = ".auditignore",
        scan_commits: bool = True,
        since_date: Optional[str] = None
    ):
        """
        Initialize secret scanner.
        
        Args:
            github_client: GitHub client instance
            ignore_file: Path to ignore patterns file
            scan_commits: Whether to scan commit history
            since_date: Scan commits since this date (YYYY-MM-DD)
        """
        self.github_client = github_client
        self.ignore_patterns = self._load_ignore_patterns(ignore_file)
        self.scan_commits = scan_commits
        self.since_date = since_date
        self.cache_dir = Path(".gh-audit-cache")
        self.cache_dir.mkdir(exist_ok=True)
    
    def _load_ignore_patterns(self, ignore_file: str) -> Set[str]:
        """Load ignore patterns from .auditignore file."""
        patterns = set()
        
        # Default patterns to ignore
        default_patterns = {
            "*.test.js",
            "*.test.py",
            "test_*.py",
            "*_test.go",
            "node_modules/*",
            "vendor/*",
            "*.min.js",
            "*.min.css",
            "*.lock",
            "package-lock.json",
            "yarn.lock",
            "poetry.lock",
            "Gemfile.lock",
        }
        patterns.update(default_patterns)
        
        # Load custom patterns if file exists
        if Path(ignore_file).exists():
            with open(ignore_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        patterns.add(line)
        
        return patterns
    
    def _should_ignore_file(self, file_path: str) -> bool:
        """Check if file should be ignored based on patterns."""
        for pattern in self.ignore_patterns:
            if pattern.endswith('/*'):
                dir_pattern = pattern[:-2]
                if file_path.startswith(dir_pattern):
                    return True
            elif pattern.startswith('*.'):
                ext = pattern[1:]
                if file_path.endswith(ext):
                    return True
            elif pattern in file_path:
                return True
        return False
    
    def scan_repository(self, repo: Repository) -> List[Finding]:
        """
        Scan a repository for secrets.
        
        Args:
            repo: GitHub repository object
            
        Returns:
            List of findings
        """
        findings = []
        
        logger.info(f"Scanning repository for secrets: {repo.full_name}")
        
        # Clone repository to temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                # Clone the repository
                clone_url = repo.clone_url.replace(
                    "https://github.com",
                    f"https://{self.github_client.token}@github.com"
                )
                
                # Add date filter if specified
                since_flag = []
                if self.since_date and self.scan_commits:
                    since_flag = [f"--since={self.since_date}"]
                
                # Use git clone with depth limit for performance
                clone_cmd = ["git", "clone", "--depth", "50", clone_url, temp_dir]
                if self.scan_commits:
                    clone_cmd = ["git", "clone", clone_url, temp_dir]
                
                subprocess.run(clone_cmd, check=True, capture_output=True)
                
                # Run detect-secrets scan
                findings.extend(self._scan_with_detect_secrets(temp_dir, repo.full_name))
                
                # Run truffleHog for deep commit scanning
                if self.scan_commits:
                    findings.extend(self._scan_with_trufflehog(temp_dir, repo.full_name))
                
                # Quick regex scan for common patterns
                findings.extend(self._quick_regex_scan(temp_dir, repo.full_name))
                
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to clone repository {repo.full_name}: {e}")
            except Exception as e:
                logger.error(f"Error scanning {repo.full_name}: {e}")
        
        return findings
    
    def _scan_with_detect_secrets(self, repo_path: str, repo_name: str) -> List[Finding]:
        """Scan using detect-secrets library."""
        findings = []
        
        try:
            secrets = SecretsCollection()
            
            with transient_settings({
                'plugins_used': [
                    {'name': 'AWSKeyDetector'},
                    {'name': 'PrivateKeyDetector'},
                    {'name': 'SlackDetector'},
                    {'name': 'GitHubTokenDetector'},
                    {'name': 'JwtTokenDetector'},
                    {'name': 'ArtifactoryDetector'},
                    {'name': 'Base64HighEntropyString'},
                    {'name': 'HexHighEntropyString'},
                ],
                'filters_used': [
                    {'path': 'detect_secrets.filters.common.is_ignored_due_to_filename'},
                    {'path': 'detect_secrets.filters.heuristic.is_likely_id_string'},
                ]
            }):
                secrets.scan_file(repo_path)
            
            # Process results
            for filename, results in secrets.results.items():
                if self._should_ignore_file(filename):
                    continue
                    
                for result in results:
                    finding = Finding(
                        type=FindingType.SECRET,
                        severity=Severity.CRITICAL,
                        title=f"Exposed secret found: {result.secret_hash[:10]}...",
                        description=f"Potential secret detected in {filename} at line {result.line_number}. Secret type: {result.type}",
                        repository=repo_name,
                        file_path=filename,
                        line_number=result.line_number,
                        fixable=True,
                        fix_strategy="revoke_and_remove",
                        fix_command="git filter-branch --force --index-filter 'git rm --cached --ignore-unmatch {filename}' --prune-empty --tag-name-filter cat -- --all",
                    )
                    findings.append(finding)
                    
        except Exception as e:
            logger.error(f"Error in detect-secrets scan: {e}")
        
        return findings
    
    def _scan_with_trufflehog(self, repo_path: str, repo_name: str) -> List[Finding]:
        """Scan using truffleHog for deep commit history scanning."""
        findings = []
        
        try:
            # Run truffleHog command
            cmd = [
                "trufflehog",
                "git",
                repo_path,
                "--json",
                "--only-verified",
                "--no-update",
            ]
            
            if self.since_date:
                cmd.extend(["--since", self.since_date])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0 or result.stdout:
                for line in result.stdout.strip().split('\n'):
                    if line:
                        try:
                            data = json.loads(line)
                            finding = Finding(
                                type=FindingType.SECRET,
                                severity=Severity.CRITICAL,
                                title=f"Secret found in commit history: {data.get('DetectorName', 'Unknown')}",
                                description=data.get('Reason', 'Secret detected in commit history'),
                                repository=repo_name,
                                commit_hash=data.get('CommitHash'),
                                file_path=data.get('Path'),
                                fixable=True,
                                fix_strategy="bfg_cleaner",
                                fix_command=f"bfg --delete-files {data.get('Path', '')}",
                            )
                            findings.append(finding)
                        except json.JSONDecodeError:
                            continue
                            
        except subprocess.TimeoutExpired:
            logger.warning(f"TruffleHog scan timed out for {repo_name}")
        except FileNotFoundError:
            logger.warning("truffleHog not installed. Install with: pip install truffleHog")
        except Exception as e:
            logger.error(f"Error in truffleHog scan: {e}")
        
        return findings
    
    def _quick_regex_scan(self, repo_path: str, repo_name: str) -> List[Finding]:
        """Quick scan using regex patterns."""
        findings = []
        
        for root, dirs, files in os.walk(repo_path):
            # Skip ignored directories
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', 'vendor', '__pycache__']]
            
            for file in files:
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, repo_path)
                
                if self._should_ignore_file(rel_path):
                    continue
                
                try:
                    # Skip binary files
                    if self._is_binary_file(file_path):
                        continue
                    
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                        
                    for line_num, line in enumerate(lines, 1):
                        for secret_type, pattern in self.SECRET_PATTERNS.items():
                            if re.search(pattern, line):
                                # Verify it's not a test or example
                                if self._is_false_positive(line, secret_type):
                                    continue
                                    
                                finding = Finding(
                                    type=FindingType.SECRET,
                                    severity=Severity.CRITICAL,
                                    title=f"Potential {secret_type} exposed",
                                    description=f"Found {secret_type} pattern in file",
                                    repository=repo_name,
                                    file_path=rel_path,
                                    line_number=line_num,
                                    fixable=True,
                                    fix_strategy="remove_and_rotate",
                                    fix_command=f"git filter-branch --force --index-filter 'git rm --cached --ignore-unmatch {rel_path}' --prune-empty --tag-name-filter cat -- --all",
                                )
                                findings.append(finding)
                                
                except Exception as e:
                    logger.debug(f"Error scanning file {rel_path}: {e}")
        
        return findings
    
    def _is_binary_file(self, file_path: str) -> bool:
        """Check if file is binary."""
        try:
            with open(file_path, 'tr') as check:
                check.read(1024)
                return False
        except UnicodeDecodeError:
            return True
    
    def _is_false_positive(self, line: str, secret_type: str) -> bool:
        """Check if detected secret is likely a false positive."""
        false_positive_indicators = [
            "example",
            "test",
            "sample",
            "demo",
            "placeholder",
            "TODO",
            "FIXME",
            "your-",
            "<your",
            "[your",
            "{your",
            "changeme",
        ]
        
        line_lower = line.lower()
        for indicator in false_positive_indicators:
            if indicator in line_lower:
                return True
        
        # Check for environment variable patterns that might be safe
        if line.startswith('export ') or line.startswith('set '):
            return True
        
        return False
    
    def auto_fix(self, finding: Finding, repo: Repository) -> bool:
        """
        Attempt to auto-fix a secret exposure.
        
        Args:
            finding: The finding to fix
            repo: Repository object
            
        Returns:
            True if fix was successful
        """
        if not finding.fixable:
            return False
        
        logger.warning(f"Auto-fixing secret exposure in {repo.full_name}")
        
        # Create an issue to revoke and rotate the secret
        issue_title = f"[SECURITY] Revoke and rotate exposed secret in {finding.file_path}"
        issue_body = f"""
## Security Alert: Exposed Secret Detected

**File:** `{finding.file_path}`
**Line:** {finding.line_number}
**Description:** {finding.description}

### Immediate Actions Required:
1. **REVOKE** the exposed secret immediately
2. **ROTATE** the secret with a new one
3. **REMOVE** the secret from git history using:

### Recommended Fix:
- If this is an API key, revoke it in the respective service dashboard
- Generate a new key and update your application configuration
- Remove the old key from git history using BFG Repo-Cleaner

**Severity:** CRITICAL
**Auto-detected by:** GitHub Security Auditor
     """
     
        return self.github_client.create_issue(
         repo,
         issue_title,
         issue_body,
         labels=["security", "critical", "auto-detected"]
     )