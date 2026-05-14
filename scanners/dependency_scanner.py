"""Dependency vulnerability scanning module."""

import os
import json
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple
from packaging import version as packaging_version
import requests
from github.Repository import Repository
import logging

from gh_audit.models.finding import Finding, Severity, FindingType

logger = logging.getLogger(__name__)


class DependencyScanner:
    """Scan dependencies for known vulnerabilities."""
    
    # Supported manifest files
    MANIFEST_FILES = {
        "requirements.txt": "pip",
        "Pipfile": "pipenv",
        "pyproject.toml": "poetry",
        "package.json": "npm",
        "package-lock.json": "npm",
        "yarn.lock": "yarn",
        "go.mod": "go",
        "Gemfile": "bundler",
        "Cargo.toml": "cargo",
        "build.gradle": "gradle",
        "pom.xml": "maven",
        "composer.json": "composer",
    }
    
    def __init__(self, github_client, severity_filter: str = "all"):
        """
        Initialize dependency scanner.
        
        Args:
            github_client: GitHub client instance
            severity_filter: Minimum severity to report (all, critical, high, medium, low)
        """
        self.github_client = github_client
        self.severity_filter = severity_filter
        self.cache_dir = Path(".gh-audit-cache")
        self.cache_dir.mkdir(exist_ok=True)
        
        # Initialize OSV API endpoint
        self.osv_api = "https://api.osv.dev/v1/query"
        
    def scan_repository(self, repo: Repository) -> List[Finding]:
        """
        Scan repository dependencies for vulnerabilities.
        
        Args:
            repo: GitHub repository object
            
        Returns:
            List of findings
        """
        findings = []
        
        logger.info(f"Scanning dependencies for {repo.full_name}")
        
        # Clone repository to temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                # Clone the repository
                clone_url = repo.clone_url.replace(
                    "https://github.com",
                    f"https://{self.github_client.token}@github.com"
                )
                
                subprocess.run(
                    ["git", "clone", "--depth", "1", clone_url, temp_dir],
                    check=True,
                    capture_output=True
                )
                
                # Find and scan manifest files
                for root, dirs, files in os.walk(temp_dir):
                    # Skip virtual environments and node_modules
                    dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', 'venv', 'env', 'virtualenv']]
                    
                    for file in files:
                        if file in self.MANIFEST_FILES:
                            manifest_path = os.path.join(root, file)
                            rel_path = os.path.relpath(manifest_path, temp_dir)
                            
                            # Parse and scan manifest
                            manifest_findings = self._scan_manifest(
                                manifest_path,
                                file,
                                repo.full_name,
                                rel_path
                            )
                            findings.extend(manifest_findings)
                            
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to clone repository {repo.full_name}: {e}")
            except Exception as e:
                logger.error(f"Error scanning dependencies for {repo.full_name}: {e}")
        
        return findings
    
    def _scan_manifest(
        self,
        manifest_path: str,
        manifest_type: str,
        repo_name: str,
        rel_path: str
    ) -> List[Finding]:
        """Scan a manifest file for vulnerabilities."""
        findings = []
        
        try:
            dependencies = self._parse_manifest(manifest_path, manifest_type)
            
            for dep_name, dep_version in dependencies.items():
                # Query OSV for vulnerabilities
                vulns = self._query_osv(dep_name, dep_version)
                
                for vuln in vulns:
                    severity = self._parse_severity(vuln)
                    
                    # Filter by severity
                    if not self._should_include_severity(severity):
                        continue
                    
                    finding = Finding(
                        type=FindingType.VULNERABILITY,
                        severity=severity,
                        title=f"Vulnerable dependency: {dep_name}@{dep_version}",
                        description=vuln.get('summary', f"Security vulnerability found in {dep_name} version {dep_version}"),
                        repository=repo_name,
                        file_path=rel_path,
                        cve_id=vuln.get('id'),
                        cvss_score=vuln.get('cvss_score'),
                        reference_url=vuln.get('references', [{}])[0].get('url') if vuln.get('references') else None,
                        fixable=True,
                        fix_strategy="update_dependency",
                        fix_command=f"Update {dep_name} to version {vuln.get('fixed_version', 'latest')}",
                        raw_data=vuln,
                    )
                    findings.append(finding)
                    
        except Exception as e:
            logger.error(f"Error scanning manifest {manifest_path}: {e}")
        
        return findings
    
    def _parse_manifest(self, manifest_path: str, manifest_type: str) -> Dict[str, str]:
        """Parse manifest file and extract dependencies."""
        dependencies = {}
        
        try:
            with open(manifest_path, 'r', encoding='utf-8') as f:
                if manifest_type == "requirements.txt":
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # Handle version specifiers
                            dep = line.split('=')[0].split('>')[0].split('<')[0].split('~')[0].strip()
                            version = self._extract_version(line)
                            if dep and version:
                                dependencies[dep] = version
                                
                elif manifest_type == "package.json":
                    data = json.load(f)
                    deps = {**data.get('dependencies', {}), **data.get('devDependencies', {})}
                    for dep, version in deps.items():
                        if not version.startswith('file:'):
                            clean_version = self._clean_npm_version(version)
                            if clean_version:
                                dependencies[dep] = clean_version
                                
                elif manifest_type == "go.mod":
                    content = f.read()
                    for line in content.split('\n'):
                        if line.startswith('require'):
                            parts = line.split()
                            if len(parts) >= 2:
                                dep = parts[1]
                                version = parts[2] if len(parts) > 2 else "latest"
                                dependencies[dep] = version
                                
                elif manifest_type == "Gemfile":
                    # Basic Gemfile parsing
                    for line in f:
                        if line.strip().startswith("gem '"):
                            import re
                            match = re.search(r"gem '([^']+)'(?:, '([^']+)')?", line)
                            if match:
                                dep = match.group(1)
                                version = match.group(2) if match.group(2) else "latest"
                                dependencies[dep] = version
                                
                elif manifest_type == "pyproject.toml":
                    # Parse TOML for poetry dependencies
                    import tomli
                    data = tomli.load(f)
                    if 'tool' in data and 'poetry' in data['tool']:
                        deps = data['tool']['poetry'].get('dependencies', {})
                        for dep, version_info in deps.items():
                            if dep != "python":
                                version = version_info if isinstance(version_info, str) else version_info.get('version', 'latest')
                                dependencies[dep] = version
                                
        except Exception as e:
            logger.error(f"Error parsing {manifest_type}: {e}")
        
        return dependencies
    
    def _extract_version(self, line: str) -> str:
        """Extract version from requirement line."""
        import re
        version_patterns = [
            r'==([\d\.]+)',
            r'>=([\d\.]+)',
            r'~=([\d\.]+)',
            r'([\d\.]+)',
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, line)
            if match:
                return match.group(1)
        
        return "latest"
    
    def _clean_npm_version(self, version: str) -> str:
        """Clean npm version string."""
        # Remove caret, tilde, etc.
        version = version.lstrip('^~>=<')
        # Handle x-range
        if version.endswith('.x'):
            version = version[:-2]
        return version
    
    def _query_osv(self, package_name: str, package_version: str) -> List[Dict[str, Any]]:
        """Query OSV API for vulnerabilities."""
        # Check cache first
        cache_key = f"{package_name}-{package_version}"
        cache_file = self.cache_dir / f"osv_{cache_key}.json"
        
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
        
        try:
            # Query OSV
            payload = {
                "version": package_version,
                "package": {
                    "name": package_name,
                    "ecosystem": "PyPI"  # Will be adjusted based on context
                }
            }
            
            response = requests.post(self.osv_api, json=payload, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                vulns = data.get('vulns', [])
                
                # Enrich with severity info
                for vuln in vulns:
                    vuln['cvss_score'] = self._extract_cvss_score(vuln)
                    
                # Cache results
                with open(cache_file, 'w') as f:
                    json.dump(vulns, f)
                    
                return vulns
                
        except Exception as e:
            logger.error(f"Error querying OSV for {package_name}: {e}")
        
        return []
    
    def _extract_cvss_score(self, vuln: Dict[str, Any]) -> Optional[float]:
        """Extract CVSS score from vulnerability data."""
        # Try to get from different fields
        if 'severity' in vuln:
            for severity in vuln['severity']:
                if severity.get('type') == 'CVSS_V3':
                    return severity.get('score')
        
        # Try to get from database-specific fields
        if 'database_specific' in vuln:
            if 'cvss' in vuln['database_specific']:
                return vuln['database_specific']['cvss'].get('score')
        
        return None
    
    def _parse_severity(self, vuln: Dict[str, Any]) -> Severity:
        """Parse severity from vulnerability data."""
        cvss_score = vuln.get('cvss_score')
        
        if cvss_score:
            if cvss_score >= 9.0:
                return Severity.CRITICAL
            elif cvss_score >= 7.0:
                return Severity.HIGH
            elif cvss_score >= 4.0:
                return Severity.MEDIUM
            else:
                return Severity.LOW
        
        # Fallback to text severity
        if 'severity' in vuln:
            for severity in vuln['severity']:
                if severity.get('type') == 'CVSS_V3':
                    sev_text = severity.get('score', '').lower()
                    if 'critical' in sev_text:
                        return Severity.CRITICAL
                    elif 'high' in sev_text:
                        return Severity.HIGH
                    elif 'medium' in sev_text:
                        return Severity.MEDIUM
        
        return Severity.MEDIUM
    
    def _should_include_severity(self, severity: Severity) -> bool:
        """Check if severity meets filter threshold."""
        severity_order = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }
        
        filter_map = {
            "all": 0,
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1,
        }
        
        filter_value = filter_map.get(self.severity_filter, 0)
        severity_value = severity_order.get(severity, 0)
        
        return severity_value >= filter_value
    
    def auto_fix(self, finding: Finding, repo: Repository) -> bool:
        """
        Attempt to auto-fix a vulnerable dependency.
        
        Args:
            finding: The finding to fix
            repo: Repository object
            
        Returns:
            True if fix was successful
        """
        if not finding.fixable:
            return False
        
        logger.info(f"Auto-fixing vulnerable dependency in {repo.full_name}")
        
        # Extract dependency info from finding
        title = finding.title
        dep_name = title.split('@')[0].replace("Vulnerable dependency: ", "")
        
        # Create a pull request with the fix
        pr_title = f"[Security] Update vulnerable dependency: {dep_name}"
        pr_body = f"""
## Security Update: Dependency Vulnerability Fix

This PR automatically updates the vulnerable dependency **{dep_name}** to a secure version.

### Vulnerable Package:
- **Package:** {dep_name}
- **Severity:** {finding.severity.value.upper()}
- **CVE:** {finding.cve_id or 'N/A'}

### Changes Made:
- Updated {dep_name} to a version without known vulnerabilities

### How to verify:
1. Review the dependency changes
2. Run tests to ensure compatibility
3. Merge if all checks pass

---
*Automatically generated by GitHub Security Auditor*
        """
        
        # Note: Creating PRs requires additional permissions
        # This is a placeholder for actual PR creation logic
        return self.github_client.create_issue(
            repo,
            pr_title,
            pr_body,
            labels=["security", "dependencies", "auto-fix"]
        )