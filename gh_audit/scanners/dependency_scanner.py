# gh_audit/scanners/dependency_scanner.py
"""CVE detection using Safety DB + OSV for multiple ecosystems."""

import json
import logging
import subprocess
import asyncio
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
from packaging.version import parse as parse_version

import requests
from rich.console import Console

from gh_audit.models.finding import DependencyFinding, Severity
from gh_audit.utils.github_client import GitHubClient

logger = logging.getLogger(__name__)
console = Console()


class DependencyScanner:
    """Scan repositories for vulnerable dependencies across multiple ecosystems."""
    
    # Supported package managers and their manifest files
    ECOSYSTEMS = {
        "pypi": {
            "manifests": ["requirements.txt", "setup.py", "Pipfile", "pyproject.toml", "poetry.lock"],
            "parser": "_parse_python_deps"
        },
        "npm": {
            "manifests": ["package.json", "package-lock.json", "yarn.lock"],
            "parser": "_parse_node_deps"
        },
        "go": {
            "manifests": ["go.mod", "go.sum"],
            "parser": "_parse_go_deps"
        },
        "maven": {
            "manifests": ["pom.xml"],
            "parser": "_parse_maven_deps"
        },
        "rubygems": {
            "manifests": ["Gemfile", "Gemfile.lock"],
            "parser": "_parse_ruby_deps"
        }
    }
    
    def __init__(
        self,
        severity: str = "all",
        verbose: bool = False,
        use_local_safety_db: bool = True
    ):
        """Initialize dependency scanner.
        
        Args:
            severity: Minimum severity level to report
            verbose: Enable verbose logging
            use_local_safety_db: Use local Safety DB if available
        """
        self.verbose = verbose
        self.use_local_safety_db = use_local_safety_db
        self.cve_cache: Dict[str, List[Dict]] = {}
        
        # Set severity threshold
        self.severity_threshold = Severity[severity.upper()] if severity != "all" else Severity.LOW
        
        # OSV API endpoint
        self.osv_api_url = "https://api.osv.dev/v1/query"
    
    async def scan_repository(self, repo_full_name: str) -> List[DependencyFinding]:
        """Scan a repository for vulnerable dependencies.
        
        Args:
            repo_full_name: Repository full name (owner/repo)
            
        Returns:
            List of dependency findings
        """
        if self.verbose:
            logger.info(f"Scanning {repo_full_name} for vulnerable dependencies...")
        
        findings = []
        
        try:
            # Check for each ecosystem's manifest files
            for ecosystem, config in self.ECOSYSTEMS.items():
                for manifest in config["manifests"]:
                    # Get manifest content from GitHub
                    content = self._get_manifest_from_github(repo_full_name, manifest)
                    
                    if content:
                        if self.verbose:
                            logger.debug(f"Found {manifest} in {repo_full_name}")
                        
                        # Parse dependencies from manifest
                        parser_method = getattr(self, config["parser"])
                        dependencies = parser_method(content, manifest)
                        
                        # Check each dependency for vulnerabilities
                        for dep in dependencies:
                            vulns = await self._check_vulnerabilities(
                                dep["name"],
                                dep["version"],
                                ecosystem
                            )
                            
                            for vuln in vulns:
                                finding = self._create_finding(
                                    repo_full_name,
                                    dep,
                                    vuln,
                                    ecosystem
                                )
                                
                                if finding:
                                    findings.append(finding)
        
        except Exception as e:
            logger.error(f"Error scanning {repo_full_name} for dependencies: {e}")
        
        return findings
    
    def _get_manifest_from_github(self, repo_full_name: str, manifest_path: str) -> Optional[str]:
        """Get manifest file content from GitHub repository.
        
        Args:
            repo_full_name: Repository full name
            manifest_path: Path to manifest file
            
        Returns:
            File content or None if not found
        """
        # This would integrate with GitHubClient
        # For now, return None as placeholder
        # In production, you'd call github_client.get_file_content()
        return None
    
    def _parse_python_deps(self, content: str, manifest_type: str) -> List[Dict[str, str]]:
        """Parse Python dependencies from various manifest files.
        
        Args:
            content: File content
            manifest_type: Type of manifest file
            
        Returns:
            List of dependencies with name and version
        """
        dependencies = []
        
        if manifest_type == "requirements.txt":
            # Parse requirements.txt format
            for line in content.split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    # Handle package==version format
                    if '==' in line:
                        name, version = line.split('==', 1)
                        dependencies.append({"name": name.strip(), "version": version.strip()})
                    elif '>=' in line:
                        name, version = line.split('>=', 1)
                        dependencies.append({"name": name.strip(), "version": version.strip()})
        
        elif manifest_type == "pyproject.toml":
            # Parse pyproject.toml (simplified)
            import tomllib
            try:
                data = tomllib.loads(content)
                if "project" in data and "dependencies" in data["project"]:
                    for dep in data["project"]["dependencies"]:
                        if '>=' in dep:
                            name, version = dep.split('>=', 1)
                            dependencies.append({"name": name.strip(), "version": version.strip()})
            except:
                pass
        
        return dependencies
    
    def _parse_node_deps(self, content: str, manifest_type: str) -> List[Dict[str, str]]:
        """Parse Node.js dependencies from package.json.
        
        Args:
            content: File content
            manifest_type: Type of manifest file
            
        Returns:
            List of dependencies with name and version
        """
        dependencies = []
        
        if manifest_type == "package.json":
            try:
                data = json.loads(content)
                
                # Check dependencies and devDependencies
                for dep_type in ["dependencies", "devDependencies"]:
                    if dep_type in data:
                        for name, version in data[dep_type].items():
                            # Clean version string (remove ^, ~, etc.)
                            clean_version = version.lstrip('^~>=<')
                            dependencies.append({
                                "name": name,
                                "version": clean_version.split()[0]
                            })
            except json.JSONDecodeError:
                pass
        
        return dependencies
    
    def _parse_go_deps(self, content: str, manifest_type: str) -> List[Dict[str, str]]:
        """Parse Go dependencies from go.mod.
        
        Args:
            content: File content
            manifest_type: Type of manifest file
            
        Returns:
            List of dependencies with name and version
        """
        dependencies = []
        
        if manifest_type == "go.mod":
            lines = content.split('\n')
            for line in lines:
                line = line.strip()
                if line.startswith('require') and not line.startswith('require ('):
                    parts = line.split()
                    if len(parts) >= 3:
                        name = parts[1]
                        version = parts[2]
                        dependencies.append({"name": name, "version": version})
                elif line.startswith('\t') and not line.startswith('\trequire'):
                    parts = line.split()
                    if len(parts) >= 2:
                        name = parts[0]
                        version = parts[1]
                        dependencies.append({"name": name, "version": version})
        
        return dependencies
    
    def _parse_maven_deps(self, content: str, manifest_type: str) -> List[Dict[str, str]]:
        """Parse Maven dependencies from pom.xml.
        
        Args:
            content: File content
            manifest_type: Type of manifest file
            
        Returns:
            List of dependencies with name and version
        """
        dependencies = []
        
        # Simple XML parsing (in production, use xml.etree.ElementTree)
        import xml.etree.ElementTree as ET
        try:
            root = ET.fromstring(content)
            namespace = {'mvn': 'http://maven.apache.org/POM/4.0.0'}
            
            for dep in root.findall('.//mvn:dependency', namespace):
                artifact_id = dep.find('mvn:artifactId', namespace)
                version = dep.find('mvn:version', namespace)
                
                if artifact_id is not None and version is not None:
                    group_id = dep.find('mvn:groupId', namespace)
                    name = f"{group_id.text if group_id is not None else ''}:{artifact_id.text}" if group_id is not None else artifact_id.text
                    dependencies.append({"name": name, "version": version.text})
        except:
            pass
        
        return dependencies
    
    def _parse_ruby_deps(self, content: str, manifest_type: str) -> List[Dict[str, str]]:
        """Parse Ruby dependencies from Gemfile.
        
        Args:
            content: File content
            manifest_type: Type of manifest file
            
        Returns:
            List of dependencies with name and version
        """
        dependencies = []
        
        if manifest_type == "Gemfile":
            # Simple Gemfile parsing
            import re
            gem_pattern = r"gem ['\"]([^'\"]+)['\"](?:, ['\"]([^'\"]+)['\"])?"
            
            for match in re.finditer(gem_pattern, content):
                name = match.group(1)
                version = match.group(2) if match.group(2) else "unknown"
                dependencies.append({"name": name, "version": version})
        
        return dependencies
    
    async def _check_vulnerabilities(
        self,
        package_name: str,
        version: str,
        ecosystem: str
    ) -> List[Dict[str, Any]]:
        """Check for vulnerabilities using OSV API.
        
        Args:
            package_name: Package name
            version: Package version
            ecosystem: Package ecosystem
            
        Returns:
            List of vulnerability information
        """
        # Check cache first
        cache_key = f"{ecosystem}:{package_name}:{version}"
        if cache_key in self.cve_cache:
            return self.cve_cache[cache_key]
        
        vulnerabilities = []
        
        try:
            # Query OSV API
            query = {
                "package": {
                    "name": package_name,
                    "ecosystem": ecosystem
                },
                "version": version
            }
            
            response = requests.post(self.osv_api_url, json=query, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                vulns = data.get("vulns", [])
                
                for vuln in vulns:
                    vulnerabilities.append({
                        "id": vuln.get("id"),
                        "summary": vuln.get("summary", ""),
                        "severity": self._parse_severity(vuln),
                        "fixed_version": self._get_fixed_version(vuln, package_name),
                        "cvss_score": self._get_cvss_score(vuln)
                    })
            
            # Cache results
            self.cve_cache[cache_key] = vulnerabilities
            
        except Exception as e:
            if self.verbose:
                logger.debug(f"Error checking {package_name}: {e}")
        
        return vulnerabilities
    
    def _parse_severity(self, vuln: Dict) -> Severity:
        """Parse severity from vulnerability data.
        
        Args:
            vuln: Vulnerability data from OSV
            
        Returns:
            Severity level
        """
        # Try to get CVSS score
        if "severity" in vuln:
            for severity_info in vuln["severity"]:
                if "score" in severity_info:
                    score = float(severity_info["score"])
                    if score >= 9.0:
                        return Severity.CRITICAL
                    elif score >= 7.0:
                        return Severity.HIGH
                    elif score >= 4.0:
                        return Severity.MEDIUM
                    else:
                        return Severity.LOW
        
        # Default to medium if unknown
        return Severity.MEDIUM
    
    def _get_fixed_version(self, vuln: Dict, package_name: str) -> Optional[str]:
        """Get fixed version from vulnerability data.
        
        Args:
            vuln: Vulnerability data from OSV
            package_name: Package name
            
        Returns:
            Fixed version or None
        """
        if "affected" in vuln:
            for affected in vuln["affected"]:
                if affected.get("package", {}).get("name") == package_name:
                    for range_info in affected.get("ranges", []):
                        if range_info.get("type") == "ECOSYSTEM":
                            for event in range_info.get("events", []):
                                if "fixed" in event:
                                    return event["fixed"]
        return None
    
    def _get_cvss_score(self, vuln: Dict) -> Optional[float]:
        """Extract CVSS score from vulnerability data.
        
        Args:
            vuln: Vulnerability data from OSV
            
        Returns:
            CVSS score or None
        """
        if "severity" in vuln:
            for severity_info in vuln["severity"]:
                if "score" in severity_info:
                    return float(severity_info["score"])
        return None
    
    def _create_finding(
        self,
        repo_name: str,
        dependency: Dict,
        vulnerability: Dict,
        ecosystem: str
    ) -> Optional[DependencyFinding]:
        """Create a dependency finding from vulnerability data.
        
        Args:
            repo_name: Repository name
            dependency: Dependency information
            vulnerability: Vulnerability information
            ecosystem: Package ecosystem
            
        Returns:
            DependencyFinding or None if below severity threshold
        """
        severity = vulnerability.get("severity", Severity.MEDIUM)
        
        # Check severity threshold
        if severity.value > self.severity_threshold.value:
            return None
        
        return DependencyFinding.create(
            repository=repo_name,
            package_name=dependency["name"],
            installed_version=dependency["version"],
            vulnerable_versions=f"< {vulnerability.get('fixed_version', 'unknown')}",
            severity=severity,
            cve_ids=[vulnerability.get("id")],
            cvss_score=vulnerability.get("cvss_score"),
            fixed_version=vulnerability.get("fixed_version"),
            ecosystem=ecosystem
        )
    
    def get_statistics(self, findings: List[DependencyFinding]) -> Dict[str, Any]:
        """Get statistics about dependency findings.
        
        Args:
            findings: List of dependency findings
            
        Returns:
            Dictionary with statistics
        """
        stats = {
            "total_vulnerabilities": len(findings),
            "by_severity": {},
            "by_ecosystem": {},
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0
        }
        
        for finding in findings:
            # Count by severity
            severity = finding.severity.value
            stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1
            
            # Count by ecosystem
            ecosystem = finding.ecosystem
            stats["by_ecosystem"][ecosystem] = stats["by_ecosystem"].get(ecosystem, 0) + 1
            
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