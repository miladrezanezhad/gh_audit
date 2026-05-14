# gh_audit/models/finding.py
"""Data models for security findings and organization scores."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum


class Severity(Enum):
    """Severity levels for security findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    
    def __lt__(self, other):
        """Compare severity levels for sorting."""
        order = {Severity.CRITICAL: 0, Severity.HIGH: 1, 
                 Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
        return order[self] < order[other]


class FindingType(Enum):
    """Types of security findings."""
    SECRET = "secret"
    DEPENDENCY = "dependency"
    CONFIGURATION = "configuration"


@dataclass
class Finding:
    """Base finding dataclass for all security issues."""
    
    type: FindingType
    severity: Severity
    title: str
    description: str
    repository: str
    location: Optional[str] = None
    remediation: Optional[str] = None
    auto_fixable: bool = False
    discovered_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for JSON serialization."""
        return {
            "type": self.type.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "repository": self.repository,
            "location": self.location,
            "remediation": self.remediation,
            "auto_fixable": self.auto_fixable,
            "discovered_at": self.discovered_at.isoformat(),
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Finding':
        """Create finding from dictionary."""
        return cls(
            type=FindingType(data["type"]),
            severity=Severity(data["severity"]),
            title=data["title"],
            description=data["description"],
            repository=data["repository"],
            location=data.get("location"),
            remediation=data.get("remediation"),
            auto_fixable=data.get("auto_fixable", False),
            discovered_at=datetime.fromisoformat(data["discovered_at"]),
            metadata=data.get("metadata", {})
        )


@dataclass
class SecretFinding(Finding):
    """Finding for exposed secrets in code."""
    
    secret_type: str = ""  # e.g., "API Key", "Password", "Token"
    file_path: str = ""
    line_number: Optional[int] = None
    commit_hash: Optional[str] = None
    commit_author: Optional[str] = None
    commit_date: Optional[datetime] = None
    
    def __post_init__(self):
        """Initialize as secret type finding."""
        self.type = FindingType.SECRET
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert secret finding to dictionary."""
        data = super().to_dict()
        data.update({
            "secret_type": self.secret_type,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "commit_hash": self.commit_hash,
            "commit_author": self.commit_author,
            "commit_date": self.commit_date.isoformat() if self.commit_date else None
        })
        return data
    
    @classmethod
    def create(
        cls,
        repository: str,
        secret_type: str,
        file_path: str,
        line_number: Optional[int],
        severity: Severity,
        description: str,
        remediation: Optional[str] = None
    ) -> 'SecretFinding':
        """Factory method to create a secret finding."""
        return cls(
            severity=severity,
            title=f"Exposed {secret_type} detected",
            description=description,
            repository=repository,
            location=f"{file_path}:{line_number}" if line_number else file_path,
            remediation=remediation or "Revoke the exposed secret immediately and remove it from git history using BFG Repo-Cleaner or git filter-branch.",
            auto_fixable=False,  # Secrets cannot be auto-fixed, require manual rotation
            secret_type=secret_type,
            file_path=file_path,
            line_number=line_number
        )


@dataclass
class DependencyFinding(Finding):
    """Finding for vulnerable dependencies."""
    
    package_name: str = ""
    installed_version: str = ""
    vulnerable_versions: str = ""
    fixed_version: Optional[str] = None
    cve_ids: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    ecosystem: str = ""  # pypi, npm, go, maven, etc.
    
    def __post_init__(self):
        """Initialize as dependency type finding."""
        self.type = FindingType.DEPENDENCY
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert dependency finding to dictionary."""
        data = super().to_dict()
        data.update({
            "package_name": self.package_name,
            "installed_version": self.installed_version,
            "vulnerable_versions": self.vulnerable_versions,
            "fixed_version": self.fixed_version,
            "cve_ids": self.cve_ids,
            "cvss_score": self.cvss_score,
            "ecosystem": self.ecosystem
        })
        return data
    
    @classmethod
    def create(
        cls,
        repository: str,
        package_name: str,
        installed_version: str,
        vulnerable_versions: str,
        severity: Severity,
        cve_ids: List[str],
        cvss_score: Optional[float] = None,
        fixed_version: Optional[str] = None,
        ecosystem: str = "unknown"
    ) -> 'DependencyFinding':
        """Factory method to create a dependency finding."""
        remediation = f"Update {package_name} to version {fixed_version}" if fixed_version else f"Review and update {package_name} to a secure version"
        
        return cls(
            severity=severity,
            title=f"Vulnerable dependency: {package_name} {installed_version}",
            description=f"Package {package_name} version {installed_version} is vulnerable to {len(cve_ids)} CVE(s).",
            repository=repository,
            location="dependency manifest",
            remediation=remediation,
            auto_fixable=bool(fixed_version),  # Auto-fixable if we know a fixed version
            package_name=package_name,
            installed_version=installed_version,
            vulnerable_versions=vulnerable_versions,
            fixed_version=fixed_version,
            cve_ids=cve_ids,
            cvss_score=cvss_score,
            ecosystem=ecosystem
        )


@dataclass
class ConfigFinding(Finding):
    """Finding for security misconfigurations."""
    
    config_category: str = ""  # branch_protection, secret_scanning, dependabot, etc.
    current_value: Any = None
    expected_value: Any = None
    auto_fix_strategy: Optional[str] = None
    
    def __post_init__(self):
        """Initialize as configuration type finding."""
        self.type = FindingType.CONFIGURATION
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration finding to dictionary."""
        data = super().to_dict()
        data.update({
            "config_category": self.config_category,
            "current_value": self.current_value,
            "expected_value": self.expected_value,
            "auto_fix_strategy": self.auto_fix_strategy
        })
        return data
    
    @classmethod
    def create(
        cls,
        repository: str,
        config_category: str,
        severity: Severity,
        title: str,
        description: str,
        remediation: str,
        current_value: Any = None,
        expected_value: Any = None,
        auto_fix_strategy: Optional[str] = None
    ) -> 'ConfigFinding':
        """Factory method to create a configuration finding."""
        return cls(
            severity=severity,
            title=title,
            description=description,
            repository=repository,
            location="repository settings",
            remediation=remediation,
            auto_fixable=bool(auto_fix_strategy),
            config_category=config_category,
            current_value=current_value,
            expected_value=expected_value,
            auto_fix_strategy=auto_fix_strategy
        )


@dataclass
class OrganizationScore:
    """Security score and summary for an organization or repository."""
    
    entity_name: str
    total_score: float  # 0-100
    secret_scan_score: float  # 0-100
    dependency_score: float  # 0-100
    config_score: float  # 0-100
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    findings_by_type: Dict[str, int] = field(default_factory=dict)
    generated_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert organization score to dictionary."""
        return {
            "entity_name": self.entity_name,
            "total_score": self.total_score,
            "secret_scan_score": self.secret_scan_score,
            "dependency_score": self.dependency_score,
            "config_score": self.config_score,
            "total_findings": self.total_findings,
            "critical_findings": self.critical_findings,
            "high_findings": self.high_findings,
            "medium_findings": self.medium_findings,
            "low_findings": self.low_findings,
            "findings_by_type": self.findings_by_type,
            "generated_at": self.generated_at.isoformat()
        }
    
    @classmethod
    def calculate(
        cls,
        entity_name: str,
        findings: List[Finding],
        secret_score: float = 100.0,
        dependency_score: float = 100.0,
        config_score: float = 100.0
    ) -> 'OrganizationScore':
        """Calculate scores based on findings."""
        
        # Count findings by severity
        critical = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in findings if f.severity == Severity.HIGH)
        medium = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        low = sum(1 for f in findings if f.severity == Severity.LOW)
        
        # Count by type
        findings_by_type = {
            "secret": sum(1 for f in findings if f.type == FindingType.SECRET),
            "dependency": sum(1 for f in findings if f.type == FindingType.DEPENDENCY),
            "configuration": sum(1 for f in findings if f.type == FindingType.CONFIGURATION)
        }
        
        # Calculate total score (weighted average of category scores)
        # Apply penalty based on finding severity
        penalty = (critical * 10) + (high * 5) + (medium * 2) + (low * 1)
        total_score = max(0, min(100, (secret_score + dependency_score + config_score) / 3 - (penalty / 10)))
        
        return cls(
            entity_name=entity_name,
            total_score=round(total_score, 1),
            secret_scan_score=round(secret_score, 1),
            dependency_score=round(dependency_score, 1),
            config_score=round(config_score, 1),
            total_findings=len(findings),
            critical_findings=critical,
            high_findings=high,
            medium_findings=medium,
            low_findings=low,
            findings_by_type=findings_by_type
        )