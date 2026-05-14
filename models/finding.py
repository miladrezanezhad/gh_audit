"""Data models for security findings."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
from uuid import uuid4


class Severity(str, Enum):
    """Security finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingType(str, Enum):
    """Types of security findings."""
    SECRET = "secret"
    VULNERABILITY = "vulnerability"
    CONFIG_ISSUE = "config_issue"
    POLICY_VIOLATION = "policy_violation"


@dataclass
class Finding:
    """Represents a security finding."""
    
    id: str = field(default_factory=lambda: str(uuid4()))
    type: FindingType = FindingType.CONFIG_ISSUE
    severity: Severity = Severity.MEDIUM
    title: str = ""
    description: str = ""
    repository: str = ""
    organization: str = ""
    
    # Location information
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    commit_hash: Optional[str] = None
    
    # Remediation
    fixable: bool = False
    fix_command: Optional[str] = None
    fix_strategy: Optional[str] = None
    
    # Metadata
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    reference_url: Optional[str] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "type": self.type.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "repository": self.repository,
            "organization": self.organization,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "commit_hash": self.commit_hash,
            "fixable": self.fixable,
            "fix_command": self.fix_command,
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "reference_url": self.reference_url,
            "created_at": self.created_at.isoformat(),
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        """Create finding from dictionary."""
        return cls(
            id=data.get("id", str(uuid4())),
            type=FindingType(data["type"]),
            severity=Severity(data["severity"]),
            title=data["title"],
            description=data["description"],
            repository=data["repository"],
            organization=data["organization"],
            file_path=data.get("file_path"),
            line_number=data.get("line_number"),
            commit_hash=data.get("commit_hash"),
            fixable=data.get("fixable", False),
            fix_command=data.get("fix_command"),
            cve_id=data.get("cve_id"),
            cvss_score=data.get("cvss_score"),
            reference_url=data.get("reference_url"),
            created_at=datetime.fromisoformat(data["created_at"]) if "created_at" in data else datetime.utcnow(),
        )


@dataclass
class AuditReport:
    """Complete audit report for an organization."""
    
    scan_timestamp: datetime = field(default_factory=datetime.utcnow)
    organizations: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    fixes_applied: List[str] = field(default_factory=list)
    score: float = 0.0
    
    @property
    def findings_by_severity(self) -> Dict[str, int]:
        """Count findings by severity."""
        counts = {sev.value: 0 for sev in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts
    
    @property
    def findings_by_type(self) -> Dict[str, int]:
        """Count findings by type."""
        counts = {ft.value: 0 for ft in FindingType}
        for finding in self.findings:
            counts[finding.type.value] += 1
        return counts
    
    @property
    def critical_findings(self) -> List[Finding]:
        """Get all critical findings."""
        return [f for f in self.findings if f.severity == Severity.CRITICAL]
    
    @property
    def fixable_findings(self) -> List[Finding]:
        """Get all fixable findings."""
        return [f for f in self.findings if f.fixable]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary."""
        return {
            "schema_version": "1.0",
            "scan_timestamp": self.scan_timestamp.isoformat(),
            "organizations": self.organizations,
            "findings": [f.to_dict() for f in self.findings],
            "findings_by_severity": self.findings_by_severity,
            "findings_by_type": self.findings_by_type,
            "fixes_applied": self.fixes_applied,
            "score": self.score,
            "total_findings": len(self.findings),
        }