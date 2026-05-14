# gh_audit/reporters/json_reporter.py
"""JSON report generator with schema version 1.0."""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
from collections import Counter

from gh_audit.models.finding import Finding, Severity, FindingType


class JSONReporter:
    """Generate JSON format reports for programmatic analysis."""
    
    SCHEMA_VERSION = "1.0"
    
    def __init__(self):
        """Initialize JSON reporter."""
        pass
    
    def generate(
        self,
        findings: List[Finding],
        org_scores: Dict[str, float],
        output_path: str,
        organization: str
    ) -> None:
        """Generate JSON report from findings.
        
        Args:
            findings: List of security findings
            org_scores: Dictionary mapping repository names to scores
            output_path: Path where to save the JSON file
            organization: Organization name
        """
        # Prepare report data
        report_data = self._prepare_report_data(findings, org_scores, organization)
        
        # Write to file
        output_file = Path(output_path)
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
    
    def _prepare_report_data(
        self,
        findings: List[Finding],
        org_scores: Dict[str, float],
        organization: str
    ) -> Dict[str, Any]:
        """Prepare complete report data structure.
        
        Args:
            findings: List of findings
            org_scores: Repository scores
            organization: Organization name
            
        Returns:
            Dictionary with complete report data
        """
        # Calculate summary statistics
        total_findings = len(findings)
        critical = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in findings if f.severity == Severity.HIGH)
        medium = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        low = sum(1 for f in findings if f.severity == Severity.LOW)
        
        # Findings by type
        secret_count = sum(1 for f in findings if f.type == FindingType.SECRET)
        dependency_count = sum(1 for f in findings if f.type == FindingType.DEPENDENCY)
        config_count = sum(1 for f in findings if f.type == FindingType.CONFIGURATION)
        
        # Calculate average score
        avg_score = sum(org_scores.values()) / len(org_scores) if org_scores else 0
        
        # Top repositories by finding count
        repo_finding_counts = Counter(f.repository for f in findings)
        top_repos = [
            {"repository": repo, "finding_count": count}
            for repo, count in repo_finding_counts.most_common(10)
        ]
        
        # Group findings by repository
        findings_by_repo = {}
        for finding in findings:
            repo_name = finding.repository
            if repo_name not in findings_by_repo:
                findings_by_repo[repo_name] = []
            findings_by_repo[repo_name].append(self._finding_to_dict(finding))
        
        # Prepare repository details with scores
        repositories = []
        for repo_name, score in org_scores.items():
            repo_findings = findings_by_repo.get(repo_name, [])
            repo_critical = sum(1 for f in repo_findings if f["severity"] == "critical")
            repo_high = sum(1 for f in repo_findings if f["severity"] == "high")
            repo_medium = sum(1 for f in repo_findings if f["severity"] == "medium")
            repo_low = sum(1 for f in repo_findings if f["severity"] == "low")
            
            repositories.append({
                "name": repo_name,
                "score": score,
                "total_findings": len(repo_findings),
                "critical_count": repo_critical,
                "high_count": repo_high,
                "medium_count": repo_medium,
                "low_count": repo_low,
                "findings": repo_findings
            })
        
        # Sort repositories by score (lowest first - most critical)
        repositories.sort(key=lambda x: x["score"])
        
        # Prepare timeline data
        timeline = self._prepare_timeline(findings)
        
        # Prepare severity distribution
        severity_distribution = {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low
        }
        
        # Prepare type distribution
        type_distribution = {
            "secret": secret_count,
            "dependency": dependency_count,
            "configuration": config_count
        }
        
        # Build complete report
        report = {
            "schema_version": self.SCHEMA_VERSION,
            "metadata": {
                "organization": organization,
                "generated_at": datetime.now().isoformat(),
                "total_repositories": len(org_scores),
                "average_security_score": round(avg_score, 2)
            },
            "summary": {
                "total_findings": total_findings,
                "severity_distribution": severity_distribution,
                "type_distribution": type_distribution,
                "top_repositories": top_repos
            },
            "repositories": repositories,
            "timeline": timeline,
            "all_findings": [self._finding_to_dict(f) for f in findings]
        }
        
        return report
    
    def _finding_to_dict(self, finding: Finding) -> Dict[str, Any]:
        """Convert finding to dictionary for JSON serialization.
        
        Args:
            finding: Finding object
            
        Returns:
            Dictionary representation
        """
        result = {
            "id": self._generate_finding_id(finding),
            "type": finding.type.value,
            "severity": finding.severity.value,
            "title": finding.title,
            "description": finding.description,
            "repository": finding.repository,
            "location": finding.location,
            "remediation": finding.remediation,
            "auto_fixable": finding.auto_fixable,
            "discovered_at": finding.discovered_at.isoformat()
        }
        
        # Add type-specific fields
        if finding.type == FindingType.SECRET:
            result["secret_type"] = getattr(finding, 'secret_type', None)
            result["file_path"] = getattr(finding, 'file_path', None)
            result["line_number"] = getattr(finding, 'line_number', None)
            result["commit_hash"] = getattr(finding, 'commit_hash', None)
            result["commit_author"] = getattr(finding, 'commit_author', None)
            result["commit_date"] = getattr(finding, 'commit_date', None)
            if result["commit_date"]:
                result["commit_date"] = result["commit_date"].isoformat() if hasattr(result["commit_date"], 'isoformat') else result["commit_date"]
        
        elif finding.type == FindingType.DEPENDENCY:
            result["package_name"] = getattr(finding, 'package_name', None)
            result["installed_version"] = getattr(finding, 'installed_version', None)
            result["vulnerable_versions"] = getattr(finding, 'vulnerable_versions', None)
            result["fixed_version"] = getattr(finding, 'fixed_version', None)
            result["cve_ids"] = getattr(finding, 'cve_ids', [])
            result["cvss_score"] = getattr(finding, 'cvss_score', None)
            result["ecosystem"] = getattr(finding, 'ecosystem', None)
        
        elif finding.type == FindingType.CONFIGURATION:
            result["config_category"] = getattr(finding, 'config_category', None)
            result["current_value"] = str(getattr(finding, 'current_value', None)) if getattr(finding, 'current_value', None) is not None else None
            result["expected_value"] = str(getattr(finding, 'expected_value', None)) if getattr(finding, 'expected_value', None) is not None else None
            result["auto_fix_strategy"] = getattr(finding, 'auto_fix_strategy', None)
        
        return result
    
    def _prepare_timeline(self, findings: List[Finding]) -> Dict[str, List]:
        """Prepare timeline data for findings over time.
        
        Args:
            findings: List of findings
            
        Returns:
            Dictionary with dates and findings
        """
        date_findings = {}
        
        for finding in findings:
            date_key = finding.discovered_at.strftime("%Y-%m-%d")
            if date_key not in date_findings:
                date_findings[date_key] = []
            date_findings[date_key].append({
                "title": finding.title,
                "severity": finding.severity.value,
                "repository": finding.repository
            })
        
        # Sort by date
        sorted_dates = sorted(date_findings.items())
        
        return {
            "dates": [date for date, _ in sorted_dates],
            "findings_by_date": [
                {"date": date, "findings": findings, "count": len(findings)}
                for date, findings in sorted_dates
            ]
        }
    
    def _generate_finding_id(self, finding: Finding) -> str:
        """Generate a unique ID for a finding.
        
        Args:
            finding: Finding object
            
        Returns:
            Unique ID string
        """
        import hashlib
        
        # Create unique string based on finding attributes
        unique_string = f"{finding.repository}|{finding.title}|{finding.location}|{finding.discovered_at.isoformat()}"
        
        # Generate hash
        return hashlib.md5(unique_string.encode()).hexdigest()[:12]
    
    def export_csv(self, findings: List[Finding], output_path: str) -> None:
        """Export findings to CSV format for spreadsheet analysis.
        
        Args:
            findings: List of findings
            output_path: Path where to save the CSV file
        """
        import csv
        
        output_file = Path(output_path)
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow([
                "ID", "Type", "Severity", "Title", "Description",
                "Repository", "Location", "Remediation", "Auto-fixable", "Discovered At"
            ])
            
            # Write rows
            for finding in findings:
                writer.writerow([
                    self._generate_finding_id(finding),
                    finding.type.value,
                    finding.severity.value,
                    finding.title,
                    finding.description,
                    finding.repository,
                    finding.location or "",
                    finding.remediation or "",
                    "Yes" if finding.auto_fixable else "No",
                    finding.discovered_at.isoformat()
                ])
    
    def generate_comparison_report(
        self,
        current_findings: List[Finding],
        previous_findings: List[Finding],
        output_path: str
    ) -> None:
        """Generate a comparison report between two audit runs.
        
        Args:
            current_findings: Findings from current audit
            previous_findings: Findings from previous audit
            output_path: Path where to save the comparison report
        """
        # Create sets for comparison
        current_ids = {self._generate_finding_id(f) for f in current_findings}
        previous_ids = {self._generate_finding_id(f) for f in previous_findings}
        
        # New findings (in current but not in previous)
        new_findings = [f for f in current_findings if self._generate_finding_id(f) not in previous_ids]
        
        # Fixed findings (in previous but not in current)
        fixed_findings = [f for f in previous_findings if self._generate_finding_id(f) not in current_ids]
        
        # Persistent findings (in both)
        persistent_ids = current_ids & previous_ids
        persistent_findings = [f for f in current_findings if self._generate_finding_id(f) in persistent_ids]
        
        # Build comparison report
        comparison = {
            "schema_version": self.SCHEMA_VERSION,
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "current_total": len(current_findings),
                "previous_total": len(previous_findings),
                "new_findings": len(new_findings),
                "fixed_findings": len(fixed_findings),
                "persistent_findings": len(persistent_findings),
                "improvement_rate": self._calculate_improvement_rate(current_findings, previous_findings)
            },
            "new_findings": [self._finding_to_dict(f) for f in new_findings],
            "fixed_findings": [self._finding_to_dict(f) for f in fixed_findings],
            "persistent_findings": [self._finding_to_dict(f) for f in persistent_findings]
        }
        
        # Write to file
        output_file = Path(output_path)
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(comparison, f, indent=2, ensure_ascii=False)
    
    def _calculate_improvement_rate(
        self,
        current_findings: List[Finding],
        previous_findings: List[Finding]
    ) -> float:
        """Calculate improvement rate between two audits.
        
        Args:
            current_findings: Current audit findings
            previous_findings: Previous audit findings
            
        Returns:
            Improvement rate as percentage (positive = improvement)
        """
        if not previous_findings:
            return 0.0
        
        # Weight findings by severity
        severity_weights = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 5,
            Severity.MEDIUM: 2,
            Severity.LOW: 1
        }
        
        def calculate_weighted_score(findings):
            return sum(severity_weights.get(f.severity, 1) for f in findings)
        
        prev_score = calculate_weighted_score(previous_findings)
        curr_score = calculate_weighted_score(current_findings)
        
        if prev_score == 0:
            return 0.0
        
        improvement = ((prev_score - curr_score) / prev_score) * 100
        return round(improvement, 2)