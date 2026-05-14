"""JSON report generation."""

import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any
import logging

from gh_audit.models.finding import AuditReport

logger = logging.getLogger(__name__)


class JSONReporter:
    """Generate JSON reports."""
    
    def generate_report(self, report: AuditReport, output_path: str) -> str:
        """
        Generate JSON report.
        
        Args:
            report: Audit report object
            output_path: Output file path
            
        Returns:
            Path to generated report
        """
        # Convert report to dictionary
        report_dict = report.to_dict()
        
        # Add additional metadata
        report_dict["generated_at"] = datetime.utcnow().isoformat()
        report_dict["report_version"] = "1.0"
        
        # Write to file
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report_dict, f, indent=2, ensure_ascii=False)
        
        logger.info(f"JSON report generated: {output_file}")
        
        return str(output_file)
    
    def generate_summary(self, report: AuditReport) -> Dict[str, Any]:
        """
        Generate executive summary from report.
        
        Args:
            report: Audit report object
            
        Returns:
            Summary dictionary
        """
        return {
            "executive_summary": {
                "total_findings": len(report.findings),
                "security_score": report.score,
                "critical_findings": len(report.critical_findings),
                "fixable_findings": len(report.fixable_findings),
                "fixes_applied": len(report.fixes_applied),
                "scan_timestamp": report.scan_timestamp.isoformat(),
            },
            "top_critical_issues": [
                {
                    "title": f.title,
                    "repository": f.repository,
                    "severity": f.severity.value,
                }
                for f in report.critical_findings[:5]
            ],
            "findings_by_severity": report.findings_by_severity,
            "findings_by_type": report.findings_by_type,
            "organizations_scanned": report.organizations,
            "improvement_trend": self._calculate_trend(report),
        }
    
    def _calculate_trend(self, report: AuditReport) -> str:
        """
        Calculate security improvement trend.
        
        Args:
            report: Audit report object
            
        Returns:
            Trend description
        """
        # This would normally compare with previous reports
        # For now, provide based on fixable vs fixed ratio
        if report.fixes_applied:
            return "improving"
        elif report.critical_findings:
            return "needs_attention"
        else:
            return "stable"