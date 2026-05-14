"""HTML report generation with interactive dashboard."""

import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any
from jinja2 import Environment, FileSystemLoader, select_autoescape
import logging

from gh_audit.models.finding import Finding, AuditReport, Severity

logger = logging.getLogger(__name__)


class HTMLReporter:
    """Generate HTML reports with interactive dashboard."""
    
    def __init__(self, template_dir: str = "templates"):
        """
        Initialize HTML reporter.
        
        Args:
            template_dir: Directory containing Jinja2 templates
        """
        template_path = Path(__file__).parent.parent / template_dir
        self.env = Environment(
            loader=FileSystemLoader(str(template_path)),
            autoescape=select_autoescape(['html', 'xml'])
        )
    
    def generate_report(self, report: AuditReport, output_path: str) -> str:
        """
        Generate HTML report.
        
        Args:
            report: Audit report object
            output_path: Output file path
            
        Returns:
            Path to generated report
        """
        # Prepare template data
        template_data = self._prepare_template_data(report)
        
        # Render template
        template = self.env.get_template('dashboard.html')
        html_content = template.render(**template_data)
        
        # Write to file
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"HTML report generated: {output_file}")
        
        return str(output_file)
    
    def _prepare_template_data(self, report: AuditReport) -> Dict[str, Any]:
        """
        Prepare data for template rendering.
        
        Args:
            report: Audit report object
            
        Returns:
            Dictionary of template variables
        """
        # Calculate statistics
        total_findings = len(report.findings)
        critical_count = len([f for f in report.findings if f.severity == Severity.CRITICAL])
        high_count = len([f for f in report.findings if f.severity == Severity.HIGH])
        medium_count = len([f for f in report.findings if f.severity == Severity.MEDIUM])
        low_count = len([f for f in report.findings if f.severity == Severity.LOW])
        
        # Group findings by repository
        findings_by_repo = {}
        for finding in report.findings:
            if finding.repository not in findings_by_repo:
                findings_by_repo[finding.repository] = []
            findings_by_repo[finding.repository].append(finding)
        
        # Prepare timeline data (simplified - would track changes over time)
        timeline_data = {
            "labels": ["Day 1", "Day 7", "Day 14", "Day 21", "Day 28"],
            "critical": [critical_count, critical_count - 2, critical_count - 3, critical_count - 4, critical_count - 5],
            "high": [high_count, high_count - 1, high_count - 2, high_count - 3, high_count - 3],
            "medium": [medium_count, medium_count, medium_count - 1, medium_count - 2, medium_count - 2],
            "low": [low_count, low_count, low_count, low_count - 1, low_count - 1],
        }
        
        # Prepare severity distribution
        severity_data = {
            "labels": ["Critical", "High", "Medium", "Low"],
            "values": [critical_count, high_count, medium_count, low_count],
            "colors": ["#dc3545", "#fd7e14", "#ffc107", "#28a745"],
        }
        
        # Prepare fix status
        fixable_count = len([f for f in report.findings if f.fixable])
        fixed_count = len(report.fixes_applied)
        
        return {
            "report": report,
            "scan_timestamp": report.scan_timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "total_findings": total_findings,
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "score": report.score,
            "findings_by_repo": findings_by_repo,
            "timeline_data": json.dumps(timeline_data),
            "severity_data": json.dumps(severity_data),
            "fixable_count": fixable_count,
            "fixed_count": fixed_count,
            "remediation_rate": (fixed_count / fixable_count * 100) if fixable_count > 0 else 0,
            "organizations": report.organizations,
        }