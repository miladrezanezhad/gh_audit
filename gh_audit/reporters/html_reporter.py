# gh_audit/reporters/html_reporter.py
"""Jinja2 HTML report generator with Chart.js dashboard and interactive filters."""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
from collections import Counter

from jinja2 import Template

from gh_audit.models.finding import Finding, Severity, FindingType
from gh_audit.models.finding import OrganizationScore


class HTMLReporter:
    """Generate interactive HTML reports with charts and filtering."""
    
    def __init__(self):
        """Initialize HTML reporter."""
        self.template = self._get_template()
    
    def generate(
        self,
        findings: List[Finding],
        org_scores: Dict[str, float],
        output_path: str,
        organization: str
    ) -> None:
        """Generate HTML report from findings.
        
        Args:
            findings: List of security findings
            org_scores: Dictionary mapping repository names to scores
            output_path: Path where to save the HTML file
            organization: Organization name
        """
        # Prepare data for template
        report_data = self._prepare_report_data(findings, org_scores, organization)
        
        # Render template
        html_content = self.template.render(**report_data)
        
        # Write to file
        output_file = Path(output_path)
        output_file.write_text(html_content, encoding='utf-8')
    
    def _prepare_report_data(
        self,
        findings: List[Finding],
        org_scores: Dict[str, float],
        organization: str
    ) -> Dict[str, Any]:
        """Prepare data for HTML template.
        
        Args:
            findings: List of findings
            org_scores: Repository scores
            organization: Organization name
            
        Returns:
            Dictionary with template variables
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
        
        # Average score
        avg_score = sum(org_scores.values()) / len(org_scores) if org_scores else 0
        
        # Top repositories by finding count
        repo_finding_counts = Counter(f.repository for f in findings)
        top_repos = repo_finding_counts.most_common(10)
        
        # Findings by repository (for table view)
        findings_by_repo = {}
        for finding in findings:
            repo_name = finding.repository.split('/')[-1]
            if repo_name not in findings_by_repo:
                findings_by_repo[repo_name] = []
            findings_by_repo[repo_name].append(finding)
        
        # Prepare timeline data (findings over time)
        timeline_data = self._prepare_timeline_data(findings)
        
        # Prepare severity distribution for chart
        severity_data = {
            "labels": ["Critical", "High", "Medium", "Low"],
            "values": [critical, high, medium, low],
            "colors": ["#dc3545", "#fd7e14", "#ffc107", "#28a745"]
        }
        
        # Prepare type distribution for chart
        type_data = {
            "labels": ["Secrets", "Dependencies", "Configuration"],
            "values": [secret_count, dependency_count, config_count],
            "colors": ["#dc3545", "#ffc107", "#17a2b8"]
        }
        
        # Prepare repository scores for chart
        repo_names = list(org_scores.keys())
        repo_scores = list(org_scores.values())
        # Limit to top 20 for readability
        if len(repo_names) > 20:
            repo_names = repo_names[:20]
            repo_scores = repo_scores[:20]
        
        return {
            "organization": organization,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_findings": total_findings,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "secret_count": secret_count,
            "dependency_count": dependency_count,
            "config_count": config_count,
            "avg_score": round(avg_score, 1),
            "total_repositories": len(org_scores),
            "top_repos": top_repos,
            "findings_by_repo": findings_by_repo,
            "timeline_data": json.dumps(timeline_data),
            "severity_data": json.dumps(severity_data),
            "type_data": json.dumps(type_data),
            "repo_names": json.dumps(repo_names),
            "repo_scores": json.dumps(repo_scores),
            "findings_json": json.dumps([self._finding_to_dict(f) for f in findings])
        }
    
    def _prepare_timeline_data(self, findings: List[Finding]) -> Dict[str, List]:
        """Prepare timeline data for Chart.js.
        
        Args:
            findings: List of findings
            
        Returns:
            Dictionary with dates and counts
        """
        date_counts = Counter()
        
        for finding in findings:
            date_key = finding.discovered_at.strftime("%Y-%m-%d")
            date_counts[date_key] += 1
        
        # Sort by date
        sorted_dates = sorted(date_counts.items())
        
        return {
            "dates": [date for date, _ in sorted_dates],
            "counts": [count for _, count in sorted_dates]
        }
    
    def _finding_to_dict(self, finding: Finding) -> Dict[str, Any]:
        """Convert finding to dictionary for JSON serialization.
        
        Args:
            finding: Finding object
            
        Returns:
            Dictionary representation
        """
        return {
            "title": finding.title,
            "severity": finding.severity.value,
            "type": finding.type.value,
            "repository": finding.repository,
            "description": finding.description,
            "location": finding.location,
            "remediation": finding.remediation,
            "discovered_at": finding.discovered_at.isoformat()
        }
    
    def _get_template(self) -> Template:
        """Get Jinja2 HTML template.
        
        Returns:
            Jinja2 Template object
        """
        template_str = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Audit Report - {{ organization }}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: #f5f7fb;
            color: #1a202c;
            line-height: 1.6;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header .meta {
            opacity: 0.9;
            font-size: 0.9em;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 12px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }
        
        .stat-card h3 {
            font-size: 0.9em;
            color: #718096;
            margin-bottom: 10px;
            text-transform: uppercase;
        }
        
        .stat-card .value {
            font-size: 2.5em;
            font-weight: bold;
        }
        
        .stat-card.critical .value { color: #dc3545; }
        .stat-card.high .value { color: #fd7e14; }
        .stat-card.medium .value { color: #ffc107; }
        .stat-card.low .value { color: #28a745; }
        
        .chart-container {
            background: white;
            padding: 20px;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .chart-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .filters {
            background: white;
            padding: 20px;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .filter-group {
            display: inline-block;
            margin-right: 20px;
        }
        
        .filter-group label {
            margin-right: 10px;
            font-weight: 500;
        }
        
        select, input {
            padding: 8px 12px;
            border: 1px solid #e2e8f0;
            border-radius: 6px;
            font-size: 14px;
        }
        
        .findings-table {
            background: white;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .findings-table table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .findings-table th {
            background: #f7fafc;
            padding: 15px;
            text-align: left;
            font-weight: 600;
            color: #4a5568;
            border-bottom: 2px solid #e2e8f0;
        }
        
        .findings-table td {
            padding: 12px 15px;
            border-bottom: 1px solid #e2e8f0;
        }
        
        .severity-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .severity-critical { background: #dc3545; color: white; }
        .severity-high { background: #fd7e14; color: white; }
        .severity-medium { background: #ffc107; color: #1a202c; }
        .severity-low { background: #28a745; color: white; }
        
        .type-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: 600;
        }
        
        .type-secret { background: #dc3545; color: white; }
        .type-dependency { background: #ffc107; color: #1a202c; }
        .type-configuration { background: #17a2b8; color: white; }
        
        .remediation {
            background: #f0f9ff;
            padding: 8px;
            border-radius: 6px;
            margin-top: 8px;
            font-size: 0.9em;
            color: #0369a1;
        }
        
        @media (max-width: 768px) {
            .chart-grid {
                grid-template-columns: 1fr;
            }
            
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Security Audit Report</h1>
            <p><strong>{{ organization }}</strong></p>
            <p class="meta">Generated: {{ generated_at }}</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Findings</h3>
                <div class="value">{{ total_findings }}</div>
            </div>
            <div class="stat-card critical">
                <h3>Critical</h3>
                <div class="value">{{ critical }}</div>
            </div>
            <div class="stat-card high">
                <h3>High</h3>
                <div class="value">{{ high }}</div>
            </div>
            <div class="stat-card medium">
                <h3>Medium</h3>
                <div class="value">{{ medium }}</div>
            </div>
            <div class="stat-card low">
                <h3>Low</h3>
                <div class="value">{{ low }}</div>
            </div>
            <div class="stat-card">
                <h3>Avg Security Score</h3>
                <div class="value">{{ avg_score }}/100</div>
            </div>
        </div>
        
        <div class="chart-grid">
            <div class="chart-container">
                <canvas id="severityChart"></canvas>
            </div>
            <div class="chart-container">
                <canvas id="typeChart"></canvas>
            </div>
        </div>
        
        <div class="chart-container">
            <canvas id="scoresChart"></canvas>
        </div>
        
        <div class="filters">
            <h3>🔍 Filter Findings</h3>
            <div class="filter-group">
                <label>Severity:</label>
                <select id="severityFilter">
                    <option value="all">All</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Type:</label>
                <select id="typeFilter">
                    <option value="all">All</option>
                    <option value="secret">Secrets</option>
                    <option value="dependency">Dependencies</option>
                    <option value="configuration">Configuration</option>
                </select>
            </div>
            <div class="filter-group">
                <label>Repository:</label>
                <input type="text" id="repoFilter" placeholder="Repository name...">
            </div>
        </div>
        
        <div class="findings-table">
            <table id="findingsTable">
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Type</th>
                        <th>Repository</th>
                        <th>Title</th>
                        <th>Location</th>
                        <th>Remediation</th>
                    </tr>
                </thead>
                <tbody id="findingsBody"></tbody>
            </table>
        </div>
    </div>
    
    <script>
        const findingsData = {{ findings_json | safe }};
        
        // Initialize charts
        const severityData = {{ severity_data | safe }};
        const typeData = {{ type_data | safe }};
        
        new Chart(document.getElementById('severityChart'), {
            type: 'bar',
            data: {
                labels: severityData.labels,
                datasets: [{
                    label: 'Findings by Severity',
                    data: severityData.values,
                    backgroundColor: severityData.colors
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { position: 'top' },
                    title: { display: true, text: 'Findings by Severity' }
                }
            }
        });
        
        new Chart(document.getElementById('typeChart'), {
            type: 'pie',
            data: {
                labels: typeData.labels,
                datasets: [{
                    data: typeData.values,
                    backgroundColor: typeData.colors
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { position: 'top' },
                    title: { display: true, text: 'Findings by Type' }
                }
            }
        });
        
        const repoNames = {{ repo_names | safe }};
        const repoScores = {{ repo_scores | safe }};
        
        new Chart(document.getElementById('scoresChart'), {
            type: 'bar',
            data: {
                labels: repoNames,
                datasets: [{
                    label: 'Security Score (0-100)',
                    data: repoScores,
                    backgroundColor: '#667eea'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: { position: 'top' },
                    title: { display: true, text: 'Repository Security Scores' }
                },
                scales: {
                    y: {
                        min: 0,
                        max: 100,
                        title: { display: true, text: 'Score' }
                    }
                }
            }
        });
        
        // Filter and render findings
        function renderFindings() {
            const severityFilter = document.getElementById('severityFilter').value;
            const typeFilter = document.getElementById('typeFilter').value;
            const repoFilter = document.getElementById('repoFilter').value.toLowerCase();
            
            const filtered = findingsData.filter(f => {
                if (severityFilter !== 'all' && f.severity !== severityFilter) return false;
                if (typeFilter !== 'all' && f.type !== typeFilter) return false;
                if (repoFilter && !f.repository.toLowerCase().includes(repoFilter)) return false;
                return true;
            });
            
            const tbody = document.getElementById('findingsBody');
            tbody.innerHTML = '';
            
            filtered.forEach(f => {
                const row = tbody.insertRow();
                row.innerHTML = `
                    <td><span class="severity-badge severity-${f.severity}">${f.severity}</span></td>
                    <td><span class="type-badge type-${f.type}">${f.type}</span></td>
                    <td>${f.repository.split('/').pop()}</td>
                    <td><strong>${f.title}</strong><br><small>${f.description.substring(0, 100)}...</small></td>
                    <td><code>${f.location || 'N/A'}</code></td>
                    <td><div class="remediation">${f.remediation || 'No remediation provided'}</div></td>
                `;
            });
        }
        
        document.getElementById('severityFilter').addEventListener('change', renderFindings);
        document.getElementById('typeFilter').addEventListener('change', renderFindings);
        document.getElementById('repoFilter').addEventListener('input', renderFindings);
        
        renderFindings();
    </script>
</body>
</html>"""
        
        return Template(template_str)