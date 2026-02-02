"""Report generation for lattix_guard (JSON and HTML).

SECURITY GUARANTEES:
- All user-derived content escaped with markupsafe.escape()
- Jinja2 configured with autoescape=True
- Only relative paths in reports (no absolute system paths)
"""

import json
from datetime import datetime
from pathlib import Path
from typing import List

from jinja2 import Environment, FileSystemLoader, select_autoescape
from markupsafe import escape

from .scanner import ScanResult
from .rules.base import Finding


def _sanitize_path(path: Path, project_root: Path) -> str:
    """Convert absolute path to relative path for safe inclusion in reports.

    SECURITY: Never expose absolute system paths in reports.

    Args:
        path: Path to sanitize
        project_root: Project root for relative path calculation

    Returns:
        Relative path string
    """
    try:
        rel_path = path.relative_to(project_root)
        return str(rel_path)
    except ValueError:
        # Path is outside project root - use only the filename
        return path.name


def generate_json_report(scan_result: ScanResult, output_path: Path) -> None:
    """Generate JSON report from scan result.

    Args:
        scan_result: ScanResult from scanner
        output_path: Path to write JSON file
    """
    # Build report structure
    report = {
        "scan_metadata": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "project_path": _sanitize_path(scan_result.project_path, scan_result.project_path.parent),
            "lattix_guard_version": "0.1.0",
            "duration_ms": scan_result.scan_duration_ms,
            "files_scanned": scan_result.files_scanned
        },
        "score": scan_result.score_details,
        "summary": {
            "total_findings": scan_result.score_details['total_findings'],
            "by_severity": scan_result.score_details['by_severity']
        },
        "findings": [
            finding.to_dict()
            for finding in scan_result.findings
        ],
        "errors": scan_result.errors
    }

    # Write JSON file
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)


def generate_html_report(scan_result: ScanResult, output_path: Path) -> None:
    """Generate HTML report from scan result.

    SECURITY: Uses Jinja2 with autoescape=True and markupsafe.escape()

    Args:
        scan_result: ScanResult from scanner
        output_path: Path to write HTML file
    """
    # Get template directory
    template_dir = Path(__file__).parent.parent / 'templates'

    # Configure Jinja2 with autoescape for security
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(['html', 'xml', 'jinja', 'jinja2'])
    )

    # Add custom filter for additional escaping
    env.filters['escape'] = escape

    # Load template
    template = env.get_template('report.html.jinja')

    # Group findings by severity
    findings_by_severity = {
        'CRITICAL': [],
        'HIGH': [],
        'MEDIUM': [],
        'LOW': [],
        'INFO': []
    }

    for finding in scan_result.findings:
        severity = finding.severity.value
        findings_by_severity[severity].append(finding)

    # Prepare template data
    template_data = {
        'timestamp': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
        'project_path': _sanitize_path(scan_result.project_path, scan_result.project_path.parent),
        'version': '0.1.0',
        'duration_ms': scan_result.scan_duration_ms,
        'files_scanned': scan_result.files_scanned,
        'score': scan_result.score_details['score'],
        'grade': scan_result.score_details['grade'],
        'total_findings': scan_result.score_details['total_findings'],
        'severity_counts': scan_result.score_details['by_severity'],
        'findings_by_severity': findings_by_severity,
        'errors': scan_result.errors
    }

    # Render template
    html_content = template.render(**template_data)

    # Write HTML file
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w') as f:
        f.write(html_content)


def generate_reports(
    scan_result: ScanResult,
    output_dir: Path,
    formats: List[str] = None
) -> dict:
    """Generate reports in specified formats.

    Args:
        scan_result: ScanResult from scanner
        output_dir: Directory to write reports
        formats: List of formats ('json', 'html', 'both'). Default: ['both']

    Returns:
        Dictionary with paths to generated reports:
        {
            'json': Path or None,
            'html': Path or None
        }
    """
    if formats is None:
        formats = ['both']

    # Normalize formats
    generate_json = 'json' in formats or 'both' in formats
    generate_html = 'html' in formats or 'both' in formats

    generated = {
        'json': None,
        'html': None
    }

    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)

    # Generate JSON report
    if generate_json:
        json_path = output_dir / 'report.json'
        generate_json_report(scan_result, json_path)
        generated['json'] = json_path

    # Generate HTML report
    if generate_html:
        html_path = output_dir / 'report.html'
        generate_html_report(scan_result, html_path)
        generated['html'] = html_path

    return generated
