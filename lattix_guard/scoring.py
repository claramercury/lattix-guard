"""Security score calculation for lattix_guard."""

from typing import List, Dict
from .rules.base import Severity, Finding


# Severity weights for score deduction
SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 20,
    Severity.HIGH: 10,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFO: 0,
}


def calculate_score(findings: List[Finding]) -> Dict:
    """Calculate security score (0-100) based on findings.

    Scoring algorithm:
    - Start with 100 points
    - Deduct points based on severity:
      - CRITICAL: -20 points
      - HIGH: -10 points
      - MEDIUM: -5 points
      - LOW: -2 points
      - INFO: -0 points
    - Floor at 0 (cannot go negative)

    Args:
        findings: List of Finding objects

    Returns:
        Dictionary with score details:
        {
            'score': 85,
            'grade': 'B',
            'deductions': {
                'CRITICAL': 0,
                'HIGH': 10,
                'MEDIUM': 5,
                'LOW': 0,
                'INFO': 0
            },
            'total_findings': 3,
            'by_severity': {
                'CRITICAL': 0,
                'HIGH': 1,
                'MEDIUM': 1,
                'LOW': 0,
                'INFO': 1
            }
        }
    """
    base_score = 100
    deductions = {severity: 0 for severity in Severity}
    severity_counts = {severity: 0 for severity in Severity}

    # Calculate deductions and count findings by severity
    for finding in findings:
        severity = finding.severity
        deduction = SEVERITY_WEIGHTS[severity]

        deductions[severity] += deduction
        severity_counts[severity] += 1
        base_score -= deduction

    # Floor at 0
    final_score = max(0, base_score)

    # Calculate grade
    grade = _calculate_grade(final_score)

    return {
        'score': final_score,
        'grade': grade,
        'deductions': {s.value: d for s, d in deductions.items()},
        'total_findings': len(findings),
        'by_severity': {s.value: c for s, c in severity_counts.items()}
    }


def _calculate_grade(score: int) -> str:
    """Convert numeric score to letter grade.

    Grading scale:
    - 90-100: A (Excellent)
    - 80-89: B (Good)
    - 70-79: C (Fair)
    - 60-69: D (Poor)
    - 0-59: F (Critical issues)

    Args:
        score: Numeric score (0-100)

    Returns:
        Letter grade (A, B, C, D, F)
    """
    if score >= 90:
        return 'A'
    elif score >= 80:
        return 'B'
    elif score >= 70:
        return 'C'
    elif score >= 60:
        return 'D'
    else:
        return 'F'


def get_grade_description(grade: str) -> str:
    """Get human-readable description for a grade.

    Args:
        grade: Letter grade

    Returns:
        Description string
    """
    descriptions = {
        'A': 'Excellent security posture',
        'B': 'Good security, minor improvements needed',
        'C': 'Fair security, several issues to address',
        'D': 'Poor security, significant gaps present',
        'F': 'Critical security issues, immediate action required'
    }

    return descriptions.get(grade, 'Unknown grade')
