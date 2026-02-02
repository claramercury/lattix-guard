"""Tests for scoring system."""

import pytest
from lattix_guard.scoring import calculate_score, _calculate_grade, get_grade_description
from lattix_guard.rules.base import Severity, Finding, Evidence


def test_perfect_score():
    """Test scoring with no findings."""
    findings = []

    result = calculate_score(findings)

    assert result['score'] == 100, "Should have perfect score with no findings"
    assert result['grade'] == 'A'
    assert result['total_findings'] == 0
    assert all(count == 0 for count in result['by_severity'].values())


def test_critical_deduction():
    """Test that CRITICAL findings deduct 20 points each."""
    findings = [
        Finding(
            rule_id="TEST-001",
            title="Test",
            severity=Severity.CRITICAL,
            description="Test",
            recommendation="Test",
            evidence=[]
        )
    ]

    result = calculate_score(findings)

    assert result['score'] == 80, "CRITICAL should deduct 20 points"
    assert result['grade'] == 'B'
    assert result['deductions']['CRITICAL'] == 20


def test_multiple_severities():
    """Test scoring with mix of severities."""
    findings = [
        Finding("T1", "Test", Severity.CRITICAL, "Test", "Test", []),  # -20
        Finding("T2", "Test", Severity.HIGH, "Test", "Test", []),  # -10
        Finding("T3", "Test", Severity.MEDIUM, "Test", "Test", []),  # -5
        Finding("T4", "Test", Severity.LOW, "Test", "Test", []),  # -2
        Finding("T5", "Test", Severity.INFO, "Test", "Test", []),  # -0
    ]

    result = calculate_score(findings)

    # Score should be 100 - 20 - 10 - 5 - 2 = 63
    assert result['score'] == 63, "Should deduct correct points"
    assert result['grade'] == 'D'
    assert result['total_findings'] == 5
    assert result['by_severity']['CRITICAL'] == 1
    assert result['by_severity']['HIGH'] == 1
    assert result['by_severity']['MEDIUM'] == 1
    assert result['by_severity']['LOW'] == 1
    assert result['by_severity']['INFO'] == 1


def test_score_floor():
    """Test that score doesn't go below 0."""
    # Create 10 CRITICAL findings (10 * 20 = 200 points deduction)
    findings = [
        Finding("T", "Test", Severity.CRITICAL, "Test", "Test", [])
        for _ in range(10)
    ]

    result = calculate_score(findings)

    assert result['score'] == 0, "Score should floor at 0"
    assert result['grade'] == 'F'


def test_grade_boundaries():
    """Test grade calculation boundaries."""
    assert _calculate_grade(100) == 'A'
    assert _calculate_grade(90) == 'A'
    assert _calculate_grade(89) == 'B'
    assert _calculate_grade(80) == 'B'
    assert _calculate_grade(79) == 'C'
    assert _calculate_grade(70) == 'C'
    assert _calculate_grade(69) == 'D'
    assert _calculate_grade(60) == 'D'
    assert _calculate_grade(59) == 'F'
    assert _calculate_grade(0) == 'F'


def test_grade_descriptions():
    """Test that all grades have descriptions."""
    assert 'Excellent' in get_grade_description('A')
    assert 'Good' in get_grade_description('B')
    assert 'Fair' in get_grade_description('C')
    assert 'Poor' in get_grade_description('D')
    assert 'Critical' in get_grade_description('F')
