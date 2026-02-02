"""Lattix Guard - Security auditing tool for Docker/FastAPI projects."""

__version__ = "0.1.0"
__author__ = "Clara Mercury"
__description__ = "Static security analysis for Docker and FastAPI configurations"

from .scanner import scan_project, SecurityScanner, ScanResult
from .rules.base import Rule, Finding, Severity, Evidence
from .scoring import calculate_score

__all__ = [
    '__version__',
    'scan_project',
    'SecurityScanner',
    'ScanResult',
    'Rule',
    'Finding',
    'Severity',
    'Evidence',
    'calculate_score'
]
