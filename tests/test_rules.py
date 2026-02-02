"""Tests for security rules."""

import pytest
from lattix_guard.rules.base import Severity
from lattix_guard.rules.docker_rules import (
    PrivilegedContainerRule,
    LatestImageTagRule,
    ExposedPortsRule
)
from lattix_guard.rules.fastapi_rules import CORSWildcardRule


def test_privileged_container_detection():
    """Test DOCKER-001: Privileged container detection."""
    rule = PrivilegedContainerRule()

    # Test case: service with privileged: true
    parsed_data = {
        "docker_compose": {
            "services": {
                "malicious": {
                    "image": "ubuntu",
                    "privileged": True
                }
            }
        }
    }

    findings = rule.check(parsed_data)

    assert len(findings) == 1, "Should detect one privileged container"
    assert findings[0].severity == Severity.CRITICAL, "Should be CRITICAL severity"
    assert "malicious" in findings[0].description, "Should mention service name"
    assert findings[0].rule_id == "DOCKER-001"
    assert findings[0].evidence[0].key == "services.malicious.privileged"


def test_privileged_container_not_detected_when_absent():
    """Test DOCKER-001: No false positives when privileged is absent."""
    rule = PrivilegedContainerRule()

    parsed_data = {
        "docker_compose": {
            "services": {
                "safe": {
                    "image": "ubuntu"
                    # No privileged key
                }
            }
        }
    }

    findings = rule.check(parsed_data)
    assert len(findings) == 0, "Should not detect issues in safe container"


def test_latest_tag_detection():
    """Test DOCKER-006: Detection of :latest tag."""
    rule = LatestImageTagRule()

    # Test case 1: Explicit :latest
    parsed_data = {
        "docker_compose": {
            "services": {
                "app1": {"image": "python:latest"},
                "app2": {"image": "ubuntu"}  # Implicit latest (no tag)
            }
        }
    }

    findings = rule.check(parsed_data)

    assert len(findings) == 2, "Should detect both explicit and implicit :latest"
    assert all(f.severity == Severity.LOW for f in findings)
    assert all(f.rule_id == "DOCKER-006" for f in findings)


def test_exposed_ports_to_all_interfaces():
    """Test DOCKER-003: Detection of ports exposed to 0.0.0.0."""
    rule = ExposedPortsRule()

    parsed_data = {
        "docker_compose": {
            "services": {
                "exposed": {
                    "ports": [
                        "0.0.0.0:8000:8000",  # Explicit 0.0.0.0
                        "9000:9000"  # Implicit 0.0.0.0
                    ]
                },
                "safe": {
                    "ports": [
                        "127.0.0.1:3000:3000"  # Safe: localhost only
                    ]
                }
            }
        }
    }

    findings = rule.check(parsed_data)

    # Should detect 2 issues (explicit and implicit 0.0.0.0)
    assert len(findings) == 2, "Should detect exposed ports"
    assert all(f.severity == Severity.HIGH for f in findings)
    assert all(f.rule_id == "DOCKER-003" for f in findings)


def test_cors_wildcard_detection():
    """Test FASTAPI-001: Detection of CORS wildcard."""
    rule = CORSWildcardRule()

    parsed_data = {
        "python_files": {
            "main.py": {
                "cors_middleware": [
                    {
                        "line": 15,
                        "allow_origins": ["*"]  # Wildcard
                    }
                ]
            }
        }
    }

    findings = rule.check(parsed_data)

    assert len(findings) == 1, "Should detect CORS wildcard"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].rule_id == "FASTAPI-001"
    assert findings[0].evidence[0].line == 15


def test_no_findings_on_empty_data():
    """Test that rules handle empty data gracefully."""
    rule = PrivilegedContainerRule()

    parsed_data = {
        "docker_compose": {},
        "python_files": {},
        "env_config": {}
    }

    findings = rule.check(parsed_data)
    assert len(findings) == 0, "Should handle empty data without errors"


def test_rule_properties():
    """Test that rules have required properties."""
    rule = PrivilegedContainerRule()

    assert rule.id == "DOCKER-001"
    assert isinstance(rule.title, str)
    assert rule.severity == Severity.CRITICAL
    assert callable(rule.check)
