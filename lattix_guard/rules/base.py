"""Base types for lattix_guard security rules."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Severity(Enum):
    """Security finding severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Evidence:
    """Evidence for a security finding.

    Contains the location and context of a security issue.
    """
    file: str  # Relative path to file
    line: Optional[int] = None  # Line number (if applicable)
    key: Optional[str] = None  # YAML key path (e.g., "services.api.privileged")
    snippet: Optional[str] = None  # Code snippet showing the issue

    def __post_init__(self):
        """Validate and normalize evidence data."""
        # Ensure file path is relative (security: no absolute paths)
        if self.file.startswith('/'):
            # Convert to relative path by removing leading /
            parts = self.file.split('/')
            self.file = '/'.join(parts[1:]) if len(parts) > 1 else parts[0]


@dataclass
class Finding:
    """A security finding from a rule.

    Represents a detected security issue with full context.
    """
    rule_id: str  # e.g., "DOCKER-001"
    title: str  # Short title
    severity: Severity
    description: str  # Detailed description of the issue
    recommendation: str  # How to fix it
    evidence: List[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert finding to dictionary for JSON serialization."""
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "recommendation": self.recommendation,
            "evidence": [
                {
                    "file": e.file,
                    "line": e.line,
                    "key": e.key,
                    "snippet": e.snippet
                }
                for e in self.evidence
            ]
        }


class Rule(ABC):
    """Base class for all security rules.

    Each rule checks for a specific security issue and returns findings.
    """

    @property
    @abstractmethod
    def id(self) -> str:
        """Unique rule identifier (e.g., 'DOCKER-001')."""
        pass

    @property
    @abstractmethod
    def title(self) -> str:
        """Short rule title."""
        pass

    @property
    @abstractmethod
    def severity(self) -> Severity:
        """Default severity level for this rule."""
        pass

    @abstractmethod
    def check(self, parsed_data: dict) -> List[Finding]:
        """Check rule against parsed project data.

        Args:
            parsed_data: Dictionary containing:
                - 'docker_compose': Parsed docker-compose.yml data
                - 'python_files': Dict of filename -> AST analysis results
                - 'env_files': List of .env file paths
                - 'gitignore': Parsed .gitignore patterns
                - 'project_root': Root directory of scanned project

        Returns:
            List of Finding objects (empty list if no issues found)
        """
        pass

    def _create_finding(
        self,
        description: str,
        recommendation: str,
        evidence: List[Evidence]
    ) -> Finding:
        """Helper to create a finding with rule metadata.

        Args:
            description: Detailed description of the specific issue
            recommendation: Concrete steps to fix the issue
            evidence: List of Evidence objects showing where the issue was found

        Returns:
            Finding object with rule metadata
        """
        return Finding(
            rule_id=self.id,
            title=self.title,
            severity=self.severity,
            description=description,
            recommendation=recommendation,
            evidence=evidence
        )
