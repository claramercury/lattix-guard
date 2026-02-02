"""General security rules applicable to any project."""

from pathlib import Path
from typing import List
from .base import Rule, Severity, Finding, Evidence
from . import register_rule


@register_rule
class CertificateFilesInRepoRule(Rule):
    """GENERAL-001: Detect certificate/key files in repository."""

    @property
    def id(self) -> str:
        return "GENERAL-001"

    @property
    def title(self) -> str:
        return "Certificate or key files found in repository"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    def check(self, parsed_data: dict) -> List[Finding]:
        findings = []
        env_config = parsed_data.get("env_config", {})
        cert_files = env_config.get("cert_files", [])
        project_root = parsed_data.get("project_root", Path())

        for cert_file in cert_files:
            # Get relative path
            try:
                rel_path = cert_file.relative_to(project_root)
            except ValueError:
                rel_path = cert_file

            # Get file extension
            ext = cert_file.suffix.lower()

            findings.append(self._create_finding(
                description=f"Certificate/key file found: {rel_path} ({ext} file)",
                recommendation=f"Remove {ext} files from repository. Store certificates and private keys in secure secret management systems (e.g., HashiCorp Vault, AWS Secrets Manager). Add *{ext} to .gitignore. Check git history to ensure file was never committed.",
                evidence=[Evidence(
                    file=str(rel_path),
                    snippet=f"# {ext.upper()} file in repository"
                )]
            ))

        return findings


@register_rule
class MissingGitignoreRule(Rule):
    """GENERAL-002: Detect missing or insufficient .gitignore."""

    @property
    def id(self) -> str:
        return "GENERAL-002"

    @property
    def title(self) -> str:
        return "Missing or insufficient .gitignore"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    def check(self, parsed_data: dict) -> List[Finding]:
        findings = []
        env_config = parsed_data.get("env_config", {})

        gitignore_exists = env_config.get("gitignore_exists", False)
        has_minimal_gitignore = env_config.get("has_minimal_gitignore", False)

        if not gitignore_exists:
            findings.append(self._create_finding(
                description=".gitignore file is missing from project",
                recommendation="Create a .gitignore file with at least: .env, __pycache__/, venv/, .venv/, *.pyc, .DS_Store. This prevents accidental commit of secrets and generated files.",
                evidence=[Evidence(
                    file=".gitignore",
                    snippet="# .gitignore file not found"
                )]
            ))
        elif not has_minimal_gitignore:
            findings.append(self._create_finding(
                description=".gitignore exists but does not include essential patterns (e.g., .env)",
                recommendation="Update .gitignore to include at minimum: .env (to protect secrets), __pycache__/ (Python cache), venv/ and .venv/ (virtual environments).",
                evidence=[Evidence(
                    file=".gitignore",
                    snippet="# .gitignore missing essential patterns"
                )]
            ))

        return findings
