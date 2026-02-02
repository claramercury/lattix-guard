"""FastAPI and Python security rules."""

from pathlib import Path
from typing import List
from .base import Rule, Severity, Finding, Evidence
from . import register_rule


@register_rule
class CORSWildcardRule(Rule):
    """FASTAPI-001: Detect CORS allow_origins=["*"]."""

    @property
    def id(self) -> str:
        return "FASTAPI-001"

    @property
    def title(self) -> str:
        return "CORS configured with wildcard (*)"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    def check(self, parsed_data: dict) -> List[Finding]:
        findings = []
        python_files = parsed_data.get("python_files", {})

        for file_path, analysis in python_files.items():
            cors_configs = analysis.get("cors_middleware", [])

            for config in cors_configs:
                allow_origins = config.get("allow_origins")

                # Check if allow_origins is ["*"] or contains "*"
                if isinstance(allow_origins, list) and "*" in allow_origins:
                    findings.append(self._create_finding(
                        description=f"File '{file_path}' configures CORS with allow_origins=['*'], allowing any origin",
                        recommendation="Specify explicit allowed origins instead of wildcard. Example: allow_origins=['https://yourdomain.com', 'https://app.yourdomain.com']",
                        evidence=[Evidence(
                            file=file_path,
                            line=config.get("line"),
                            snippet="allow_origins=['*']"
                        )]
                    ))

        return findings


@register_rule
class DocsEnabledRule(Rule):
    """FASTAPI-002: Detect enabled API documentation."""

    @property
    def id(self) -> str:
        return "FASTAPI-002"

    @property
    def title(self) -> str:
        return "API documentation endpoints enabled"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    def check(self, parsed_data: dict) -> List[Finding]:
        findings = []
        python_files = parsed_data.get("python_files", {})

        for file_path, analysis in python_files.items():
            fastapi_apps = analysis.get("fastapi_apps", [])

            for app_config in fastapi_apps:
                # Check if docs are explicitly enabled or not disabled
                docs_url = app_config.get("docs_url")
                redoc_url = app_config.get("redoc_url")
                openapi_url = app_config.get("openapi_url")

                # If any of these are not None, docs are enabled
                docs_enabled = False
                enabled_endpoints = []

                if docs_url is not False and docs_url is not None:
                    docs_enabled = True
                    enabled_endpoints.append("/docs")

                if redoc_url is not False and redoc_url is not None:
                    docs_enabled = True
                    enabled_endpoints.append("/redoc")

                if openapi_url is not False and openapi_url is not None:
                    docs_enabled = True
                    enabled_endpoints.append("/openapi.json")

                if docs_enabled:
                    endpoints_str = ", ".join(enabled_endpoints)
                    findings.append(self._create_finding(
                        description=f"File '{file_path}' has API documentation enabled: {endpoints_str}",
                        recommendation="Disable docs in production by setting: docs_url=None, redoc_url=None, openapi_url=None in FastAPI constructor.",
                        evidence=[Evidence(
                            file=file_path,
                            line=app_config.get("line"),
                            snippet=f"FastAPI()  # {endpoints_str} enabled"
                        )]
                    ))

        return findings


@register_rule
class EnvNotInGitignoreRule(Rule):
    """FASTAPI-003: Detect .env files not in .gitignore."""

    @property
    def id(self) -> str:
        return "FASTAPI-003"

    @property
    def title(self) -> str:
        return ".env file exists but not in .gitignore"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    def check(self, parsed_data: dict) -> List[Finding]:
        findings = []
        env_config = parsed_data.get("env_config", {})

        unignored_env_files = env_config.get("unignored_env_files", [])
        project_root = parsed_data.get("project_root", Path())

        for env_file in unignored_env_files:
            # Get relative path
            try:
                rel_path = env_file.relative_to(project_root)
            except ValueError:
                rel_path = env_file

            findings.append(self._create_finding(
                description=f".env file '{rel_path}' exists but is NOT in .gitignore, risking secret exposure in repository",
                recommendation="Add '.env' to .gitignore immediately. Check git history to ensure .env was never committed. If it was, rotate all secrets and use git-filter-branch or BFG to remove from history.",
                evidence=[Evidence(
                    file=str(rel_path),
                    snippet="# .env file not ignored by git"
                )]
            ))

        return findings


@register_rule
class HardcodedSecretsRule(Rule):
    """FASTAPI-004: Detect hardcoded SECRET_KEY or JWT_SECRET."""

    @property
    def id(self) -> str:
        return "FASTAPI-004"

    @property
    def title(self) -> str:
        return "Hardcoded secret key detected"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    def check(self, parsed_data: dict) -> List[Finding]:
        findings = []
        python_files = parsed_data.get("python_files", {})

        for file_path, analysis in python_files.items():
            hardcoded_secrets = analysis.get("hardcoded_secrets", [])

            for secret in hardcoded_secrets:
                # Only report if it's a literal value (not os.getenv)
                if secret.get("is_literal"):
                    var_name = secret.get("variable")
                    findings.append(self._create_finding(
                        description=f"File '{file_path}' has hardcoded secret: {var_name}",
                        recommendation=f"Move {var_name} to .env file and load with os.getenv(). Example: {var_name} = os.getenv('{var_name}'). Never commit secrets to source control.",
                        evidence=[Evidence(
                            file=file_path,
                            line=secret.get("line"),
                            snippet=f"{var_name} = '***'"
                        )]
                    ))

        return findings


@register_rule
class DebugModeRule(Rule):
    """FASTAPI-005: Detect DEBUG=True in production."""

    @property
    def id(self) -> str:
        return "FASTAPI-005"

    @property
    def title(self) -> str:
        return "DEBUG mode enabled"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    def check(self, parsed_data: dict) -> List[Finding]:
        findings = []
        python_files = parsed_data.get("python_files", {})

        for file_path, analysis in python_files.items():
            debug_assignments = analysis.get("debug_assignments", [])

            for assignment in debug_assignments:
                value = assignment.get("value")
                if value is True or str(value).lower() == 'true':
                    var_name = assignment.get("variable")
                    findings.append(self._create_finding(
                        description=f"File '{file_path}' sets {var_name}=True, enabling debug mode",
                        recommendation=f"Set {var_name}=False in production. Debug mode exposes sensitive information in error messages and disables security features.",
                        evidence=[Evidence(
                            file=file_path,
                            line=assignment.get("line"),
                            snippet=f"{var_name} = True"
                        )]
                    ))

        return findings


@register_rule
class JWTExpirationRule(Rule):
    """FASTAPI-006: Detect JWT without expiration check (basic heuristic)."""

    @property
    def id(self) -> str:
        return "FASTAPI-006"

    @property
    def title(self) -> str:
        return "JWT implementation may lack expiration check"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    def check(self, parsed_data: dict) -> List[Finding]:
        findings = []
        python_files = parsed_data.get("python_files", {})

        # Heuristic: if we find JWT-related secrets but no 'exp' checks in Python files
        has_jwt_secret = False
        has_exp_check = False

        for file_path, analysis in python_files.items():
            # Check for JWT-related secrets
            hardcoded_secrets = analysis.get("hardcoded_secrets", [])
            for secret in hardcoded_secrets:
                var_name = secret.get("variable", "").upper()
                if 'JWT' in var_name and ('SECRET' in var_name or 'KEY' in var_name):
                    has_jwt_secret = True

            # Check if 'exp' appears in the file (basic check)
            # This is a heuristic - in real implementation we'd do AST analysis
            # For now, we'll just warn if JWT_SECRET exists
            # (a more sophisticated check would analyze jwt.decode calls)

        # If we found JWT secrets but no expiration handling, warn
        # This is a simplified check - in production would be more sophisticated
        if has_jwt_secret and not has_exp_check:
            # For MVP, we'll skip this rule or make it very simple
            # A proper implementation would analyze jwt.decode() calls
            pass

        return findings  # Empty for MVP - requires more sophisticated AST analysis


@register_rule
class LoggingSecretsRule(Rule):
    """FASTAPI-007: Detect potential token/secret logging (basic pattern matching)."""

    @property
    def id(self) -> str:
        return "FASTAPI-007"

    @property
    def title(self) -> str:
        return "Potential secrets in log statements"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    def check(self, parsed_data: dict) -> List[Finding]:
        findings = []
        python_files = parsed_data.get("python_files", {})

        # This rule requires reading file content and searching for logging patterns
        # For MVP, we'll implement a basic version
        # A full implementation would use AST to analyze logging.* calls

        project_root = parsed_data.get("project_root", Path())

        for file_path_str, analysis in python_files.items():
            file_path = project_root / file_path_str

            try:
                if file_path.exists():
                    content = file_path.read_text()

                    # Simple pattern: look for logging with secret-related variables
                    suspicious_patterns = [
                        ('token', 'logging'),
                        ('password', 'logging'),
                        ('secret', 'logging'),
                        ('key', 'logging'),
                        ('token', 'print'),
                        ('password', 'print'),
                    ]

                    for secret_keyword, log_keyword in suspicious_patterns:
                        if secret_keyword in content.lower() and log_keyword in content.lower():
                            # This is a very basic heuristic
                            # In production, would analyze actual logging statements
                            findings.append(self._create_finding(
                                description=f"File '{file_path_str}' may log sensitive data (contains '{secret_keyword}' near '{log_keyword}')",
                                recommendation="Review logging statements to ensure tokens, passwords, and secrets are not logged. Use log sanitization or redaction for sensitive fields.",
                                evidence=[Evidence(
                                    file=file_path_str,
                                    snippet=f"# File contains '{secret_keyword}' and '{log_keyword}' - review for secret logging"
                                )]
                            ))
                            break  # Only report once per file

            except Exception:
                pass  # Skip files we can't read

        return findings


@register_rule
class OpenAPIExposedRule(Rule):
    """FASTAPI-008: Detect exposed OpenAPI JSON."""

    @property
    def id(self) -> str:
        return "FASTAPI-008"

    @property
    def title(self) -> str:
        return "OpenAPI JSON endpoint exposed"

    @property
    def severity(self) -> Severity:
        return Severity.LOW

    def check(self, parsed_data: dict) -> List[Finding]:
        findings = []
        python_files = parsed_data.get("python_files", {})

        for file_path, analysis in python_files.items():
            fastapi_apps = analysis.get("fastapi_apps", [])

            for app_config in fastapi_apps:
                openapi_url = app_config.get("openapi_url")

                # If openapi_url is not explicitly disabled (None/False)
                if openapi_url not in (None, False):
                    openapi_path = openapi_url if openapi_url else "/openapi.json"
                    findings.append(self._create_finding(
                        description=f"File '{file_path}' exposes OpenAPI schema at {openapi_path}",
                        recommendation="Disable OpenAPI endpoint in production by setting openapi_url=None in FastAPI constructor. This prevents API schema discovery.",
                        evidence=[Evidence(
                            file=file_path,
                            line=app_config.get("line"),
                            snippet=f"FastAPI()  # openapi_url exposed at {openapi_path}"
                        )]
                    ))

        return findings
