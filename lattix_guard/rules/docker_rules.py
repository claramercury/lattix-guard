"""Docker and Docker Compose security rules."""

from typing import List
from .base import Rule, Severity, Finding, Evidence
from . import register_rule


@register_rule
class PrivilegedContainerRule(Rule):
    """DOCKER-001: Detect privileged containers."""

    @property
    def id(self) -> str:
        return "DOCKER-001"

    @property
    def title(self) -> str:
        return "Privileged container detected"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    def check(self, parsed_data: dict) -> List[Finding]:
        findings = []
        compose_data = parsed_data.get("docker_compose", {})
        services = compose_data.get("services", {})

        for service_name, service_config in services.items():
            if not isinstance(service_config, dict):
                continue

            if service_config.get("privileged") is True:
                findings.append(self._create_finding(
                    description=f"Service '{service_name}' runs with privileged: true, granting full host access",
                    recommendation="Remove 'privileged: true'. Use specific capabilities with 'cap_add' instead of full privileged mode.",
                    evidence=[Evidence(
                        file="docker-compose.yml",
                        key=f"services.{service_name}.privileged",
                        snippet="privileged: true"
                    )]
                ))

        return findings


@register_rule
class HostNetworkModeRule(Rule):
    """DOCKER-002: Detect host network mode."""

    @property
    def id(self) -> str:
        return "DOCKER-002"

    @property
    def title(self) -> str:
        return "Host network mode detected"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    def check(self, parsed_data: dict) -> List[Finding]:
        findings = []
        compose_data = parsed_data.get("docker_compose", {})
        services = compose_data.get("services", {})

        for service_name, service_config in services.items():
            if not isinstance(service_config, dict):
                continue

            network_mode = service_config.get("network_mode")
            if network_mode == "host":
                findings.append(self._create_finding(
                    description=f"Service '{service_name}' uses network_mode: host, bypassing Docker network isolation",
                    recommendation="Remove 'network_mode: host'. Use published ports instead or create a custom bridge network.",
                    evidence=[Evidence(
                        file="docker-compose.yml",
                        key=f"services.{service_name}.network_mode",
                        snippet="network_mode: host"
                    )]
                ))

        return findings


@register_rule
class ExposedPortsRule(Rule):
    """DOCKER-003: Detect ports exposed to 0.0.0.0."""

    @property
    def id(self) -> str:
        return "DOCKER-003"

    @property
    def title(self) -> str:
        return "Ports exposed to all interfaces (0.0.0.0)"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    def check(self, parsed_data: dict) -> List[Finding]:
        findings = []
        compose_data = parsed_data.get("docker_compose", {})
        services = compose_data.get("services", {})

        for service_name, service_config in services.items():
            if not isinstance(service_config, dict):
                continue

            ports = service_config.get("ports", [])
            if not isinstance(ports, list):
                continue

            for port_spec in ports:
                port_str = str(port_spec)

                # Check for explicit 0.0.0.0 binding
                if port_str.startswith("0.0.0.0:"):
                    findings.append(self._create_finding(
                        description=f"Service '{service_name}' exposes port to 0.0.0.0 (all interfaces): {port_str}",
                        recommendation="Bind to localhost (127.0.0.1) instead of 0.0.0.0 to restrict external access. Example: '127.0.0.1:8000:8000'",
                        evidence=[Evidence(
                            file="docker-compose.yml",
                            key=f"services.{service_name}.ports",
                            snippet=port_str
                        )]
                    ))

                # Check for implicit 0.0.0.0 binding (no IP specified)
                elif ":" in port_str and not port_str.startswith("127.0.0.1:"):
                    # Format like "8000:8000" (implicit 0.0.0.0)
                    parts = port_str.split(":")
                    if len(parts) == 2 and parts[0].isdigit():
                        findings.append(self._create_finding(
                            description=f"Service '{service_name}' implicitly exposes port to 0.0.0.0: {port_str}",
                            recommendation="Explicitly bind to 127.0.0.1 to prevent external access. Change '{port_str}' to '127.0.0.1:{port_str}'",
                            evidence=[Evidence(
                                file="docker-compose.yml",
                                key=f"services.{service_name}.ports",
                                snippet=port_str
                            )]
                        ))

        return findings


@register_rule
class DockerSocketMountRule(Rule):
    """DOCKER-004: Detect Docker socket mounting."""

    @property
    def id(self) -> str:
        return "DOCKER-004"

    @property
    def title(self) -> str:
        return "Docker socket mounted in container"

    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL

    def check(self, parsed_data: dict) -> List[Finding]:
        findings = []
        compose_data = parsed_data.get("docker_compose", {})
        services = compose_data.get("services", {})

        for service_name, service_config in services.items():
            if not isinstance(service_config, dict):
                continue

            volumes = service_config.get("volumes", [])
            if not isinstance(volumes, list):
                continue

            for volume in volumes:
                volume_str = str(volume)

                if "/var/run/docker.sock" in volume_str:
                    findings.append(self._create_finding(
                        description=f"Service '{service_name}' mounts Docker socket, granting full Docker API access",
                        recommendation="Remove Docker socket mount. If Docker API access is required, use Docker API with TLS authentication or run in a dedicated management container with restricted scope.",
                        evidence=[Evidence(
                            file="docker-compose.yml",
                            key=f"services.{service_name}.volumes",
                            snippet=volume_str
                        )]
                    ))

        return findings


@register_rule
class SecretsInEnvironmentRule(Rule):
    """DOCKER-005: Detect secrets in environment variables."""

    @property
    def id(self) -> str:
        return "DOCKER-005"

    @property
    def title(self) -> str:
        return "Potential secrets in environment variables"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    def check(self, parsed_data: dict) -> List[Finding]:
        findings = []
        compose_data = parsed_data.get("docker_compose", {})
        services = compose_data.get("services", {})

        SECRET_KEYWORDS = ['PASSWORD', 'SECRET', 'KEY', 'TOKEN', 'CREDENTIAL']

        for service_name, service_config in services.items():
            if not isinstance(service_config, dict):
                continue

            environment = service_config.get("environment", {})

            # Handle both dict and list formats
            env_items = []
            if isinstance(environment, dict):
                env_items = environment.items()
            elif isinstance(environment, list):
                env_items = [(str(item).split('=')[0], str(item).split('=')[1] if '=' in str(item) else '') for item in environment]

            for key, value in env_items:
                key_upper = key.upper()

                # Check if key contains secret-related keyword
                if any(keyword in key_upper for keyword in SECRET_KEYWORDS):
                    # Check if value looks like a hardcoded secret (not a variable reference)
                    value_str = str(value)
                    if value_str and not value_str.startswith('${') and value_str != '':
                        findings.append(self._create_finding(
                            description=f"Service '{service_name}' has potential hardcoded secret in environment: {key}",
                            recommendation="Use 'env_file' or variable substitution (${VAR}) instead of hardcoding secrets. Move secrets to .env file and reference with ${VARIABLE_NAME}.",
                            evidence=[Evidence(
                                file="docker-compose.yml",
                                key=f"services.{service_name}.environment.{key}",
                                snippet=f"{key}=***"
                            )]
                        ))

        return findings


@register_rule
class LatestImageTagRule(Rule):
    """DOCKER-006: Detect usage of :latest tag."""

    @property
    def id(self) -> str:
        return "DOCKER-006"

    @property
    def title(self) -> str:
        return "Image uses 'latest' tag"

    @property
    def severity(self) -> Severity:
        return Severity.LOW

    def check(self, parsed_data: dict) -> List[Finding]:
        findings = []
        compose_data = parsed_data.get("docker_compose", {})
        services = compose_data.get("services", {})

        for service_name, service_config in services.items():
            if not isinstance(service_config, dict):
                continue

            image = service_config.get("image", "")
            if not image:
                continue

            if image.endswith(":latest") or (':' not in image):
                findings.append(self._create_finding(
                    description=f"Service '{service_name}' uses ':latest' tag or no tag (implicit latest): {image}",
                    recommendation="Pin to specific version tag for reproducibility and security. Example: 'ubuntu:22.04' instead of 'ubuntu:latest'",
                    evidence=[Evidence(
                        file="docker-compose.yml",
                        key=f"services.{service_name}.image",
                        snippet=image
                    )]
                ))

        return findings


@register_rule
class MissingUserDirectiveRule(Rule):
    """DOCKER-007: Detect missing user directive."""

    @property
    def id(self) -> str:
        return "DOCKER-007"

    @property
    def title(self) -> str:
        return "Container runs as root (missing user directive)"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    def check(self, parsed_data: dict) -> List[Finding]:
        findings = []
        compose_data = parsed_data.get("docker_compose", {})
        services = compose_data.get("services", {})

        for service_name, service_config in services.items():
            if not isinstance(service_config, dict):
                continue

            # Check if user directive is present
            if "user" not in service_config:
                findings.append(self._create_finding(
                    description=f"Service '{service_name}' does not specify 'user' directive, likely running as root",
                    recommendation="Add 'user' directive to run container as non-root user. Example: 'user: \"1000:1000\"' or 'user: \"nobody\"'",
                    evidence=[Evidence(
                        file="docker-compose.yml",
                        key=f"services.{service_name}",
                        snippet=f"# Service '{service_name}' missing 'user:' directive"
                    )]
                ))

        return findings


@register_rule
class CapabilityAddRule(Rule):
    """DOCKER-008: Detect capability additions."""

    @property
    def id(self) -> str:
        return "DOCKER-008"

    @property
    def title(self) -> str:
        return "Linux capabilities added to container"

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM

    def check(self, parsed_data: dict) -> List[Finding]:
        findings = []
        compose_data = parsed_data.get("docker_compose", {})
        services = compose_data.get("services", {})

        for service_name, service_config in services.items():
            if not isinstance(service_config, dict):
                continue

            cap_add = service_config.get("cap_add", [])
            if cap_add:
                caps_str = ", ".join(str(cap) for cap in cap_add)
                findings.append(self._create_finding(
                    description=f"Service '{service_name}' adds Linux capabilities: {caps_str}",
                    recommendation="Review if added capabilities are necessary. Each capability increases attack surface. Remove unnecessary capabilities.",
                    evidence=[Evidence(
                        file="docker-compose.yml",
                        key=f"services.{service_name}.cap_add",
                        snippet=caps_str
                    )]
                ))

        return findings


@register_rule
class DangerousVolumeMountRule(Rule):
    """DOCKER-009: Detect dangerous volume mounts."""

    @property
    def id(self) -> str:
        return "DOCKER-009"

    @property
    def title(self) -> str:
        return "Dangerous volume mount detected"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    def check(self, parsed_data: dict) -> List[Finding]:
        findings = []
        compose_data = parsed_data.get("docker_compose", {})
        services = compose_data.get("services", {})

        DANGEROUS_PATHS = ['/etc', '/sys', '/proc', '/boot', '/dev', '/']

        for service_name, service_config in services.items():
            if not isinstance(service_config, dict):
                continue

            volumes = service_config.get("volumes", [])
            if not isinstance(volumes, list):
                continue

            for volume in volumes:
                volume_str = str(volume)
                source_path = volume_str.split(':')[0] if ':' in volume_str else ''

                for dangerous_path in DANGEROUS_PATHS:
                    if source_path == dangerous_path or source_path.startswith(dangerous_path + '/'):
                        findings.append(self._create_finding(
                            description=f"Service '{service_name}' mounts dangerous host path: {volume_str}",
                            recommendation=f"Avoid mounting system directories like {dangerous_path}. Mount specific subdirectories or use named volumes instead.",
                            evidence=[Evidence(
                                file="docker-compose.yml",
                                key=f"services.{service_name}.volumes",
                                snippet=volume_str
                            )]
                        ))
                        break  # Only report once per volume

        return findings


@register_rule
class DatabasePortExposedRule(Rule):
    """DOCKER-010: Detect exposed database ports."""

    @property
    def id(self) -> str:
        return "DOCKER-010"

    @property
    def title(self) -> str:
        return "Database port exposed"

    @property
    def severity(self) -> Severity:
        return Severity.HIGH

    def check(self, parsed_data: dict) -> List[Finding]:
        findings = []
        compose_data = parsed_data.get("docker_compose", {})
        services = compose_data.get("services", {})

        # Common database ports
        DB_PORTS = {
            '3306': 'MySQL',
            '5432': 'PostgreSQL',
            '6379': 'Redis',
            '27017': 'MongoDB',
            '9042': 'Cassandra',
            '7000': 'Cassandra',
            '5984': 'CouchDB',
            '9200': 'Elasticsearch',
            '8086': 'InfluxDB',
            '7474': 'Neo4j',
        }

        for service_name, service_config in services.items():
            if not isinstance(service_config, dict):
                continue

            ports = service_config.get("ports", [])
            if not isinstance(ports, list):
                continue

            for port_spec in ports:
                port_str = str(port_spec)

                # Extract the container port from spec like "127.0.0.1:3306:3306" or "3306:3306"
                parts = port_str.split(':')
                container_port = parts[-1].split('/')[0]  # Handle "3306/tcp"

                if container_port in DB_PORTS:
                    db_name = DB_PORTS[container_port]
                    findings.append(self._create_finding(
                        description=f"Service '{service_name}' exposes {db_name} port {container_port}",
                        recommendation=f"Database ports should not be exposed externally. Remove port mapping or bind to localhost only (127.0.0.1:{container_port}:{container_port}). Access database through application layer instead.",
                        evidence=[Evidence(
                            file="docker-compose.yml",
                            key=f"services.{service_name}.ports",
                            snippet=port_str
                        )]
                    ))

        return findings
