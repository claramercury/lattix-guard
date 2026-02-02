"""Docker Compose YAML parser with security validations.

SECURITY GUARANTEES:
- Uses ONLY yaml.safe_load() (no yaml.load or yaml.unsafe_load)
- Enforces 1MB file size limit
- Enforces 12-level maximum depth
- Enforces 5000 maximum keys
- Detects and blocks YAML bombs/excessive anchors
- 10-second timeout per file
"""

import yaml
import signal
from pathlib import Path
from typing import Dict, Any, Optional


class YAMLSecurityError(Exception):
    """Raised when YAML file violates security constraints."""
    pass


class TimeoutError(Exception):
    """Raised when YAML parsing exceeds timeout."""
    pass


def _timeout_handler(signum, frame):
    """Signal handler for timeout."""
    raise TimeoutError("YAML parsing exceeded 10 second timeout")


def _count_keys(data: Any, depth: int = 0, max_depth: int = 12) -> int:
    """Recursively count keys in a nested structure and validate depth.

    Args:
        data: YAML data structure
        depth: Current nesting depth
        max_depth: Maximum allowed depth

    Returns:
        Total number of keys

    Raises:
        YAMLSecurityError: If depth or key count exceeds limits
    """
    if depth > max_depth:
        raise YAMLSecurityError(
            f"YAML nesting depth ({depth}) exceeds maximum ({max_depth})"
        )

    if isinstance(data, dict):
        count = len(data)
        for value in data.values():
            count += _count_keys(value, depth + 1, max_depth)
        return count
    elif isinstance(data, list):
        count = 0
        for item in data:
            count += _count_keys(item, depth + 1, max_depth)
        return count
    else:
        return 0


def _detect_yaml_bomb(file_path: Path, max_aliases: int = 100) -> None:
    """Detect YAML bombs by checking for excessive aliases/anchors.

    Args:
        file_path: Path to YAML file
        max_aliases: Maximum allowed aliases

    Raises:
        YAMLSecurityError: If excessive aliases detected
    """
    content = file_path.read_text()

    # Count alias definitions (&anchor) and references (*alias)
    anchor_count = content.count('&')
    alias_count = content.count('*')

    if anchor_count > max_aliases or alias_count > max_aliases:
        raise YAMLSecurityError(
            f"Possible YAML bomb detected: {anchor_count} anchors, "
            f"{alias_count} aliases (max {max_aliases})"
        )


def parse_compose_file(file_path: Path) -> Optional[Dict[str, Any]]:
    """Parse a docker-compose.yml file with security validations.

    SECURITY VALIDATIONS:
    1. File size <= 1MB
    2. YAML depth <= 12 levels
    3. Total keys <= 5000
    4. No YAML bombs (excessive aliases)
    5. Timeout after 10 seconds
    6. Uses yaml.safe_load() ONLY

    Args:
        file_path: Path to docker-compose.yml file

    Returns:
        Parsed YAML data as dictionary, or None if file not found

    Raises:
        YAMLSecurityError: If file violates security constraints
        TimeoutError: If parsing exceeds 10 seconds
        yaml.YAMLError: If YAML is malformed
    """
    if not file_path.exists():
        return None

    # Security check 1: File size limit (1MB)
    file_size = file_path.stat().st_size
    MAX_SIZE = 1024 * 1024  # 1MB
    if file_size > MAX_SIZE:
        raise YAMLSecurityError(
            f"YAML file too large ({file_size} bytes). Maximum: {MAX_SIZE} bytes (1MB)"
        )

    # Security check 2: YAML bomb detection
    _detect_yaml_bomb(file_path)

    # Security check 3: Set timeout (10 seconds)
    # Note: signal.alarm only works on Unix systems
    try:
        signal.signal(signal.SIGALRM, _timeout_handler)
        signal.alarm(10)

        # Security check 4: Use safe_load ONLY (prevents arbitrary code execution)
        with open(file_path, 'r') as f:
            data = yaml.safe_load(f)

        # Cancel timeout
        signal.alarm(0)

    except Exception:
        # Cancel timeout on any error
        signal.alarm(0)
        raise

    if data is None:
        return {}

    # Security check 5: Depth and key count validation
    total_keys = _count_keys(data, depth=0, max_depth=12)
    if total_keys > 5000:
        raise YAMLSecurityError(
            f"YAML file has too many keys ({total_keys}). Maximum: 5000"
        )

    # Normalize: remove version field if present (we don't care about compose version)
    if isinstance(data, dict) and 'version' in data:
        data = dict(data)  # Create a copy
        del data['version']

    return data


def parse_compose(compose_path: Path) -> Dict[str, Any]:
    """Parse docker-compose.yml and return normalized structure.

    Args:
        compose_path: Path to docker-compose.yml

    Returns:
        Dictionary with parsed compose data. Structure:
        {
            'services': {
                'service_name': {
                    'image': '...',
                    'ports': [...],
                    'volumes': [...],
                    'environment': {...},
                    'privileged': bool,
                    'network_mode': '...',
                    'cap_add': [...],
                    'user': '...',
                    ...
                }
            },
            'volumes': {...},
            'networks': {...}
        }

        Returns empty dict if file not found or invalid.
    """
    try:
        data = parse_compose_file(compose_path)
        if data is None:
            return {}
        return data
    except (YAMLSecurityError, TimeoutError, yaml.YAMLError) as e:
        # Log error but don't crash - return empty dict
        print(f"Warning: Failed to parse {compose_path}: {e}")
        return {}


def get_services(compose_data: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Extract services section from compose data.

    Args:
        compose_data: Parsed docker-compose data

    Returns:
        Dictionary of service configurations
    """
    return compose_data.get('services', {})


def get_service_config(
    compose_data: Dict[str, Any],
    service_name: str
) -> Optional[Dict[str, Any]]:
    """Get configuration for a specific service.

    Args:
        compose_data: Parsed docker-compose data
        service_name: Name of the service

    Returns:
        Service configuration dict, or None if not found
    """
    services = get_services(compose_data)
    return services.get(service_name)
