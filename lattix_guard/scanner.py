"""Security scanner orchestrator for lattix_guard."""

import time
from pathlib import Path
from typing import Dict, List, Any
from dataclasses import dataclass, field

from .parsers import parse_compose, analyze_python_file, analyze_environment_config
from .rules import get_all_rules, Finding
from .scoring import calculate_score


@dataclass
class ScanResult:
    """Result of a security scan."""
    project_path: Path
    score_details: Dict = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    scan_duration_ms: int = 0
    files_scanned: Dict[str, int] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


class SecurityScanner:
    """Main security scanner that orchestrates parsing and rule execution.

    SECURITY FEATURES:
    - No symlink following
    - File scanning limits (max 500 files)
    - Read-only operations
    - No code execution
    """

    def __init__(self, project_path: Path):
        """Initialize scanner.

        Args:
            project_path: Root directory of project to scan
        """
        if not project_path.exists():
            raise ValueError(f"Project path does not exist: {project_path}")

        if not project_path.is_dir():
            raise ValueError(f"Project path is not a directory: {project_path}")

        self.project_path = project_path.resolve()
        self.max_files = 500

    def scan(self) -> ScanResult:
        """Perform complete security scan of project.

        Returns:
            ScanResult with findings and score

        Process:
        1. Detect relevant files
        2. Parse files (docker-compose, Python, env)
        3. Run all registered rules
        4. Calculate score
        5. Return aggregated results
        """
        start_time = time.time()

        result = ScanResult(project_path=self.project_path)

        try:
            # Step 1: Detect files
            detected_files = self._detect_files()
            result.files_scanned = {
                'docker_compose': 1 if detected_files['docker_compose'] else 0,
                'python_files': len(detected_files['python_files']),
                'env_files': len(detected_files.get('env_files', [])),
            }

            # Step 2: Parse files
            parsed_data = self._parse_files(detected_files)

            # Step 3: Load and run all rules
            # Import rule modules to trigger @register_rule decorators
            from .rules import docker_rules, fastapi_rules, general_rules

            all_rules = get_all_rules()
            all_findings = []

            for rule in all_rules:
                try:
                    findings = rule.check(parsed_data)
                    all_findings.extend(findings)
                except Exception as e:
                    error_msg = f"Error executing rule {rule.id}: {str(e)}"
                    result.errors.append(error_msg)

            result.findings = all_findings

            # Step 4: Calculate score
            result.score_details = calculate_score(all_findings)

        except Exception as e:
            result.errors.append(f"Scan error: {str(e)}")

        # Record duration
        end_time = time.time()
        result.scan_duration_ms = int((end_time - start_time) * 1000)

        return result

    def _detect_files(self) -> Dict[str, Any]:
        """Detect relevant files in project.

        Returns:
            Dictionary with detected file paths:
            {
                'docker_compose': Path or None,
                'python_files': [Path, ...],
                'env_files': [Path, ...],
                'gitignore': Path or None
            }
        """
        detected = {
            'docker_compose': None,
            'python_files': [],
            'env_files': [],
            'gitignore': None
        }

        # Look for docker-compose.yml
        compose_variants = ['docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml']
        for variant in compose_variants:
            compose_path = self.project_path / variant
            if compose_path.exists():
                detected['docker_compose'] = compose_path
                break

        # Look for .gitignore
        gitignore_path = self.project_path / '.gitignore'
        if gitignore_path.exists():
            detected['gitignore'] = gitignore_path

        # Find Python files (limit to max_files)
        python_files = []
        file_count = 0

        SKIP_DIRS = {'.git', 'node_modules', 'venv', '.venv', '__pycache__', 'dist', 'build', '.pytest_cache', '.local', '.cache', '.config', 'snap', '.steam', '.var', 'Downloads', 'Desktop', 'Documents', 'Pictures', 'Videos', 'Music', 'site-packages'}

        for root, dirs, files in self.project_path.walk():
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

            for file in files:
                if file.endswith('.py'):
                    file_count += 1
                    if file_count > self.max_files:
                        break

                    python_files.append(Path(root) / file)

            if file_count > self.max_files:
                break

        detected['python_files'] = python_files

        return detected

    def _parse_files(self, detected_files: Dict[str, Any]) -> Dict[str, Any]:
        """Parse detected files into structured data.

        Args:
            detected_files: Output from _detect_files()

        Returns:
            Dictionary with parsed data:
            {
                'docker_compose': {...},
                'python_files': {
                    'file.py': {...},
                    ...
                },
                'env_config': {...},
                'project_root': Path
            }
        """
        parsed = {
            'docker_compose': {},
            'python_files': {},
            'env_config': {},
            'project_root': self.project_path
        }

        # Parse docker-compose.yml
        if detected_files['docker_compose']:
            try:
                compose_data = parse_compose(detected_files['docker_compose'])
                parsed['docker_compose'] = compose_data
            except Exception as e:
                # Error already logged by parse_compose
                pass

        # Parse Python files
        for py_file in detected_files['python_files']:
            try:
                # Get relative path for cleaner output
                rel_path = py_file.relative_to(self.project_path)
                analysis = analyze_python_file(py_file)
                parsed['python_files'][str(rel_path)] = analysis
            except Exception as e:
                # Skip files that can't be parsed
                pass

        # Analyze environment configuration
        try:
            env_analysis = analyze_environment_config(self.project_path)
            parsed['env_config'] = env_analysis
        except Exception as e:
            # Continue even if env analysis fails
            pass

        return parsed


def scan_project(project_path: Path) -> ScanResult:
    """Convenience function to scan a project.

    Args:
        project_path: Path to project root

    Returns:
        ScanResult with findings and score
    """
    scanner = SecurityScanner(project_path)
    return scanner.scan()
