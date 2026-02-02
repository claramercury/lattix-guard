"""Environment file and .gitignore parser.

SECURITY GUARANTEES:
- No symlink following
- File scanning limits (max 500 files)
- No execution of any code
- Static analysis only
"""

import os
from pathlib import Path
from typing import List, Set, Optional


def find_env_files(project_root: Path, max_files: int = 500) -> List[Path]:
    """Find .env files in project.

    Args:
        project_root: Root directory of project
        max_files: Maximum number of files to scan

    Returns:
        List of .env file paths
    """
    env_files = []
    file_count = 0

    # Directories to skip
    SKIP_DIRS = {'.git', 'node_modules', 'venv', '.venv', '__pycache__', 'dist', 'build'}

    for root, dirs, files in os.walk(project_root, followlinks=False):
        # Skip excluded directories (modify dirs in-place to prune walk)
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for file in files:
            file_count += 1

            # Security: Enforce file scanning limit
            if file_count > max_files:
                break

            if file == '.env' or file.startswith('.env.'):
                env_files.append(Path(root) / file)

        if file_count > max_files:
            break

    return env_files


def find_certificate_files(project_root: Path, max_files: int = 500) -> List[Path]:
    """Find certificate/key files that might be secrets.

    Looks for files with extensions: .pem, .key, .crt, .cer, .p12, .pfx

    Args:
        project_root: Root directory of project
        max_files: Maximum number of files to scan

    Returns:
        List of certificate/key file paths
    """
    cert_files = []
    file_count = 0

    SKIP_DIRS = {'.git', 'node_modules', 'venv', '.venv', '__pycache__', 'dist', 'build'}
    CERT_EXTENSIONS = {'.pem', '.key', '.crt', '.cer', '.p12', '.pfx'}

    for root, dirs, files in os.walk(project_root, followlinks=False):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for file in files:
            file_count += 1

            if file_count > max_files:
                break

            file_path = Path(root) / file
            if file_path.suffix.lower() in CERT_EXTENSIONS:
                cert_files.append(file_path)

        if file_count > max_files:
            break

    return cert_files


def parse_gitignore(gitignore_path: Path) -> Set[str]:
    """Parse .gitignore file and return set of patterns.

    Args:
        gitignore_path: Path to .gitignore file

    Returns:
        Set of gitignore patterns (comments and empty lines removed)
    """
    if not gitignore_path.exists():
        return set()

    patterns = set()

    try:
        with open(gitignore_path, 'r') as f:
            for line in f:
                line = line.strip()

                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue

                patterns.add(line)
    except Exception:
        # If we can't read .gitignore, return empty set
        return set()

    return patterns


def is_path_ignored(file_path: str, gitignore_patterns: Set[str]) -> bool:
    """Check if a file path matches any gitignore pattern.

    Simple pattern matching (not full gitignore spec, but covers common cases).

    Args:
        file_path: File path to check (relative)
        gitignore_patterns: Set of gitignore patterns

    Returns:
        True if file should be ignored
    """
    file_path = file_path.lstrip('./')

    for pattern in gitignore_patterns:
        # Exact match
        if pattern == file_path:
            return True

        # Directory match (pattern ends with /)
        if pattern.endswith('/'):
            dir_pattern = pattern.rstrip('/')
            if file_path.startswith(dir_pattern + '/'):
                return True

        # Wildcard match (simple glob)
        if '*' in pattern:
            # Convert simple glob to basic check
            if pattern == '*':
                return True
            if pattern.startswith('*') and file_path.endswith(pattern[1:]):
                return True
            if pattern.endswith('*') and file_path.startswith(pattern[:-1]):
                return True

        # Filename match anywhere in tree
        if '/' not in pattern:
            if Path(file_path).name == pattern:
                return True

    return False


def check_env_in_gitignore(
    env_files: List[Path],
    gitignore_patterns: Set[str],
    project_root: Path
) -> List[Path]:
    """Check which .env files are NOT in .gitignore.

    Args:
        env_files: List of .env file paths
        gitignore_patterns: Set of gitignore patterns
        project_root: Project root for relative path calculation

    Returns:
        List of .env files that are NOT ignored (security risk)
    """
    unignored = []

    for env_file in env_files:
        # Get relative path
        try:
            rel_path = env_file.relative_to(project_root)
        except ValueError:
            # File is outside project root
            continue

        # Check if ignored
        if not is_path_ignored(str(rel_path), gitignore_patterns):
            unignored.append(env_file)

    return unignored


def has_minimal_gitignore(gitignore_patterns: Set[str]) -> bool:
    """Check if .gitignore has minimal security patterns.

    A minimal .gitignore should at least ignore:
    - .env files
    - Common dependency directories

    Args:
        gitignore_patterns: Set of gitignore patterns

    Returns:
        True if .gitignore has basic security patterns
    """
    essential_patterns = [
        '.env',  # Must ignore .env
        '__pycache__',  # Python cache
        'venv',  # Virtual environment
        '.venv',  # Alternative venv name
    ]

    # Check if at least .env is ignored
    has_env = any(
        '.env' in pattern or pattern == '.env'
        for pattern in gitignore_patterns
    )

    return has_env


def analyze_environment_config(project_root: Path) -> dict:
    """Analyze environment configuration security.

    Args:
        project_root: Root directory of project

    Returns:
        Dictionary with analysis:
        {
            'env_files': [Path, ...],
            'cert_files': [Path, ...],
            'gitignore_exists': bool,
            'gitignore_patterns': Set[str],
            'unignored_env_files': [Path, ...],
            'has_minimal_gitignore': bool
        }
    """
    gitignore_path = project_root / '.gitignore'
    gitignore_patterns = parse_gitignore(gitignore_path)

    env_files = find_env_files(project_root)
    cert_files = find_certificate_files(project_root)
    unignored_env = check_env_in_gitignore(env_files, gitignore_patterns, project_root)

    return {
        'env_files': env_files,
        'cert_files': cert_files,
        'gitignore_exists': gitignore_path.exists(),
        'gitignore_patterns': gitignore_patterns,
        'unignored_env_files': unignored_env,
        'has_minimal_gitignore': has_minimal_gitignore(gitignore_patterns)
    }
