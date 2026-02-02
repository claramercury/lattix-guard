"""Python file parser using AST (Abstract Syntax Tree) analysis.

SECURITY GUARANTEES:
- Uses ONLY ast.parse() (no eval, exec, or dynamic imports)
- Does NOT import or execute user code
- File size limit: 500KB per Python file
- 100% static analysis
- No code execution
"""

import ast
from pathlib import Path
from typing import Dict, List, Any, Optional


class PythonParseError(Exception):
    """Raised when Python file cannot be parsed safely."""
    pass


def parse_python_file(file_path: Path) -> Optional[ast.Module]:
    """Parse a Python file into an AST.

    Args:
        file_path: Path to Python file

    Returns:
        AST Module object, or None if file cannot be parsed

    Raises:
        PythonParseError: If file is too large or has syntax errors
    """
    if not file_path.exists() or not file_path.is_file():
        return None

    # Security: File size limit (500KB)
    file_size = file_path.stat().st_size
    MAX_SIZE = 500 * 1024  # 500KB
    if file_size > MAX_SIZE:
        raise PythonParseError(
            f"Python file too large ({file_size} bytes). Maximum: {MAX_SIZE} bytes"
        )

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            source = f.read()

        # Security: Use ast.parse() ONLY (no eval/exec)
        tree = ast.parse(source, filename=str(file_path))
        return tree

    except (SyntaxError, UnicodeDecodeError) as e:
        # Invalid Python file - skip it
        return None


def find_fastapi_app_creation(tree: ast.Module) -> List[Dict[str, Any]]:
    """Find FastAPI() app instantiation and extract configuration.

    Looks for patterns like:
        app = FastAPI(docs_url=None, ...)
        app = FastAPI()

    Args:
        tree: AST Module

    Returns:
        List of dicts with FastAPI configuration:
        [
            {
                'line': 10,
                'docs_url': None,
                'redoc_url': '/redoc',
                'openapi_url': '/openapi.json',
                ...
            }
        ]
    """
    results = []

    for node in ast.walk(tree):
        # Look for: app = FastAPI(...)
        if isinstance(node, ast.Assign):
            if isinstance(node.value, ast.Call):
                # Check if it's calling FastAPI
                call_name = None
                if isinstance(node.value.func, ast.Name):
                    call_name = node.value.func.id
                elif isinstance(node.value.func, ast.Attribute):
                    call_name = node.value.func.attr

                if call_name == 'FastAPI':
                    config = {'line': node.lineno}

                    # Extract keyword arguments
                    for keyword in node.value.keywords:
                        arg_name = keyword.arg
                        arg_value = _ast_literal_value(keyword.value)
                        config[arg_name] = arg_value

                    results.append(config)

    return results


def find_cors_middleware(tree: ast.Module) -> List[Dict[str, Any]]:
    """Find CORS middleware configuration.

    Looks for patterns like:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            ...
        )

    Args:
        tree: AST Module

    Returns:
        List of dicts with CORS configuration:
        [
            {
                'line': 15,
                'allow_origins': ['*'],
                'allow_credentials': True,
                ...
            }
        ]
    """
    results = []

    for node in ast.walk(tree):
        # Look for: app.add_middleware(CORSMiddleware, ...)
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            call = node.value

            # Check if it's add_middleware
            if isinstance(call.func, ast.Attribute) and call.func.attr == 'add_middleware':
                # Check if first argument is CORSMiddleware
                if call.args and isinstance(call.args[0], ast.Name):
                    if 'CORS' in call.args[0].id:
                        config = {'line': node.lineno}

                        # Extract keyword arguments
                        for keyword in call.keywords:
                            arg_name = keyword.arg
                            arg_value = _ast_literal_value(keyword.value)
                            config[arg_name] = arg_value

                        results.append(config)

    return results


def find_debug_assignments(tree: ast.Module) -> List[Dict[str, Any]]:
    """Find DEBUG = True assignments.

    Args:
        tree: AST Module

    Returns:
        List of dicts:
        [
            {'line': 5, 'variable': 'DEBUG', 'value': True}
        ]
    """
    results = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id
                    if 'DEBUG' in var_name.upper():
                        value = _ast_literal_value(node.value)
                        results.append({
                            'line': node.lineno,
                            'variable': var_name,
                            'value': value
                        })

    return results


def find_hardcoded_secrets(tree: ast.Module) -> List[Dict[str, Any]]:
    """Find hardcoded secret keys (SECRET_KEY, JWT_SECRET, etc.).

    Looks for assignments like:
        SECRET_KEY = "hardcoded_value"
        JWT_SECRET = "my_secret"

    Args:
        tree: AST Module

    Returns:
        List of dicts:
        [
            {
                'line': 8,
                'variable': 'SECRET_KEY',
                'value': 'hardcoded_value',
                'is_literal': True
            }
        ]
    """
    results = []
    secret_keywords = ['SECRET', 'KEY', 'TOKEN', 'PASSWORD', 'API_KEY']

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_name = target.id.upper()

                    # Check if variable name contains secret-related keywords
                    if any(keyword in var_name for keyword in secret_keywords):
                        value = _ast_literal_value(node.value)

                        # Check if it's a literal (not os.getenv or similar)
                        is_literal = isinstance(node.value, (ast.Str, ast.Constant))

                        results.append({
                            'line': node.lineno,
                            'variable': target.id,
                            'value': value if is_literal else '<dynamic>',
                            'is_literal': is_literal
                        })

    return results


def _ast_literal_value(node: ast.AST) -> Any:
    """Extract literal value from AST node.

    Args:
        node: AST node

    Returns:
        Python literal value, or None if not a literal
    """
    try:
        # Python 3.8+
        if isinstance(node, ast.Constant):
            return node.value
        # Python 3.7 compatibility
        elif isinstance(node, ast.Str):
            return node.s
        elif isinstance(node, ast.Num):
            return node.n
        elif isinstance(node, ast.NameConstant):
            return node.value
        elif isinstance(node, ast.List):
            return [_ast_literal_value(elt) for elt in node.elts]
        elif isinstance(node, ast.Dict):
            keys = [_ast_literal_value(k) for k in node.keys]
            values = [_ast_literal_value(v) for v in node.values]
            return dict(zip(keys, values))
        else:
            return None
    except Exception:
        return None


def analyze_python_file(file_path: Path) -> Dict[str, Any]:
    """Analyze a Python file and extract security-relevant patterns.

    Args:
        file_path: Path to Python file

    Returns:
        Dictionary with analysis results:
        {
            'file': 'main.py',
            'fastapi_apps': [...],
            'cors_middleware': [...],
            'debug_assignments': [...],
            'hardcoded_secrets': [...],
            'parse_error': None or error message
        }
    """
    result = {
        'file': file_path.name,
        'fastapi_apps': [],
        'cors_middleware': [],
        'debug_assignments': [],
        'hardcoded_secrets': [],
        'parse_error': None
    }

    try:
        tree = parse_python_file(file_path)
        if tree is None:
            result['parse_error'] = "Could not parse file"
            return result

        result['fastapi_apps'] = find_fastapi_app_creation(tree)
        result['cors_middleware'] = find_cors_middleware(tree)
        result['debug_assignments'] = find_debug_assignments(tree)
        result['hardcoded_secrets'] = find_hardcoded_secrets(tree)

    except PythonParseError as e:
        result['parse_error'] = str(e)

    return result
