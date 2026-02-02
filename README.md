Lattix Guard

🛡️ Static security scanner for Docker Compose + FastAPI + Python

Lattix Guard performs static analysis to detect common security misconfigurations in Docker Compose files and Python/FastAPI projects.
It generates actionable findings and produces reports in JSON (machines) and HTML (humans).

✅ No runtime scanning
✅ No code execution
✅ Safe-by-design parsing
✅ Designed for CI/CD and local audits

Features

✅ 20+ security rules (Docker, FastAPI, General)

📊 Score system (0–100) + letter grade (A–F)

📝 Dual reports: JSON + HTML

🔒 Security-first design: safe YAML parsing, escaping, limits, timeouts

🔌 Extensible architecture: decorator-based rule registration

⚡ Fast: static checks only

Installation
git clone https://github.com/claramercury/lattix-guard.git
cd lattix-guard
pip install -r requirements.txt

Usage
Basic scan
python -m lattix_guard /path/to/project

Output directory
python -m lattix_guard /path/to/project --out ./security-reports

Report format
python -m lattix_guard /path/to/project --format json
python -m lattix_guard /path/to/project --format html
python -m lattix_guard /path/to/project --format both

CI/CD mode

Fail the pipeline if severe issues are found:

python -m lattix_guard /path/to/project --fail-on critical
python -m lattix_guard /path/to/project --fail-on high

Exit codes

0 → scan OK (or below fail threshold)

1 → scan error (invalid input / parser failure)

2 → failed due to --fail-on threshold (critical/high)

Security Rules
Docker/Compose (10 rules)

Examples:

privileged: true

network_mode: host

exposed ports (0.0.0.0)

docker socket mounts (/var/run/docker.sock)

secrets in env variables

use of :latest

missing user: directive (runs as root)

FastAPI/Python (8 rules)

Examples:

CORS wildcard (allow_origins=["*"])

debug mode enabled

hardcoded secrets

unsafe logging patterns

missing JWT expiration patterns

General (2 rules)

Examples:

leaked certificates/keys (.pem, .key, .crt)

missing / insufficient .gitignore

Score interpretation
Score	Grade	Meaning
90–100	A	Excellent security posture
80–89	B	Good security, minor improvements needed
70–79	C	Several issues to address
60–69	D	Poor security posture
0–59	F	Critical issues, immediate action required
Security guarantees (by design)

Lattix Guard is built to be safe to run even on untrusted projects:

✅ YAML parsing: yaml.safe_load() only + strict limits

✅ No code execution: static analysis only

✅ HTML output escaped: markupsafe.escape + Jinja2 autoescape

✅ No symlinks

✅ Max file limits: prevents scanning huge home directories by accident

Development

Run tests:

pytest -v


Project structure:

lattix_guard/
├── lattix_guard/
│   ├── rules/
│   ├── parsers/
│   ├── scanner.py
│   ├── scoring.py
│   ├── report.py
│   └── cli.py
├── templates/
├── tests/
└── examples/

License

Licensed under GNU AGPL v3.0.
See LICENSE
.

Author

Clara Mercury
GitHub: https://github.com/claramercury

Part of the Lattix Project: https://github.com/claramercury/lattix

Contributing

PRs and issues are welcome.
If you propose new rules, please include a small test case.
## Reglas de Seguridad

### Docker/Docker Compose (10 reglas)

| ID de Regla | Título | Severidad | Descripción |
|-------------|--------|-----------|-------------|
| DOCKER-001 | Contenedor privilegiado | CRÍTICA | Detecta privileged: true |
| DOCKER-002 | Red del host | ALTA | Detecta network_mode: host |
| DOCKER-003 | Puertos expuestos | ALTA | Puertos expuestos a 0.0.0.0 |
| DOCKER-004 | Montaje de socket Docker | CRÍTICA | /var/run/docker.sock montado |
| DOCKER-005 | Secretos en variables de entorno | ALTA | Secretos hardcodeados en variables de entorno |
| DOCKER-006 | Etiqueta latest | BAJA | Uso de etiqueta de imagen :latest |
| DOCKER-007 | Falta directiva de usuario | MEDIA | Contenedor ejecutándose como root |
| DOCKER-008 | Adición de capacidades | MEDIA | Capacidades de Linux añadidas |
| DOCKER-009 | Volúmenes peligrosos | ALTA | Directorios del sistema montados |
| DOCKER-010 | Puerto de base de datos expuesto | ALTA | Puertos de BD (3306, 5432, etc.) expuestos |

### FastAPI/Python (8 reglas)

| ID de Regla | Título | Severidad | Descripción |
|-------------|--------|-----------|-------------|
| FASTAPI-001 | CORS con comodín | ALTA | allow_origins=["*"] |
| FASTAPI-002 | Documentación habilitada | MEDIA | Documentación de API no deshabilitada |
| FASTAPI-003 | .env no en .gitignore | CRÍTICA | Archivo .env rastreado por git |
| FASTAPI-004 | Secretos hardcodeados | CRÍTICA | SECRET_KEY hardcodeado |
| FASTAPI-005 | Modo debug | ALTA | DEBUG=True |
| FASTAPI-006 | Expiración JWT | MEDIA | Faltan verificaciones de expiración JWT |
| FASTAPI-007 | Secretos en logs | MEDIA | Tokens/secretos en registros |
| FASTAPI-008 | OpenAPI expuesto | BAJA | Endpoint OpenAPI no deshabilitado |

### General (2 reglas)

| ID de Regla | Título | Severidad | Descripción |
|-------------|--------|-----------|-------------|
| GENERAL-001 | Certificados en repositorio | CRÍTICA | Archivos .pem, .key, .crt encontrados |
| GENERAL-002 | Falta .gitignore | MEDIA | .gitignore ausente o insuficiente |

## Interpretación de Puntuación

| Puntuación | Calificación | Descripción |
|------------|--------------|-------------|
| 90-100 | A | Excelente postura de seguridad |
| 80-89 | B | Buena seguridad, mejoras menores necesarias |
| 70-79 | C | Seguridad aceptable, varios problemas por abordar |
| 60-69 | D | Seguridad deficiente, brechas significativas |
| 0-59 | F | Problemas críticos, acción inmediata requerida |

## Garantías de Seguridad

Lattix Guard está diseñado con la seguridad en mente:

1. **Análisis Seguro de YAML**: Usa yaml.safe_load() únicamente con límites de tamaño/profundidad/claves
2. **Sin Ejecución de Código**: 100% análisis estático, sin eval(), exec() o imports
3. **Sanitización de Entrada**: Todo el contenido derivado del usuario escapado en reportes HTML
4. **Seguridad de Rutas**: Solo rutas relativas en reportes, sin seguimiento de enlaces simbólicos
5. **Límites de Recursos**: Máximo 500 archivos escaneados, archivos YAML de 1MB, timeout de 10s
