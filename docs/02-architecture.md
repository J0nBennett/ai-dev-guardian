# Architecture

- `guardian/cli.py`: entrypoint CLI y orquestación.
- `guardian/scan/filesystem.py`: recorrido seguro y lectura controlada.
- `guardian/scan/metrics.py`: métricas de estructura y dependencias.
- `guardian/scan/security.py`: detección de brechas de seguridad.
- `guardian/scan/ci_checks.py`: riesgos en pipelines CI/CD.
- `guardian/scan/rules_engine.py`: consolidación y severidad.
- `guardian/scan/reporter.py`: exportación JSON y Markdown.
