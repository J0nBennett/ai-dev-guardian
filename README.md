# ai-dev-guardian

`ai-dev-guardian` es un scanner local-first para analizar repositorios de codigo y detectar riesgos de calidad y seguridad de forma reproducible, sin usar cloud ni LLMs.

## Quickstart

```bash
python -m guardian --version
python -m guardian scan --path . --out reports
python -m unittest -q
```

## Quick demo (CI-friendly)

```bash
python -m guardian scan --path . --out reports --fail-on HIGH
```

Interpretacion de exit codes:
- `0`: scan exitoso y no supera el umbral de `--fail-on`
- `1`: error interno inesperado
- `2`: se alcanzo o supero el umbral de severidad configurado

`--fail-on NONE` deshabilita el umbral y siempre retorna `0` aunque existan hallazgos CRITICAL.

## Que Hace

- Recorre archivos de forma segura (sin ejecutar codigo del repositorio objetivo).
- Calcula metricas estructurales:
  - total de archivos
  - conteo por extension
  - LOC estimadas
  - deteccion de carpetas de tests
  - deteccion de CI (`.github/workflows/*`, `.gitlab-ci.yml`)
- Detecta brechas potenciales:
  - secrets y credenciales hardcodeadas
  - archivos sensibles versionados
  - practicas riesgosas en CI/CD
  - checks basicos de dependencias (lockfiles y versiones no fijadas)
- Integracion opcional local de semgrep con reglas offline `rulesets/semgrep-basic.yml`.
- Genera reportes en JSON y Markdown.

## Que NO Hace

- No explota vulnerabilidades.
- No ejecuta codigo del repositorio analizado.
- No envia codigo a la nube.
- No usa APIs externas.

## Estructura De Reportes

- `reports/scan.json`
  - `tool` (`name`, `version`)
  - `schema_version`
  - `project_summary`
  - `metrics`
  - `security_summary`
  - `security_findings`
  - `integrations`
  - `ci_status`
  - `warnings`
- `reports/scan.md`
  - resumen ejecutivo
  - CI status (`fail_on`, `max_severity`, `expected_exit_code`)
  - resumen de semgrep
  - tabla de hallazgos

## Severidad Y Confidence

- Severidad: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
- Confidence: `LOW`, `MEDIUM`, `HIGH`

Cada hallazgo incluye: `id`, severidad, confidence, archivo, linea (si aplica), evidencia sanitizada y recomendacion.

## Seguridad De Evidencia

El reporte aplica masking para no exponer secretos completos:
- tokens: prefijo + `****` + ultimos 4 caracteres (ej: `ghp_****1a2b`)
- private keys: solo header `BEGIN PRIVATE KEY`
- aplica tanto a hallazgos nativos como a hallazgos de semgrep

## Integracion Opcional De Semgrep

Semgrep es opcional y local:

```bash
python -m guardian scan --path . --out reports --with-semgrep
```

Comportamiento:
- si semgrep no esta instalado: agrega warning y continua
- si esta instalado: ejecuta reglas offline de `rulesets/semgrep-basic.yml`

Mapping de severidad semgrep a guardian:
- `ERROR` -> `HIGH` (o `CRITICAL` si la regla es de seguridad directa)
- `WARNING` -> `MEDIUM`
- `INFO` -> `LOW`
- sin severidad -> `MEDIUM`

Trazabilidad:
- los hallazgos semgrep usan `id` tipo `SG-<rule_id_original>`
- ademas incluyen `source_rule_id` en `scan.json`

## Modo CI Con Fail-On

`--fail-on` controla cuando el comando debe fallar por severidad.

- `NONE` (default): nunca falla por findings
- `LOW|MEDIUM|HIGH|CRITICAL`: retorna exit code `2` si existe al menos un hallazgo con severidad mayor o igual al umbral

Ejemplos:

```bash
python -m guardian scan --path . --out reports --fail-on NONE
python -m guardian scan --path . --out reports --fail-on HIGH
python -m guardian scan --path . --out reports --fail-on CRITICAL
```

## Restricciones Del MVP 0.1.1

- 100% local-first
- Python estandar
- dependencias runtime minimas
