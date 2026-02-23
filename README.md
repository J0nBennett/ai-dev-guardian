# ai-dev-guardian

`ai-dev-guardian` es una herramienta local-first para analizar repositorios y explicar riesgos de forma accionable.

## Quickstart

```bash
python -m guardian --version
python -m guardian scan --path . --out reports
python -m guardian ai --scan reports/scan.json --out reports/ai.md
python -m unittest -q
```

## Principios

- 100% local-first
- Sin cloud ni APIs externas
- Sin ejecutar codigo del repo analizado
- `scan.json` es la fuente de verdad para la fase IA

## Fase Scan

`guardian scan` realiza analisis deterministico y genera:
- `reports/scan.json`
- `reports/scan.md`

Incluye:
- metricas de estructura
- hallazgos de seguridad
- CI status
- integracion opcional semgrep local
- **project_profile**

### Project Profile

`scan.json` ahora incluye:

```json
"project_profile": {
  "name": "generic|web|backend|mobile|infra|library",
  "signals": ["package.json", "AGENTS.md"]
}
```

Heuristicas best-effort:
- `web`: frameworks web comunes en `package.json`
- `backend`: frameworks backend node/python
- `mobile`: `pubspec.yaml`, `android/`, `ios/`
- `infra`: terraform/k8s/docker-heavy
- `library`: `src/` + `docs/` sin entrypoints claros
- default: `generic`

Tambien detecta senales de repos asistidos por IA/agentes (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.windsurfrules`, etc.).

## Fase AI (Generalista)

`guardian ai` **no escanea codigo**. Solo interpreta `scan.json`.

```bash
python -m guardian ai --scan reports/scan.json --out reports/ai.md
```

Defaults:
- `--provider ollama`
- `--model llama3.1:8b`
- `--max-findings 25`

Comportamiento:
- Prompt generalista para cualquier web/app/proyecto
- Terminologia orientada a hallazgos/riesgos
- Agrupacion de hallazgos para evitar repeticion
- Checklist obligatorio "repos generados por IA/agentes"

## Agrupacion De Hallazgos (AI)

Antes de pedir explicacion al modelo, los findings se agrupan por:
- `rule_id + severity`

Cada grupo incluye:
- `rule_id`
- `severity`
- `count`
- hasta 5 `examples` (paths)
- acciones sugeridas

Ejemplo: 15 findings `SEC-017` -> 1 grupo con `count=15`.

## ai.json Estructurado

Ademas de `ai.md`, se genera `ai.json` con campos para automatizacion:

- `risk_level`
- `grouped_findings`
- `priorities` (`P0`, `P1`, `P2`)
- `quick_wins`
- `manual_checks`
- `ci_hardening`

## Integracion Opcional De Semgrep

Semgrep sigue siendo opcional y local:

```bash
python -m guardian scan --path . --out reports --with-semgrep
```

Si semgrep no esta disponible, el scan continua con warning.

## Modo CI Con Fail-On

```bash
python -m guardian scan --path . --out reports --fail-on NONE
python -m guardian scan --path . --out reports --fail-on HIGH
```

Exit codes scan:
- `0`: OK segun umbral
- `1`: error interno
- `2`: umbral alcanzado

Exit codes ai:
- `0`: exito
- `1`: error interno/entrada invalida
- `3`: proveedor IA no disponible (Ollama/modelo)
