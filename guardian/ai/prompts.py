from __future__ import annotations

import json
from typing import Any


def build_ai_prompt(scan_payload: dict[str, Any], max_findings: int) -> str:
    project_summary = scan_payload.get("project_summary", {})
    security_summary = scan_payload.get("security_summary", {})
    ci_status = scan_payload.get("ci_status", {})
    warnings = scan_payload.get("warnings", [])
    findings = scan_payload.get("security_findings", [])[:max_findings]

    input_data = {
        "project_summary": project_summary,
        "security_summary": security_summary,
        "ci_status": ci_status,
        "warnings": warnings,
        "security_findings": findings,
    }

    instructions = (
        "Eres un asistente de seguridad para desarrolladores. "
        "Responde SOLO en espanol. Usa EXCLUSIVAMENTE los datos JSON entregados. "
        "No inventes hallazgos. No recomiendes explotacion ofensiva. "
        "No muestres secretos completos. Respeta valores enmascarados."
    )

    terminology_rules = (
        "Reglas de terminologia obligatorias:\n"
        "- Usa 'hallazgos' o 'riesgos' por defecto.\n"
        "- Usa 'vulnerabilidad' solo cuando el hallazgo sea inequivoco (secrets reales, CI riesgoso claro o patron directo).\n"
        "- Para SEC-017 (SQL versionado), NUNCA decir 'no se recomienda su uso'. "
        "Debes tratarlo como riesgo contextual y pedir revision de contenido."
    )

    sec017_context = (
        "Contextualizacion obligatoria para SEC-017:\n"
        "- Reconocer que archivos SQL son comunes en repos APEX/QA (deploy scripts, callbacks, tests SQL).\n"
        "- Riesgos reales a revisar: credenciales hardcodeadas, dumps con datos reales, secrets en comentarios, endpoints internos.\n"
        "- Acciones concretas: buscar patrones password=, token, api_key, bearer, AKIA, ghp_, BEGIN PRIVATE KEY; "
        "separar scripts de despliegue vs dumps de datos; permitir allowlist/ignore por paths justificando el por que; "
        "mantener --fail-on HIGH en CI para controlar ruido."
    )

    ci_hardening = (
        "Hardening de CI:\n"
        "- Aunque no haya hallazgos CI, incluye 3-5 recomendaciones generales.\n"
        "- Debes cubrir: permisos minimos en GitHub Actions, no imprimir secrets, pin de actions por SHA/version fija, "
        "artifact retention + masking, y usar --fail-on HIGH como gate."
    )

    output_contract = (
        "Estructura obligatoria:\n"
        "A) Resumen ejecutivo del estado del proyecto\n"
        "B) Priorizacion de riesgos (P0=CRITICAL, P1=HIGH, P2=MEDIUM)\n"
        "C) Explicacion por tipo de hallazgo: que es, por que importa, cuando es riesgo real\n"
        "D) Acciones recomendadas defensivas (pasos concretos, sin ejecutar codigo)\n"
        "E) Hardening de CI (siempre incluir, aun sin hallazgos CI)\n"
        "F) Quick wins (max 5, concretos y no repetidos)\n"
        "G) Que revisar manualmente (max 5, especifico por tipo de hallazgo, evitar generalidades)"
    )

    short_example = (
        "Ejemplo breve esperado para SEC-017:\n"
        "- 'SEC-017 sugiere un riesgo contextual: los SQL pueden ser scripts validos de APEX/QA; "
        "verifica que no incluyan credenciales, tokens ni dumps productivos.'"
    )

    return (
        f"{instructions}\n\n"
        f"{terminology_rules}\n\n"
        f"{sec017_context}\n\n"
        f"{ci_hardening}\n\n"
        f"{output_contract}\n\n"
        f"{short_example}\n\n"
        "Fuente unica de verdad (scan.json parcial):\n"
        f"{json.dumps(input_data, indent=2, ensure_ascii=False)}\n"
    )
