from __future__ import annotations

import json
from typing import Any


def _has_domain_signals(profile: dict[str, Any]) -> bool:
    signals = [str(item).lower() for item in (profile.get("signals") or [])]
    return any("qa" in signal or "apex" in signal for signal in signals)


def build_ai_prompt(
    scan_payload: dict[str, Any],
    max_findings: int,
    grouped_findings: list[dict[str, Any]],
) -> str:
    project_summary = scan_payload.get("project_summary", {})
    security_summary = scan_payload.get("security_summary", {})
    ci_status = scan_payload.get("ci_status", {})
    warnings = scan_payload.get("warnings", [])
    profile = scan_payload.get("project_profile", {"name": "generic", "signals": []})
    findings = scan_payload.get("security_findings", [])[:max_findings]

    input_data = {
        "project_summary": project_summary,
        "project_profile": profile,
        "security_summary": security_summary,
        "ci_status": ci_status,
        "warnings": warnings,
        "grouped_findings": grouped_findings,
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
        "- Usa 'vulnerabilidad' solo si existe evidencia inequivoca (HIGH/CRITICAL claros por secretos reales o CI inseguro directo).\n"
        "- Mantener tono generalista para cualquier web/app/proyecto."
    )

    neutrality = (
        "Regla de neutralidad:\n"
        "- No asumas dominios especificos por defecto.\n"
        "- Solo menciona contexto de dominio si project_profile.signals lo soporta explicitamente.\n"
        "- Si profile es generic/web/backend/mobile/infra/library sin senales de dominio, evita referencias contextuales no justificadas."
    )

    sec017_context = (
        "Contextualizacion obligatoria para SEC-017:\n"
        "- Explicar que SQL versionado puede ser normal (migrations, seeds, scripts).\n"
        "- Riesgo real solo si hay credenciales, tokens o dumps reales.\n"
        "- Acciones concretas: buscar patrones password=, token, api_key, bearer, AKIA, ghp_, BEGIN PRIVATE KEY; "
        "separar dumps de datos; usar .env.example y .gitignore adecuados."
    )

    ci_hardening = (
        "Hardening de CI (siempre incluir, aun sin hallazgos CI):\n"
        "- permissions minimas en GitHub Actions\n"
        "- no imprimir secrets\n"
        "- pin de actions por SHA o version fija\n"
        "- artifact retention + masking\n"
        "- usar --fail-on HIGH como gate"
    )

    output_contract = (
        "Estructura obligatoria:\n"
        "A) Resumen ejecutivo del estado del proyecto\n"
        "B) Priorizacion de riesgos (P0=CRITICAL, P1=HIGH, P2=MEDIUM)\n"
        "C) Explicacion por tipo de hallazgo: que es, por que importa, cuando es riesgo real\n"
        "D) Acciones recomendadas defensivas (pasos concretos, sin ejecutar codigo)\n"
        "E) Hardening de CI\n"
        "F) Quick wins (max 5, concretos y no repetidos)\n"
        "G) Que revisar manualmente (max 5, especifico por tipo de hallazgo)"
    )

    grouped_instruction = (
        "Debes priorizar grouped_findings para evitar repetir hallazgos identicos. "
        "Usa count y ejemplos para explicar impacto agregado."
    )

    domain_clause = ""
    if _has_domain_signals(profile):
        domain_clause = "\nHay senales de dominio explicitas en project_profile.signals; puedes usarlas con cautela."

    return (
        f"{instructions}\n\n"
        f"{terminology_rules}\n\n"
        f"{neutrality}{domain_clause}\n\n"
        f"{sec017_context}\n\n"
        f"{ci_hardening}\n\n"
        f"{output_contract}\n\n"
        f"{grouped_instruction}\n\n"
        "Fuente unica de verdad (scan.json parcial):\n"
        f"{json.dumps(input_data, indent=2, ensure_ascii=False)}\n"
    )
