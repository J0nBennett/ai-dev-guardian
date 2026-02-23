from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _extract_list_items(text: str, limit: int = 8) -> list[str]:
    items: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("- "):
            items.append(stripped[2:].strip())
        elif len(stripped) > 3 and stripped[0].isdigit() and stripped[1:3] == ". ":
            items.append(stripped[3:].strip())
        if len(items) >= limit:
            break
    return items


def _section_items(text: str, section_markers: list[str], limit: int = 5) -> list[str]:
    lines = text.splitlines()
    in_section = False
    items: list[str] = []
    markers = [marker.lower() for marker in section_markers]

    for line in lines:
        stripped = line.strip()
        lowered = stripped.lower()
        if stripped.startswith("#"):
            in_section = any(marker in lowered for marker in markers)
            continue
        if in_section and stripped.startswith("- "):
            items.append(stripped[2:].strip())
        if in_section and len(items) >= limit:
            break

    return items


def _actions_for_group(rule_id: str, severity: str) -> list[str]:
    if rule_id == "SEC-017":
        return [
            "Buscar patrones sensibles: password=, token, api_key, bearer, AKIA, ghp_, BEGIN PRIVATE KEY.",
            "Separar scripts SQL operativos de dumps de datos reales.",
            "Mantener .env.example y .gitignore alineados para prevenir fugas.",
        ]

    if severity == "CRITICAL":
        return ["Contener y rotar secretos/credenciales asociados de inmediato."]
    if severity == "HIGH":
        return ["Corregir en el proximo ciclo y agregar control preventivo en CI."]
    if severity == "MEDIUM":
        return ["Validar contexto y aplicar mitigacion para reducir riesgo operativo."]
    return ["Documentar decision de riesgo y monitorear recurrencia."]


def group_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], dict[str, Any]] = {}

    for finding in findings:
        rule_id = str(finding.get("id") or "UNKNOWN")
        severity = str(finding.get("severity") or "LOW")
        file_path = str(finding.get("file") or "")
        key = (rule_id, severity)

        if key not in grouped:
            grouped[key] = {
                "rule_id": rule_id,
                "severity": severity,
                "count": 0,
                "examples": [],
                "actions": _actions_for_group(rule_id, severity),
            }

        grouped[key]["count"] += 1
        if file_path and file_path not in grouped[key]["examples"] and len(grouped[key]["examples"]) < 5:
            grouped[key]["examples"].append(file_path)

    ordered = sorted(
        grouped.values(),
        key=lambda item: (
            {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(str(item["severity"]), 0) * -1,
            str(item["rule_id"]),
        ),
    )
    return ordered


def _risk_level(grouped_findings: list[dict[str, Any]]) -> str:
    severities = {str(item.get("severity", "LOW")) for item in grouped_findings}
    if "CRITICAL" in severities or "HIGH" in severities:
        return "HIGH"
    if "MEDIUM" in severities:
        return "MEDIUM"
    return "LOW"


def _priorities(grouped_findings: list[dict[str, Any]]) -> dict[str, list[str]]:
    p0 = sorted({str(item["rule_id"]) for item in grouped_findings if str(item.get("severity")) == "CRITICAL"})
    p1 = sorted({str(item["rule_id"]) for item in grouped_findings if str(item.get("severity")) == "HIGH"})
    p2 = sorted({str(item["rule_id"]) for item in grouped_findings if str(item.get("severity")) == "MEDIUM"})
    return {"P0": p0, "P1": p1, "P2": p2}


def _agent_ready_checklist(profile_name: str) -> list[str]:
    base = [
        "Revisar scripts que descargan binarios o ejecutan contenido remoto (ej. curl | bash).",
        "Aplicar permisos minimos en workflows de CI/CD.",
        "Pinear acciones de GitHub Actions por SHA o version fija.",
        "Verificar lockfiles presentes y actualizados.",
        "Justificar dependencias nuevas y eliminar las innecesarias.",
        "Asegurar un baseline de lint/format/test automatizado.",
        "Mantener .env.example actualizado y sin secretos reales.",
        "Confirmar que .env y archivos sensibles no se comitean.",
        "Agregar SECURITY.md para proceso de reporte de riesgos.",
        "Agregar CONTRIBUTING.md con estandares para cambios asistidos por IA/agentes.",
    ]

    profile_specific = {
        "web": [
            "Revisar politicas CSP/CORS y configuracion de headers de seguridad.",
            "Validar manejo de secretos en build-time vs runtime del frontend.",
        ],
        "backend": [
            "Revisar validacion de entrada y manejo de auth en endpoints expuestos.",
            "Confirmar logging seguro sin datos sensibles en respuestas/errores.",
        ],
        "mobile": [
            "Validar almacenamiento seguro de tokens en dispositivo.",
            "Revisar permisos de app y configuraciones de build por entorno.",
        ],
        "infra": [
            "Revisar estados remotos/secretos en IaC sin credenciales hardcodeadas.",
            "Aplicar politicas de drift y aprobaciones en cambios de infraestructura.",
        ],
        "library": [
            "Definir superficie publica estable y compatibilidad semantica.",
            "Documentar riesgos de seguridad para consumidores de la libreria.",
        ],
    }

    return base + profile_specific.get(profile_name, [
        "Revisar ownership de archivos criticos y controles de calidad minimos por modulo.",
        "Alinear convenciones de commit/review para cambios asistidos por agentes.",
    ])


def render_ai_markdown(model: str, provider: str, analysis_text: str, project_profile: dict[str, Any]) -> str:
    profile_name = str((project_profile or {}).get("name") or "generic")
    checklist = _agent_ready_checklist(profile_name)

    lines: list[str] = []
    lines.append("# AI Analysis Report")
    lines.append("")
    lines.append(f"- Provider: `{provider}`")
    lines.append(f"- Model: `{model}`")
    lines.append(f"- Profile: `{profile_name}`")
    lines.append("")
    lines.append("> Nota: Los hallazgos MEDIUM pueden ser contextuales; use `--fail-on HIGH` en CI para reducir ruido.")
    lines.append("")
    lines.append(analysis_text.strip())
    lines.append("")
    lines.append("## Checklist para repos generados por IA / agentes")
    for item in checklist[:12]:
        lines.append(f"- {item}")
    lines.append("")

    return "\n".join(lines)


def build_ai_json_payload(
    provider: str,
    model: str,
    analysis_text: str,
    grouped_findings: list[dict[str, Any]],
) -> dict:
    quick_wins = _section_items(analysis_text, ["quick wins"], limit=5)
    manual_checks = _section_items(analysis_text, ["revisar manualmente", "que revisar manualmente"], limit=5)
    ci_hardening = _section_items(analysis_text, ["hardening de ci", "ci hardening"], limit=5)

    if not quick_wins:
        quick_wins = [action for group in grouped_findings for action in group.get("actions", [])][:5]
    if not manual_checks:
        manual_checks = [
            "Validar manualmente los paths ejemplo de los hallazgos agrupados.",
            "Confirmar si los hallazgos MEDIUM son contextuales o requieren correccion inmediata.",
        ][:5]
    if not ci_hardening:
        ci_hardening = [
            "Aplicar permisos minimos en workflows.",
            "No imprimir secretos en logs.",
            "Pinear actions por SHA/version fija.",
            "Usar --fail-on HIGH como gate.",
        ]

    return {
        "provider": provider,
        "model": model,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": analysis_text[:1200],
        "recommendations": _extract_list_items(analysis_text, limit=10),
        "risk_level": _risk_level(grouped_findings),
        "grouped_findings": grouped_findings,
        "priorities": _priorities(grouped_findings),
        "quick_wins": quick_wins[:5],
        "manual_checks": manual_checks[:5],
        "ci_hardening": ci_hardening[:5],
    }


def write_ai_outputs(out_path: Path, markdown: str, json_payload: dict) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(markdown, encoding="utf-8")

    json_path = out_path.with_suffix(".json")
    json_path.write_text(__import__("json").dumps(json_payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
