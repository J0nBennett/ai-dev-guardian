from __future__ import annotations

import json
from pathlib import Path

from guardian import __version__

from .metrics import Metrics
from .rules import ScanResult, max_severity
from .rules_engine import severity_counter


def _score(scan_result: ScanResult) -> str:
    summary = severity_counter(scan_result.findings)
    if summary["CRITICAL"] > 0:
        return "FAIL"
    if summary["HIGH"] > 0 or summary["MEDIUM"] > 0:
        return "WARN"
    return "OK"


def _json_payload(
    project_path: Path,
    metrics: Metrics,
    scan_result: ScanResult,
    fail_on: str,
    expected_exit_code: int,
) -> dict:
    summary = severity_counter(scan_result.findings)
    findings_payload: list[dict[str, object]] = []
    for finding in scan_result.findings:
        item: dict[str, object] = {
            "id": finding.rule_id,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "file": finding.file_path,
            "line": finding.line,
            "evidence": finding.evidence,
            "recommendation": finding.recommendation,
        }
        if finding.source_rule_id:
            item["source_rule_id"] = finding.source_rule_id
        findings_payload.append(item)

    return {
        "tool": {
            "name": "ai-dev-guardian",
            "version": __version__,
        },
        "schema_version": "1.0",
        "project_summary": {
            "path": str(project_path),
            "score": _score(scan_result),
        },
        "metrics": {
            "total_files": metrics.total_files,
            "files_by_extension": metrics.files_by_extension,
            "estimated_loc": metrics.estimated_loc,
            "test_directories": metrics.test_directories,
            "ci_detected": metrics.ci_detected,
            "missing_lockfiles": metrics.missing_lockfiles,
            "unpinned_dependency_files": metrics.unpinned_dependency_files,
        },
        "security_summary": summary,
        "security_findings": findings_payload,
        "integrations": scan_result.integrations,
        "ci_status": {
            "fail_on": fail_on,
            "max_severity": max_severity(scan_result.findings),
            "expected_exit_code": expected_exit_code,
        },
        "warnings": scan_result.warnings,
    }


def _markdown_report(
    project_path: Path,
    metrics: Metrics,
    scan_result: ScanResult,
    fail_on: str,
    expected_exit_code: int,
) -> str:
    summary = severity_counter(scan_result.findings)
    score = _score(scan_result)
    max_found = max_severity(scan_result.findings)
    semgrep_info = scan_result.integrations.get("semgrep", {})

    lines: list[str] = []
    lines.append("# Guardian Scan Report")
    lines.append("")
    lines.append("## Resumen Ejecutivo")
    lines.append(f"- Proyecto: `{project_path}`")
    lines.append(f"- Tool: `ai-dev-guardian {__version__}`")
    lines.append(f"- Score: **{score}**")
    lines.append(f"- Archivos analizados: **{metrics.total_files}**")
    lines.append(f"- LOC estimadas: **{metrics.estimated_loc}**")
    lines.append("")
    lines.append("## CI Status")
    lines.append(f"- fail_on: `{fail_on}`")
    lines.append(f"- max_severity: `{max_found}`")
    lines.append(f"- expected_exit_code: `{expected_exit_code}`")
    lines.append("")
    lines.append("## Security Summary")
    lines.append(f"- CRITICAL: {summary['CRITICAL']}")
    lines.append(f"- HIGH: {summary['HIGH']}")
    lines.append(f"- MEDIUM: {summary['MEDIUM']}")
    lines.append(f"- LOW: {summary['LOW']}")
    lines.append("")
    lines.append("## Semgrep")
    lines.append(f"- enabled: {semgrep_info.get('enabled', False)}")
    lines.append(f"- available: {semgrep_info.get('available', False)}")
    lines.append(f"- findings_count: {semgrep_info.get('findings_count', 0)}")
    lines.append("")
    lines.append("## Hallazgos de Seguridad")
    lines.append("| ID | Severidad | Confidence | Archivo | Linea | Evidencia | Recomendacion |")
    lines.append("|---|---|---|---|---:|---|---|")

    for finding in scan_result.findings:
        line_value = "" if finding.line is None else str(finding.line)
        evidence = finding.evidence.replace("|", "\\|")
        recommendation = finding.recommendation.replace("|", "\\|")
        lines.append(
            f"| {finding.rule_id} | {finding.severity} | {finding.confidence} | `{finding.file_path}` | {line_value} | {evidence} | {recommendation} |"
        )

    lines.append("")
    if scan_result.warnings:
        lines.append("## Warnings")
        for warning in scan_result.warnings:
            lines.append(f"- {warning}")
        lines.append("")

    lines.append("## Recomendaciones Prioritarias")
    lines.append("1. Eliminar y rotar credenciales detectadas en codigo y archivos sensibles versionados.")
    lines.append("2. Endurecer pipelines CI/CD: permisos minimos y sin ejecucion remota insegura.")
    lines.append("3. Fijar dependencias y lockfiles para builds reproducibles.")

    return "\n".join(lines) + "\n"


def write_reports(
    path: Path,
    out_dir: Path,
    metrics: Metrics,
    scan_result: ScanResult,
    fail_on: str,
    expected_exit_code: int,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    payload = _json_payload(path, metrics, scan_result, fail_on, expected_exit_code)
    (out_dir / "scan.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    markdown = _markdown_report(path, metrics, scan_result, fail_on, expected_exit_code)
    (out_dir / "scan.md").write_text(markdown, encoding="utf-8")
