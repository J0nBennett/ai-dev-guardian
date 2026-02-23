from __future__ import annotations

import re
from pathlib import Path

from .filesystem import iter_project_files, safe_read_text
from .masking import mask_evidence
from .rules import Finding


def _new_finding(
    rule_id: str,
    severity: str,
    confidence: str,
    rel: Path,
    line: int | None,
    evidence: str,
    recommendation: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        confidence=confidence,
        file_path=str(rel).replace("\\", "/"),
        line=line,
        evidence=mask_evidence(evidence.strip()[:240]),
        recommendation=recommendation,
    )


def _looks_like_pattern_definition(line: str) -> bool:
    lower = line.lower()
    if "sec-" in lower and "r\"" in line:
        return True
    if "pattern:" in lower and any(marker in lower for marker in ("akia", "ghp_", "github_pat_", "xoxb-", "begin private key")):
        return True
    if "regex" in lower and any(marker in lower for marker in ("akia", "ghp_", "github_pat_", "xoxb-", "begin private key")):
        return True
    return False


def _is_doc_example(line: str, rule_id: str) -> bool:
    lower = line.lower()
    if rule_id == "SEC-001":
        markers = ("mask", "header", "example", "ej:", "ejemplo", "startswith", "solo", "return", "evidence =")
        if any(marker in lower for marker in markers):
            return True
    return False


def _scan_line_patterns(text: str, rel: Path) -> list[Finding]:
    findings: list[Finding] = []

    secret_patterns: list[tuple[str, str, str, str, str]] = [
        (r"BEGIN PRIVATE KEY", "SEC-001", "CRITICAL", "HIGH", "Remueve llaves privadas y rota credenciales."),
        (r"AKIA[0-9A-Z]{16}", "SEC-002", "CRITICAL", "HIGH", "Revoca la clave AWS y usa secretos fuera del repo."),
        (
            r"ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}",
            "SEC-003",
            "CRITICAL",
            "HIGH",
            "Revoca token GitHub y evita hardcodear secretos.",
        ),
        (r"xoxb-[0-9A-Za-z-]{20,}", "SEC-004", "HIGH", "HIGH", "Revoca token de Slack y usa variables seguras."),
        (r"AIza[0-9A-Za-z_-]{35}", "SEC-005", "HIGH", "HIGH", "Regenera API key de Google y elimina la exposicion."),
        (
            r"(?i)(jwt|token|auth|authorization|bearer|secret)[^\n\r]{0,40}[:=][^\n\r]*?(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})",
            "SEC-006",
            "HIGH",
            "MEDIUM",
            "No hardcodees JWT; usa emision dinamica.",
        ),
    ]

    ci_patterns: list[tuple[str, str, str, str, str]] = [
        (r"\bpull_request_target\b", "CI-001", "HIGH", "HIGH", "Evita pull_request_target sin controles estrictos."),
        (r"\bwrite-all\b|\bcontents:\s*write\b", "CI-002", "HIGH", "MEDIUM", "Reduce permisos de token CI al minimo."),
        (r"curl\s+[^\n\r]*\|\s*(bash|sh)\b", "CI-003", "CRITICAL", "HIGH", "Evita curl|bash y valida integridad con checksum."),
        (
            r"(?i)echo\s+[^\n\r]*\$(?:[A-Za-z_][A-Za-z0-9_]*(TOKEN|SECRET|KEY|PASSWORD|PASS|CRED)[A-Za-z0-9_]*)",
            "CI-004",
            "MEDIUM",
            "MEDIUM",
            "No imprimas variables sensibles en logs.",
        ),
    ]

    is_ci_file = str(rel).endswith((".yml", ".yaml", ".gitlab-ci.yml"))

    for line_number, line in enumerate(text.splitlines(), start=1):
        if not _looks_like_pattern_definition(line):
            for pattern, rule_id, severity, confidence, recommendation in secret_patterns:
                match = re.search(pattern, line)
                if not match:
                    continue
                if _is_doc_example(line, rule_id):
                    continue

                evidence = line
                if rule_id == "SEC-001":
                    evidence = "BEGIN PRIVATE KEY"
                elif match.lastindex:
                    evidence = match.group(match.lastindex)
                else:
                    evidence = match.group(0)

                findings.append(
                    _new_finding(rule_id, severity, confidence, rel, line_number, evidence, recommendation)
                )

        if is_ci_file:
            for pattern, rule_id, severity, confidence, recommendation in ci_patterns:
                if re.search(pattern, line):
                    findings.append(
                        _new_finding(rule_id, severity, confidence, rel, line_number, line, recommendation)
                    )

    return findings


def _scan_sensitive_files(rel: Path) -> list[Finding]:
    findings: list[Finding] = []
    name = rel.name.lower()
    suffix = rel.suffix.lower()

    sensitive_exact = {
        ".env": ("SEC-010", "HIGH", "HIGH", "No versiones .env con secretos reales."),
        "id_rsa": ("SEC-011", "CRITICAL", "HIGH", "Retira id_rsa y rota credenciales asociadas."),
        "kubeconfig": ("SEC-012", "HIGH", "MEDIUM", "Evita versionar kubeconfig con acceso a clusters."),
        "credentials.json": ("SEC-013", "HIGH", "MEDIUM", "Mueve credenciales fuera del repositorio."),
    }
    sensitive_extensions = {
        ".pem": ("SEC-014", "CRITICAL", "HIGH", "No comitees .pem y rota material criptografico."),
        ".p12": ("SEC-015", "CRITICAL", "HIGH", "Retira .p12 y usa almacenamiento seguro."),
        ".key": ("SEC-016", "CRITICAL", "HIGH", "No comitees .key en repositorios."),
        ".sql": ("SEC-017", "MEDIUM", "MEDIUM", "Revisa si el dump SQL contiene datos sensibles."),
        ".bak": ("SEC-018", "MEDIUM", "MEDIUM", "Evita respaldos con datos sensibles en el repo."),
        ".dump": ("SEC-019", "MEDIUM", "MEDIUM", "No versionar dumps de datos de produccion."),
    }

    if name in sensitive_exact:
        rule_id, severity, confidence, recommendation = sensitive_exact[name]
        findings.append(_new_finding(rule_id, severity, confidence, rel, None, str(rel), recommendation))

    if suffix in sensitive_extensions:
        rule_id, severity, confidence, recommendation = sensitive_extensions[suffix]
        findings.append(_new_finding(rule_id, severity, confidence, rel, None, str(rel), recommendation))

    return findings


def scan_security_findings(root: Path) -> list[Finding]:
    findings: list[Finding] = []

    for file_info in iter_project_files(root):
        rel = file_info.relative_path
        findings.extend(_scan_sensitive_files(rel))
        content = safe_read_text(file_info.path)
        if content:
            findings.extend(_scan_line_patterns(content, rel))

    return findings
