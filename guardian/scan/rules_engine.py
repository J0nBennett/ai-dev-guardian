from __future__ import annotations

from collections import Counter
from pathlib import Path

from .ci_checks import scan_ci_checks
from .metrics import Metrics
from .rules import Finding, ScanResult, normalize_severity, sort_findings
from .security import scan_security_findings
from .semgrep_integration import run_semgrep_scan


def _dependency_findings(metrics: Metrics) -> list[Finding]:
    findings: list[Finding] = []

    for manifest in metrics.missing_lockfiles:
        findings.append(
            Finding(
                rule_id="DEP-001",
                severity="MEDIUM",
                confidence="HIGH",
                file_path=manifest,
                line=None,
                evidence=f"No se detecto lockfile para {manifest}",
                recommendation="Agrega lockfile para builds reproducibles.",
            )
        )

    for manifest in metrics.unpinned_dependency_files:
        findings.append(
            Finding(
                rule_id="DEP-002",
                severity="HIGH",
                confidence="MEDIUM",
                file_path=manifest,
                line=None,
                evidence=f"Dependencias potencialmente no fijadas en {manifest}",
                recommendation="Fija versiones exactas y evita latest/* en produccion.",
            )
        )

    return findings


def run_security_scan(
    root: Path,
    metrics: Metrics | None = None,
    with_semgrep: bool = False,
) -> ScanResult:
    findings: list[Finding] = []
    warnings: list[str] = []
    integrations: dict[str, dict] = {
        "semgrep": {
            "enabled": bool(with_semgrep),
            "available": False,
            "findings_count": 0,
        }
    }

    findings.extend(scan_security_findings(root))
    findings.extend(scan_ci_checks(root))

    if metrics is not None:
        findings.extend(_dependency_findings(metrics))

    if with_semgrep:
        semgrep_findings, semgrep_warnings, semgrep_info = run_semgrep_scan(root)
        findings.extend(semgrep_findings)
        warnings.extend(semgrep_warnings)
        integrations["semgrep"] = semgrep_info

    dedup: dict[tuple[str, str, int | None, str], Finding] = {}
    for finding in findings:
        normalized = normalize_severity(finding.severity)
        fixed = Finding(
            rule_id=finding.rule_id,
            severity=normalized,
            confidence=finding.confidence,
            file_path=finding.file_path,
            line=finding.line,
            evidence=finding.evidence,
            recommendation=finding.recommendation,
            source_rule_id=finding.source_rule_id,
        )
        dedup[(fixed.rule_id, fixed.file_path, fixed.line, fixed.evidence)] = fixed

    return ScanResult(findings=sort_findings(dedup.values()), warnings=warnings, integrations=integrations)


def severity_counter(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(normalize_severity(finding.severity) for finding in findings)
    return {
        "CRITICAL": counts.get("CRITICAL", 0),
        "HIGH": counts.get("HIGH", 0),
        "MEDIUM": counts.get("MEDIUM", 0),
        "LOW": counts.get("LOW", 0),
    }
