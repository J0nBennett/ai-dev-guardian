from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


SEVERITY_ORDER = {
    Severity.LOW.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.HIGH.value: 3,
    Severity.CRITICAL.value: 4,
}


def normalize_severity(value: str) -> str:
    normalized = (value or "").strip().upper()
    if normalized in SEVERITY_ORDER:
        return normalized
    return Severity.LOW.value


def severity_gte(current: str, threshold: str) -> bool:
    return SEVERITY_ORDER.get(normalize_severity(current), 0) >= SEVERITY_ORDER.get(normalize_severity(threshold), 0)


def max_severity(findings: Iterable["Finding"]) -> str:
    best = 0
    best_name = "NONE"
    for finding in findings:
        sev = normalize_severity(finding.severity)
        rank = SEVERITY_ORDER.get(sev, 0)
        if rank > best:
            best = rank
            best_name = sev
    return best_name


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    confidence: str
    file_path: str
    line: int | None
    evidence: str
    recommendation: str
    source_rule_id: str | None = None


@dataclass(frozen=True)
class ScanResult:
    findings: list[Finding]
    warnings: list[str]
    integrations: dict[str, dict] = field(default_factory=dict)


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda finding: (
            -SEVERITY_ORDER.get(normalize_severity(finding.severity), 0),
            finding.rule_id,
            finding.file_path,
            finding.line or 0,
        ),
    )
