from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from .filesystem import DEFAULT_IGNORES
from .masking import mask_evidence
from .rules import Finding


def _is_direct_security_rule(rule_id: str) -> bool:
    lower = rule_id.lower()
    markers = (
        "security",
        "secret",
        "token",
        "auth",
        "injection",
        "xss",
        "sqli",
        "crypto",
        "command",
        "password",
        "credential",
    )
    return any(marker in lower for marker in markers)


def _map_semgrep_severity(raw: str | None, source_rule_id: str) -> str:
    value = (raw or "").upper().strip()
    if not value:
        return "MEDIUM"
    if value == "ERROR":
        return "CRITICAL" if _is_direct_security_rule(source_rule_id) else "HIGH"
    if value == "WARNING":
        return "MEDIUM"
    if value == "INFO":
        return "LOW"
    return "MEDIUM"


def _confidence_from_rule(rule_id: str) -> str:
    return "HIGH" if _is_direct_security_rule(rule_id) else "MEDIUM"


def run_semgrep_scan(root: Path) -> tuple[list[Finding], list[str], dict[str, object]]:
    info: dict[str, object] = {
        "enabled": True,
        "available": False,
        "findings_count": 0,
    }
    warnings: list[str] = []
    findings: list[Finding] = []

    semgrep_bin = shutil.which("semgrep")
    if not semgrep_bin:
        warnings.append("Semgrep no esta instalado; se omite integracion --with-semgrep.")
        return findings, warnings, info

    info["available"] = True

    tool_root = Path(__file__).resolve().parents[2]
    config_path = tool_root / "rulesets" / "semgrep-basic.yml"
    if not config_path.exists():
        warnings.append("No se encontro rulesets/semgrep-basic.yml; se omite integracion semgrep.")
        return findings, warnings, info

    command = [
        semgrep_bin,
        "--config",
        str(config_path),
        "--json",
        "--quiet",
        "--disable-version-check",
    ]
    for ignored in sorted(DEFAULT_IGNORES):
        command.extend(["--exclude", ignored])
    command.append(str(root))

    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=180)
    except OSError as exc:
        warnings.append(f"Semgrep no pudo ejecutarse: {exc}")
        return findings, warnings, info
    except subprocess.TimeoutExpired:
        warnings.append("Semgrep excedio el tiempo limite y fue omitido.")
        return findings, warnings, info

    if completed.returncode not in (0, 1):
        warnings.append("Semgrep devolvio un error y fue omitido en este scan.")
        return findings, warnings, info

    payload_text = completed.stdout.strip()
    if not payload_text:
        info["findings_count"] = 0
        return findings, warnings, info

    try:
        payload = json.loads(payload_text)
    except json.JSONDecodeError:
        warnings.append("Semgrep devolvio salida no JSON; no se incorporaron hallazgos.")
        return findings, warnings, info

    for index, item in enumerate(payload.get("results", []), start=1):
        source_rule_id = str(item.get("check_id") or f"anonymous-{index:03d}")
        extra = item.get("extra", {}) or {}
        start = item.get("start", {}) or {}
        semgrep_path = Path(str(item.get("path") or ""))
        try:
            file_path = str(semgrep_path.resolve().relative_to(root.resolve())).replace("\\", "/")
        except Exception:
            file_path = str(semgrep_path).replace("\\", "/")

        rule_id = f"SG-{source_rule_id}"
        message = str(extra.get("message") or "Semgrep finding")
        lines = str(extra.get("lines") or "").strip()
        evidence_raw = lines if lines else message
        recommendation = str(extra.get("fix") or "Revisar y corregir el patron detectado por semgrep.")

        findings.append(
            Finding(
                rule_id=rule_id,
                severity=_map_semgrep_severity(extra.get("severity"), source_rule_id),
                confidence=_confidence_from_rule(source_rule_id),
                file_path=file_path,
                line=int(start["line"]) if isinstance(start.get("line"), int) else None,
                evidence=mask_evidence(evidence_raw)[:240],
                recommendation=recommendation,
                source_rule_id=source_rule_id,
            )
        )

    info["findings_count"] = len(findings)
    return findings, warnings, info
