from __future__ import annotations

from pathlib import Path

from .filesystem import safe_read_text
from .rules import Finding


def scan_ci_checks(root: Path) -> list[Finding]:
    findings: list[Finding] = []

    workflows = root / ".github" / "workflows"
    if workflows.exists() and workflows.is_dir():
        for workflow in workflows.glob("*.y*ml"):
            content = safe_read_text(workflow)
            if not content:
                continue
            relative = str(workflow.relative_to(root)).replace("\\", "/")

            if "pull_request_target" in content:
                findings.append(
                    Finding(
                        rule_id="CI-001",
                        severity="HIGH",
                        confidence="HIGH",
                        file_path=relative,
                        line=None,
                        evidence="Workflow usa pull_request_target",
                        recommendation="Revisar confianza de forks y permisos del workflow.",
                    )
                )

            if "write-all" in content or "contents: write" in content:
                findings.append(
                    Finding(
                        rule_id="CI-002",
                        severity="HIGH",
                        confidence="MEDIUM",
                        file_path=relative,
                        line=None,
                        evidence="Workflow define permisos de escritura amplios",
                        recommendation="Reducir permisos de GITHUB_TOKEN al minimo necesario.",
                    )
                )

    gitlab = root / ".gitlab-ci.yml"
    if gitlab.exists() and gitlab.is_file():
        content = safe_read_text(gitlab)
        if "pull_request_target" in content:
            findings.append(
                Finding(
                    rule_id="CI-001",
                    severity="HIGH",
                    confidence="MEDIUM",
                    file_path=".gitlab-ci.yml",
                    line=None,
                    evidence="Patron de trigger sensible detectado en GitLab CI",
                    recommendation="Revisar ejecucion de pipelines desde fuentes no confiables.",
                )
            )
        if "curl" in content and "| bash" in content:
            findings.append(
                Finding(
                    rule_id="CI-003",
                    severity="CRITICAL",
                    confidence="HIGH",
                    file_path=".gitlab-ci.yml",
                    line=None,
                    evidence="Pipeline contiene curl | bash",
                    recommendation="Evitar ejecucion remota sin verificaciones de integridad.",
                )
            )
        if "echo $" in content:
            findings.append(
                Finding(
                    rule_id="CI-004",
                    severity="MEDIUM",
                    confidence="MEDIUM",
                    file_path=".gitlab-ci.yml",
                    line=None,
                    evidence="Pipeline puede imprimir variables en logs",
                    recommendation="No exponer variables sensibles en comandos echo.",
                )
            )

    return findings
