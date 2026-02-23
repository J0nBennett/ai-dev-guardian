from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from guardian.ai.provider import AIProviderResponse
from guardian.cli import run_ai


class _CapturingProvider:
    def __init__(self) -> None:
        self.last_request = None

    def generate(self, request):
        self.last_request = request
        return AIProviderResponse(
            text=(
                "## Resumen ejecutivo\n"
                "Proyecto con riesgo medio.\n\n"
                "## Quick wins\n"
                "- Rotar credenciales expuestas\n"
            )
        )


class AICliTests(unittest.TestCase):
    def _build_scan_payload(self) -> dict:
        return {
            "tool": {"name": "ai-dev-guardian", "version": "0.2.1"},
            "schema_version": "1.0",
            "project_summary": {"path": "sample", "score": "WARN"},
            "security_summary": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 1, "LOW": 0},
            "ci_status": {"fail_on": "NONE", "max_severity": "HIGH", "expected_exit_code": 0},
            "warnings": [],
            "security_findings": [
                {
                    "id": "SEC-017",
                    "severity": "MEDIUM",
                    "confidence": "MEDIUM",
                    "file": "db/scripts/setup.sql",
                    "line": None,
                    "evidence": "db/scripts/setup.sql",
                    "recommendation": "Revisar contenido",
                },
                {
                    "id": "SEC-003",
                    "severity": "CRITICAL",
                    "confidence": "HIGH",
                    "file": "secrets.py",
                    "line": 10,
                    "evidence": "ghp_****1a2b",
                    "recommendation": "Rotar token",
                },
            ],
        }

    def test_ai_missing_scan_argument(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "ai.md"
            result = subprocess.run(
                [sys.executable, "-m", "guardian", "ai", "--out", str(out)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("--scan", result.stderr)

    def test_ai_scan_json_not_exists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing.json"
            out = Path(tmp) / "ai.md"
            result = subprocess.run(
                [sys.executable, "-m", "guardian", "ai", "--scan", str(missing), "--out", str(out)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("No existe el archivo scan.json", result.stderr)

    def test_ai_generates_markdown_with_mock_provider(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            scan_path = tmp_path / "scan.json"
            out_path = tmp_path / "ai.md"
            scan_path.write_text(json.dumps(self._build_scan_payload()), encoding="utf-8")

            provider = _CapturingProvider()
            with patch("guardian.cli._select_provider", return_value=provider):
                exit_code = run_ai(scan=scan_path, out=out_path, provider="ollama", model="llama3.1:8b", max_findings=25)

            self.assertEqual(exit_code, 0)
            self.assertTrue(out_path.exists())

            content = out_path.read_text(encoding="utf-8")
            self.assertIn("# AI Analysis Report", content)
            self.assertIn("Provider: `ollama`", content)
            self.assertIn("--fail-on HIGH", content)

            ai_json = out_path.with_suffix(".json")
            self.assertTrue(ai_json.exists())
            payload = json.loads(ai_json.read_text(encoding="utf-8"))
            self.assertEqual(payload["provider"], "ollama")
            self.assertEqual(payload["model"], "llama3.1:8b")

    def test_prompt_includes_required_quality_instructions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            scan_path = tmp_path / "scan.json"
            out_path = tmp_path / "ai.md"
            scan_path.write_text(json.dumps(self._build_scan_payload()), encoding="utf-8")

            provider = _CapturingProvider()
            with patch("guardian.cli._select_provider", return_value=provider):
                run_ai(scan=scan_path, out=out_path, provider="ollama", model="llama3.1:8b", max_findings=25)

            self.assertIsNotNone(provider.last_request)
            prompt = provider.last_request.prompt
            self.assertIn("Usa 'hallazgos' o 'riesgos' por defecto", prompt)
            self.assertIn("SEC-017", prompt)
            self.assertIn("APEX/QA", prompt)
            self.assertIn("password=, token, api_key, bearer, AKIA, ghp_, BEGIN PRIVATE KEY", prompt)
            self.assertIn("Aunque no haya hallazgos CI", prompt)
            self.assertIn("Quick wins (max 5, concretos y no repetidos)", prompt)


if __name__ == "__main__":
    unittest.main()

