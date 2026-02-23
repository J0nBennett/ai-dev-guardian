from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from guardian.cli import evaluate_exit_code
from guardian.scan.semgrep_integration import run_semgrep_scan


class ScanSmokeTest(unittest.TestCase):
    def _run_scan(
        self,
        repo: Path,
        out_dir: Path,
        extra_args: list[str] | None = None,
        expected_code: int = 0,
        env: dict[str, str] | None = None,
    ) -> tuple[dict, subprocess.CompletedProcess[str]]:
        command = [
            sys.executable,
            "-m",
            "guardian",
            "scan",
            "--path",
            str(repo),
            "--out",
            str(out_dir),
        ]
        if extra_args:
            command.extend(extra_args)

        result = subprocess.run(command, capture_output=True, text=True, env=env)
        self.assertEqual(result.returncode, expected_code, result.stderr)

        json_path = out_dir / "scan.json"
        md_path = out_dir / "scan.md"
        self.assertTrue(json_path.exists())
        self.assertTrue(md_path.exists())
        payload = json.loads(json_path.read_text(encoding="utf-8"))
        return payload, result

    def test_scan_smoke(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            sample_repo = tmp_path / "sample_repo"
            out_dir = tmp_path / "reports"
            sample_repo.mkdir()
            (sample_repo / "app.py").write_text("print('ok')\n", encoding="utf-8")

            payload, _ = self._run_scan(sample_repo, out_dir)
            self.assertIn("tool", payload)
            self.assertEqual(payload["schema_version"], "1.0")
            self.assertIn("project_summary", payload)
            self.assertIn("metrics", payload)
            self.assertIn("security_findings", payload)

    def test_evidence_masking(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            sample_repo = tmp_path / "sample_repo"
            out_dir = tmp_path / "reports"
            sample_repo.mkdir()

            token_value = "ghp_1234567890abcdefghij"
            (sample_repo / "secrets.py").write_text(
                f"TOKEN = '{token_value}'\nPRIVATE='BEGIN PRIVATE KEY'\n",
                encoding="utf-8",
            )

            payload, _ = self._run_scan(sample_repo, out_dir)
            findings = payload.get("security_findings", [])
            by_id = {item["id"]: item for item in findings}

            self.assertIn("SEC-003", by_id)
            self.assertIn("SEC-001", by_id)

            token_evidence = by_id["SEC-003"]["evidence"]
            self.assertTrue(token_evidence.startswith("ghp_****"))
            self.assertTrue(token_evidence.endswith("ghij"))
            self.assertNotIn(token_value, token_evidence)

            key_evidence = by_id["SEC-001"]["evidence"]
            self.assertEqual(key_evidence, "BEGIN PRIVATE KEY")

    def test_fail_on_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            sample_repo = tmp_path / "sample_repo"
            out_dir = tmp_path / "reports"
            sample_repo.mkdir()
            (sample_repo / "keys.txt").write_text("AKIA1234567890ABCDEF\n", encoding="utf-8")

            payload, result = self._run_scan(
                sample_repo,
                out_dir,
                extra_args=["--fail-on", "HIGH"],
                expected_code=2,
            )
            self.assertEqual(result.returncode, 2)
            self.assertEqual(payload["ci_status"]["expected_exit_code"], 2)

    def test_fail_on_none_never_fails(self) -> None:
        simulated = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        self.assertEqual(evaluate_exit_code(simulated, "NONE"), 0)

    def test_semgrep_missing_does_not_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            sample_repo = tmp_path / "sample_repo"
            out_dir = tmp_path / "reports"
            sample_repo.mkdir()
            (sample_repo / "app.py").write_text("print('ok')\n", encoding="utf-8")

            env = dict(os.environ)
            env["PATH"] = ""
            payload, result = self._run_scan(
                sample_repo,
                out_dir,
                extra_args=["--with-semgrep"],
                expected_code=0,
                env=env,
            )
            self.assertEqual(result.returncode, 0)
            self.assertIn("warnings", payload)
            self.assertTrue(any("Semgrep no esta instalado" in warning for warning in payload["warnings"]))
            self.assertIn("integrations", payload)
            self.assertIn("semgrep", payload["integrations"])
            self.assertFalse(payload["integrations"]["semgrep"]["available"])

    @patch("guardian.scan.semgrep_integration.subprocess.run")
    @patch("guardian.scan.semgrep_integration.shutil.which")
    def test_semgrep_source_rule_id_and_mapping(self, mock_which, mock_run) -> None:
        mock_which.return_value = "semgrep"
        payload = {
            "results": [
                {
                    "check_id": "security.hardcoded-token",
                    "path": "sample.py",
                    "start": {"line": 10},
                    "extra": {
                        "severity": "ERROR",
                        "message": "Hardcoded token",
                        "lines": "token = 'ghp_1234567890abcdefghij'",
                    },
                },
                {
                    "check_id": "style.print-debug",
                    "path": "sample.py",
                    "start": {"line": 20},
                    "extra": {
                        "severity": "WARNING",
                        "message": "Debug print",
                    },
                },
                {
                    "check_id": "misc.unknown",
                    "path": "sample.py",
                    "start": {"line": 30},
                    "extra": {
                        "message": "No severity provided",
                    },
                },
            ]
        }
        mock_run.return_value = subprocess.CompletedProcess(
            args=["semgrep"],
            returncode=0,
            stdout=json.dumps(payload),
            stderr="",
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            findings, warnings, info = run_semgrep_scan(root)

        self.assertFalse(warnings)
        self.assertTrue(info["available"])
        self.assertEqual(info["findings_count"], 3)

        by_source = {f.source_rule_id: f for f in findings}

        sec = by_source["security.hardcoded-token"]
        self.assertEqual(sec.rule_id, "SG-security.hardcoded-token")
        self.assertEqual(sec.severity, "CRITICAL")
        self.assertEqual(sec.source_rule_id, "security.hardcoded-token")
        self.assertIn("ghp_****", sec.evidence)

        warn = by_source["style.print-debug"]
        self.assertEqual(warn.severity, "MEDIUM")

        missing = by_source["misc.unknown"]
        self.assertEqual(missing.severity, "MEDIUM")


if __name__ == "__main__":
    unittest.main()
