from __future__ import annotations

import argparse
from pathlib import Path

from . import __version__
from .scan.metrics import collect_metrics
from .scan.reporter import write_reports
from .scan.rules import severity_gte
from .scan.rules_engine import run_security_scan

FAIL_ON_CHOICES = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="guardian",
        description="Local-first repository scanner for quality and security risks.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a repository path")
    scan_parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    scan_parser.add_argument("--path", required=True, help="Target repository directory")
    scan_parser.add_argument("--out", required=True, help="Output directory for reports")
    scan_parser.add_argument(
        "--fail-on",
        default="NONE",
        choices=FAIL_ON_CHOICES,
        type=str.upper,
        help="Fail with exit code 2 if any finding severity is >= threshold.",
    )
    scan_parser.add_argument(
        "--with-semgrep",
        action="store_true",
        help="Enable optional local semgrep integration if available.",
    )

    return parser


def evaluate_exit_code(findings_severities: list[str], fail_on: str) -> int:
    threshold = (fail_on or "NONE").upper()
    if threshold == "NONE":
        return 0
    for severity in findings_severities:
        if severity_gte(severity, threshold):
            return 2
    return 0


def run_scan(path: Path, out: Path, fail_on: str = "NONE", with_semgrep: bool = False) -> int:
    project_path = path.resolve()
    out_dir = out.resolve()

    metrics = collect_metrics(project_path)
    result = run_security_scan(project_path, metrics=metrics, with_semgrep=with_semgrep)

    exit_code = evaluate_exit_code([finding.severity for finding in result.findings], fail_on)
    write_reports(
        path=project_path,
        out_dir=out_dir,
        metrics=metrics,
        scan_result=result,
        fail_on=fail_on,
        expected_exit_code=exit_code,
    )
    return exit_code


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "scan":
            return run_scan(
                Path(args.path),
                Path(args.out),
                fail_on=args.fail_on,
                with_semgrep=args.with_semgrep,
            )
    except Exception:
        return 1

    parser.error("Unknown command")
    return 2
