from __future__ import annotations

import re


def _mask_prefix(pattern: str, prefix: str, text: str) -> str:
    regex = re.compile(pattern)

    def repl(match: re.Match[str]) -> str:
        value = match.group(0)
        tail = value[-4:] if len(value) >= 4 else "****"
        return f"{prefix}****{tail}"

    return regex.sub(repl, text)


def sanitize_text(text: str) -> str:
    clean = text or ""
    clean = _mask_prefix(r"AKIA[0-9A-Z]{16}", "AKIA", clean)
    clean = _mask_prefix(r"ghp_[A-Za-z0-9]{8,}", "ghp_", clean)
    clean = _mask_prefix(r"github_pat_[A-Za-z0-9_]{8,}", "github_pat_", clean)

    # Force redaction for private key marker context.
    clean = re.sub(r"BEGIN\s+PRIVATE\s+KEY[\s\S]{0,300}", "BEGIN PRIVATE KEY", clean)
    return clean
