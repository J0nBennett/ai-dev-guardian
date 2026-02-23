from __future__ import annotations

import re

TOKEN_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"ghp_[A-Za-z0-9]{8,}"), "ghp_"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{8,}"), "github_pat_"),
    (re.compile(r"xoxb-[0-9A-Za-z-]{8,}"), "xoxb-"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AKIA"),
    (re.compile(r"AIza[0-9A-Za-z_-]{20,}"), "AIza"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "eyJ"),
]


def _mask_value(value: str, prefix: str) -> str:
    raw = value.strip()
    if len(raw) <= len(prefix) + 4:
        return f"{prefix}****"
    return f"{prefix}****{raw[-4:]}"


def mask_evidence(text: str) -> str:
    value = (text or "").strip()
    if not value:
        return value

    if "BEGIN PRIVATE KEY" in value:
        return "BEGIN PRIVATE KEY"

    masked = value
    for pattern, prefix in TOKEN_PATTERNS:
        masked = pattern.sub(lambda m: _mask_value(m.group(0), prefix), masked)

    return masked
