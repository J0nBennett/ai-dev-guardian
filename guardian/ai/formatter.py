from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path


def _extract_list_items(text: str, limit: int = 8) -> list[str]:
    items: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("- "):
            items.append(stripped[2:].strip())
        elif stripped[:2].isdigit() and stripped[2:4] == ". ":
            items.append(stripped[4:].strip())
        if len(items) >= limit:
            break
    return items


def render_ai_markdown(model: str, provider: str, analysis_text: str) -> str:
    lines: list[str] = []
    lines.append("# AI Analysis Report")
    lines.append("")
    lines.append(f"- Provider: `{provider}`")
    lines.append(f"- Model: `{model}`")
    lines.append("")
    lines.append("> Nota: Los hallazgos MEDIUM pueden ser contextuales; use `--fail-on HIGH` en CI para reducir ruido.")
    lines.append("")
    lines.append(analysis_text.strip())
    lines.append("")
    return "\n".join(lines)


def build_ai_json_payload(provider: str, model: str, analysis_text: str) -> dict:
    return {
        "provider": provider,
        "model": model,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": analysis_text[:1200],
        "recommendations": _extract_list_items(analysis_text, limit=10),
    }


def write_ai_outputs(out_path: Path, markdown: str, json_payload: dict) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(markdown, encoding="utf-8")

    json_path = out_path.with_suffix(".json")
    json_path.write_text(__import__("json").dumps(json_payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
