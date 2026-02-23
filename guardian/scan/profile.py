from __future__ import annotations

import json
from pathlib import Path


def _safe_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _has_any(root: Path, names: list[str]) -> list[str]:
    found: list[str] = []
    for name in names:
        p = root / name
        if p.exists():
            found.append(name)
    return found


def detect_project_profile(root: Path) -> dict[str, object]:
    root = root.resolve()
    signals: list[str] = []

    package_json = root / "package.json"
    pyproject = root / "pyproject.toml"
    requirements = root / "requirements.txt"
    pubspec = root / "pubspec.yaml"

    profile_name = "generic"

    agent_files = [
        "CLAUDE.md",
        "AGENTS.md",
        ".cursorrules",
        ".windsurfrules",
        ".github/copilot-instructions.md",
        ".github/copilot-instructions.yml",
        "COPILOT_INSTRUCTIONS.md",
    ]
    signals.extend(_has_any(root, agent_files))

    pkg = _safe_json(package_json) if package_json.exists() else {}
    deps = set()
    if pkg:
        signals.append("package.json")
        for block in ("dependencies", "devDependencies", "peerDependencies"):
            deps.update((pkg.get(block) or {}).keys())

    if pyproject.exists():
        signals.append("pyproject.toml")
    if requirements.exists():
        signals.append("requirements.txt")

    if pubspec.exists() or (root / "android").exists() or (root / "ios").exists():
        profile_name = "mobile"
        if pubspec.exists():
            signals.append("pubspec.yaml")
        if (root / "android").exists():
            signals.append("android/")
        if (root / "ios").exists():
            signals.append("ios/")

    tf_files = list(root.rglob("*.tf"))
    k8s_files = list(root.rglob("*k8s*.yml")) + list(root.rglob("*k8s*.yaml"))
    docker_files = list(root.rglob("Dockerfile"))
    if profile_name == "generic" and (tf_files or k8s_files or len(docker_files) >= 2 or (root / "docker-compose.yml").exists()):
        profile_name = "infra"
        if tf_files:
            signals.append("terraform")
        if k8s_files:
            signals.append("k8s manifests")
        if docker_files:
            signals.append("Dockerfile")
        if (root / "docker-compose.yml").exists():
            signals.append("docker-compose.yml")

    web_frameworks = {"vite", "next", "astro", "react", "vue", "svelte"}
    backend_node = {"express", "@nestjs/core", "koa", "fastify"}
    backend_python_markers = ["fastapi", "flask", "django"]

    py_text = ""
    if pyproject.exists():
        py_text += pyproject.read_text(encoding="utf-8", errors="ignore").lower()
    if requirements.exists():
        py_text += "\n" + requirements.read_text(encoding="utf-8", errors="ignore").lower()

    if profile_name == "generic" and deps.intersection(web_frameworks):
        profile_name = "web"
        signals.append("web framework")

    if profile_name == "generic":
        if deps.intersection(backend_node) or any(marker in py_text for marker in backend_python_markers):
            profile_name = "backend"
            signals.append("backend framework")

    src_exists = (root / "src").exists()
    docs_exists = (root / "docs").exists()
    entrypoints = ["main.py", "app.py", "server.py", "index.js", "main.ts", "manage.py"]
    has_entrypoint = any((root / ep).exists() for ep in entrypoints)
    if profile_name == "generic" and src_exists and docs_exists and not has_entrypoint:
        profile_name = "library"
        signals.extend(["src/", "docs/"])

    unique_signals = []
    seen = set()
    for sig in signals:
        if sig not in seen:
            seen.add(sig)
            unique_signals.append(sig)

    return {
        "name": profile_name,
        "signals": unique_signals,
    }
