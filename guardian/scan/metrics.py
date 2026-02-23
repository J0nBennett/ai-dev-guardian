from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from .filesystem import count_lines, iter_project_files, safe_read_text


@dataclass(frozen=True)
class Metrics:
    total_files: int
    files_by_extension: dict[str, int]
    estimated_loc: int
    test_directories: list[str]
    ci_detected: list[str]
    missing_lockfiles: list[str]
    unpinned_dependency_files: list[str]


def _detect_test_dirs(root: Path) -> list[str]:
    matches: list[str] = []
    names = {"test", "tests", "spec", "specs", "__tests__"}

    for path in root.rglob("*"):
        if not path.is_dir():
            continue
        name = path.name.lower()
        if name in names or name.endswith("_test"):
            try:
                matches.append(str(path.relative_to(root)).replace("\\", "/"))
            except ValueError:
                continue

    return sorted(set(matches))


def _detect_ci(root: Path) -> list[str]:
    found: list[str] = []

    workflows = root / ".github" / "workflows"
    if workflows.exists() and workflows.is_dir():
        for file_path in workflows.glob("*"):
            if file_path.is_file():
                found.append(str(file_path.relative_to(root)).replace("\\", "/"))

    gitlab = root / ".gitlab-ci.yml"
    if gitlab.exists() and gitlab.is_file():
        found.append(str(gitlab.relative_to(root)).replace("\\", "/"))

    return sorted(set(found))


def _detect_dependency_risks(root: Path) -> tuple[list[str], list[str]]:
    manifest_to_lock = {
        "package.json": ["package-lock.json", "pnpm-lock.yaml", "yarn.lock"],
        "pyproject.toml": ["poetry.lock", "pdm.lock", "uv.lock", "requirements.txt"],
        "Pipfile": ["Pipfile.lock"],
        "Cargo.toml": ["Cargo.lock"],
        "go.mod": ["go.sum"],
    }

    missing_lockfiles: list[str] = []
    unpinned: list[str] = []

    for manifest, lockfiles in manifest_to_lock.items():
        manifest_path = root / manifest
        if not manifest_path.exists():
            continue

        if not any((root / lockfile).exists() for lockfile in lockfiles):
            missing_lockfiles.append(manifest)

        content = safe_read_text(manifest_path)
        for line in content.splitlines():
            raw = line.strip().strip(",")
            if not raw:
                continue
            low = raw.lower()
            if "latest" in low:
                unpinned.append(manifest)
                break
            if ": \"*\"" in raw or "='*'" in raw or '="*"' in raw:
                unpinned.append(manifest)
                break

    requirements = root / "requirements.txt"
    if requirements.exists() and requirements.is_file():
        for line in safe_read_text(requirements).splitlines():
            item = line.strip()
            if not item or item.startswith("#"):
                continue
            if "==" not in item and " @ " not in item:
                unpinned.append("requirements.txt")
                break

    return sorted(set(missing_lockfiles)), sorted(set(unpinned))


def collect_metrics(root: Path) -> Metrics:
    root = root.resolve()
    ext_counter: Counter[str] = Counter()
    total = 0
    loc = 0

    for info in iter_project_files(root):
        total += 1
        ext = info.path.suffix.lower() or "<noext>"
        ext_counter[ext] += 1
        loc += count_lines(safe_read_text(info.path))

    test_dirs = _detect_test_dirs(root)
    ci_detected = _detect_ci(root)
    missing_lockfiles, unpinned = _detect_dependency_risks(root)

    return Metrics(
        total_files=total,
        files_by_extension=dict(sorted(ext_counter.items(), key=lambda item: item[0])),
        estimated_loc=loc,
        test_directories=test_dirs,
        ci_detected=ci_detected,
        missing_lockfiles=missing_lockfiles,
        unpinned_dependency_files=unpinned,
    )
