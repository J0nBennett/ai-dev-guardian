from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

DEFAULT_IGNORES = {".git", "node_modules", "dist", "build", ".venv", "__pycache__", "reports"}


@dataclass(frozen=True)
class FileInfo:
    path: Path
    relative_path: Path
    size_bytes: int


def should_skip_dir(name: str) -> bool:
    return name in DEFAULT_IGNORES


def is_probably_binary(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            chunk = handle.read(4096)
    except OSError:
        return True
    return b"\x00" in chunk


def iter_project_files(root: Path, max_file_size_mb: int = 5) -> Iterator[FileInfo]:
    max_size = max_file_size_mb * 1024 * 1024
    root = root.resolve()

    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        kept_dirs: list[str] = []
        for dirname in dirnames:
            if should_skip_dir(dirname):
                continue
            full_dir = Path(dirpath) / dirname
            try:
                if full_dir.is_symlink():
                    continue
            except OSError:
                continue
            kept_dirs.append(dirname)
        dirnames[:] = kept_dirs

        for filename in filenames:
            full_path = Path(dirpath) / filename
            try:
                if full_path.is_symlink():
                    continue
                stat = full_path.stat()
            except OSError:
                continue

            if stat.st_size > max_size:
                continue
            if is_probably_binary(full_path):
                continue

            try:
                rel = full_path.relative_to(root)
            except ValueError:
                continue

            yield FileInfo(path=full_path, relative_path=rel, size_bytes=stat.st_size)


def safe_read_text(path: Path) -> str:
    for encoding in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return path.read_text(encoding=encoding, errors="strict")
        except UnicodeDecodeError:
            continue
        except OSError:
            return ""
    return ""


def count_lines(text: str) -> int:
    if not text:
        return 0
    return text.count("\n") + 1

