from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Iterable

IGNORED_DIRS = {
    ".git", ".hg", ".svn", ".idea", ".vscode",
    ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache",
    "node_modules", ".dart_tool", "build", "dist", "target",
    ".next", ".nuxt", ".gradle", "Pods",
}
MAX_ENTRIES = 20_000


def infer_project_types(root: Path) -> list[str]:
    names = {p.name for p in root.iterdir()} if root.is_dir() else set()
    types: list[str] = []

    if {"pyproject.toml", "requirements.txt", "setup.py", "Pipfile"} & names:
        types.append("Python")
    if "pubspec.yaml" in names:
        # Flutter projects normally contain lib/ and one or more platform dirs.
        if (root / "lib").is_dir() and any((root / x).exists() for x in ("android", "ios", "web", "windows", "macos", "linux")):
            types.append("Flutter")
        else:
            types.append("Dart")
    if "package.json" in names:
        types.append("Node/JavaScript/TypeScript")
    if "Cargo.toml" in names:
        types.append("Rust")
    if "go.mod" in names:
        types.append("Go")
    if {"pom.xml", "build.gradle", "build.gradle.kts"} & names:
        types.append("Java/Kotlin")
    if any(n.endswith(".sln") or n.endswith(".csproj") for n in names):
        types.append(".NET")
    if "composer.json" in names:
        types.append("PHP")
    if "Gemfile" in names:
        types.append("Ruby")

    return types or ["Unknown/Mixed"]


def _safe_relative(path: Path, root: Path) -> str:
    rel = path.relative_to(root).as_posix()
    # JSON escaping later makes control characters inert, but drop NUL outright.
    return rel.replace("\x00", "\uFFFD")


def build_manifest(root: Path, max_entries: int = MAX_ENTRIES) -> dict:
    root = root.expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Selected path is not a directory.")

    entries: list[dict] = []
    truncated = False

    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)

        # Never recurse into ignored dirs or symlinked dirs.
        kept_dirs = []
        for d in sorted(dirs):
            p = current_path / d
            if d in IGNORED_DIRS:
                continue
            if p.is_symlink():
                if len(entries) >= max_entries:
                    truncated = True
                    break
                entries.append({
                    "path": _safe_relative(p, root),
                    "kind": "symlink",
                    "extension": "",
                    "size": None,
                })
                continue
            kept_dirs.append(d)
        dirs[:] = kept_dirs

        for d in dirs:
            p = current_path / d
            if len(entries) >= max_entries:
                truncated = True
                break
            entries.append({
                "path": _safe_relative(p, root),
                "kind": "directory",
                "extension": "",
                "size": None,
            })
        if truncated:
            break

        for name in sorted(files):
            p = current_path / name
            if len(entries) >= max_entries:
                truncated = True
                break
            try:
                if p.is_symlink():
                    kind, size = "symlink", None
                else:
                    kind, size = "file", p.stat().st_size
            except OSError:
                kind, size = "unreadable", None

            entries.append({
                "path": _safe_relative(p, root),
                "kind": kind,
                "extension": p.suffix.lower()[:32],
                "size": size,
            })
        if truncated:
            break

    return {
        "root_name": root.name,  # basename only; absolute local path is never sent.
        "project_types": infer_project_types(root),
        "entry_count": len(entries),
        "truncated": truncated,
        "entries": entries,
    }


def manifest_as_json(manifest: dict) -> str:
    return json.dumps(manifest, indent=2, ensure_ascii=True)
