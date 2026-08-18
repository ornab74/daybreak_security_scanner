from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

SOURCE_EXTENSIONS = {
    ".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".go", ".rs", ".java", ".kt", ".kts", ".cs", ".php", ".rb",
    ".dart", ".swift", ".c", ".h", ".cc", ".cpp", ".hpp",
    ".sh", ".bash", ".zsh", ".ps1", ".sql", ".graphql",
    ".yaml", ".yml", ".toml", ".json", ".xml",
}

MAX_SOURCE_BYTES = 256_000
MAX_SOURCE_LINES = 2_500
MAX_PATCH_CHANGED_LINES = 120
MAX_DEEP_FILES = 24
MAX_FINDINGS_PER_FILE = 6


@dataclass(frozen=True)
class SourceSnapshot:
    relative_path: str
    text: str
    line_count: int


def is_reviewable_source(entry: dict) -> bool:
    return entry.get("kind") == "file" and entry.get("extension", "").lower() in SOURCE_EXTENSIONS


def source_review_priority(entry: dict) -> tuple[int, str]:
    """Put production implementation ahead of tests, metadata, and workflows."""
    path = entry.get("path", "").replace("\\", "/").lower()
    name = path.rsplit("/", 1)[-1]
    if path.startswith(".github/") or "/.github/" in path:
        rank = 5
    elif any(part in path.split("/") for part in ("test", "tests", "fixtures", "examples", "docs")) or name.startswith("test_"):
        rank = 4
    elif entry.get("extension") in {".yaml", ".yml", ".json", ".toml", ".xml"}:
        rank = 3
    elif name in {"setup.py", "conftest.py"}:
        rank = 2
    else:
        rank = 0
    return rank, path


def _inside_root(root: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def load_source_snapshot(root: Path, relative_path: str) -> SourceSnapshot:
    root = root.expanduser().resolve(strict=True)
    candidate = (root / relative_path).resolve(strict=True)
    if not _inside_root(root, candidate):
        raise ValueError("Refusing source path outside selected project root.")
    if candidate.is_symlink() or not candidate.is_file():
        raise ValueError("Refusing symlink or non-file source target.")
    if candidate.suffix.lower() not in SOURCE_EXTENSIONS:
        raise ValueError("File extension is not in the source-review allowlist.")
    size = candidate.stat().st_size
    if size > MAX_SOURCE_BYTES:
        raise ValueError(f"Source file exceeds {MAX_SOURCE_BYTES} byte deep-review limit.")

    raw = candidate.read_bytes()
    if b"\x00" in raw:
        raise ValueError("Binary/NUL-containing file is not eligible for source review.")
    text = raw.decode("utf-8", errors="strict")
    lines = text.splitlines()
    if len(lines) > MAX_SOURCE_LINES:
        raise ValueError(f"Source file exceeds {MAX_SOURCE_LINES} line deep-review limit.")
    return SourceSnapshot(relative_path=relative_path, text=text, line_count=max(1, len(lines)))


def number_source(text: str) -> str:
    lines = text.splitlines()
    if not lines:
        return "000001 | "
    return "\n".join(f"{i:06d} | {line}" for i, line in enumerate(lines, 1))


def validate_finding_spans(findings: list, line_count: int) -> list:
    valid = []
    for finding in findings:
        start = int(finding.line_start)
        end = int(finding.line_end)
        if not (1 <= start <= end <= line_count):
            continue
        threshold = {"medium": 0.72, "high": 0.85, "critical": 0.93}[finding.severity]
        if finding.confidence < threshold:
            continue
        valid.append(finding)
    return valid


def changed_line_count(diff: str) -> int:
    count = 0
    for line in diff.splitlines():
        if line.startswith(("+++", "---")):
            continue
        if line.startswith(("+", "-")):
            count += 1
    return count


def validate_unified_diff(diff: str, target_path: str) -> tuple[bool, str]:
    if not diff.strip():
        return False, "Patch agent returned no diff."
    if "GIT binary patch" in diff or "Binary files " in diff:
        return False, "Binary patches are forbidden."
    if "\x00" in diff:
        return False, "NUL byte in patch."
    if changed_line_count(diff) > MAX_PATCH_CHANGED_LINES:
        return False, f"Patch exceeds {MAX_PATCH_CHANGED_LINES} changed-line limit."

    old_headers = [line[4:].strip() for line in diff.splitlines() if line.startswith("--- ")]
    new_headers = [line[4:].strip() for line in diff.splitlines() if line.startswith("+++ ")]
    if len(old_headers) != 1 or len(new_headers) != 1:
        return False, "Patch must contain exactly one old/new file header."

    def norm(header: str) -> str:
        header = header.split("\t", 1)[0]
        if header.startswith("a/") or header.startswith("b/"):
            header = header[2:]
        return header.replace("\\", "/")

    old, new = norm(old_headers[0]), norm(new_headers[0])
    if old == "/dev/null" or new == "/dev/null":
        return False, "File creation/deletion is forbidden."
    target = target_path.replace("\\", "/")
    if old != target or new != target:
        return False, f"Patch target mismatch: expected {target!r}."
    if old.startswith("/") or new.startswith("/") or "../" in old or "../" in new:
        return False, "Unsafe patch path."
    if not any(line.startswith("@@ ") for line in diff.splitlines()):
        return False, "Patch contains no hunks."
    return True, "ok"
