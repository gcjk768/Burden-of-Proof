"""Path confinement: nothing a model names may resolve outside the checkout."""

from __future__ import annotations

from pathlib import Path


class PathEscape(ValueError):
    pass


def confined(root: Path, relative: str) -> Path:
    if not relative or "\x00" in relative:
        raise PathEscape("empty or invalid path")
    candidate = Path(relative)
    if candidate.is_absolute():
        raise PathEscape(f"absolute paths are not allowed: {relative}")
    root = root.resolve()
    resolved = (root / candidate).resolve()
    if resolved != root and root not in resolved.parents:
        raise PathEscape(f"path leaves the repository: {relative}")
    return resolved


def relative(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()
