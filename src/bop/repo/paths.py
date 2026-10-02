"""Path confinement: nothing a model names may resolve outside the checkout."""

from __future__ import annotations

import os
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


def _components(root: Path, path: Path) -> list[Path]:
    """Each path from just below ``root`` down to ``path``, without following any link."""
    target = Path(os.path.abspath(path))
    for base in (Path(os.path.abspath(root)), Path(os.path.realpath(root))):
        try:
            rel = target.relative_to(base)
        except ValueError:
            continue
        out, current = [], base
        for part in rel.parts:
            current = current / part
            out.append(current)
        return out
    raise PathEscape(f"{path} is not inside {root}")


def has_link(root: Path, path: Path) -> bool:
    """Whether any component between ``root`` and ``path`` (inclusive) is a symbolic link."""
    return any(c.is_symlink() for c in _components(root, path))


def defuse_links(root: Path, path: Path) -> None:
    """Remove the first symbolic link on the way from ``root`` down to ``path``.

    Builds of the target's code run with the snapshot writable and can swap any file or directory
    for a link to a host path. Host-side code calls this before it deletes or reads what a build left
    behind, so the operation stays inside the snapshot. Only the link itself is removed. No build runs
    at the same time (the jail kills every process it started when its command exits), so nothing can
    swap the link back between this check and the caller's operation.
    """
    for component in _components(root, path):
        if component.is_symlink():
            component.unlink()
            return
        if not component.exists():
            return
