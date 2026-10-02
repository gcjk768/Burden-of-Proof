"""Copies the target repository into the run directory, and restores files after an attempt."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

IGNORED = shutil.ignore_patterns(".git", "target", "build", ".idea", ".vscode", "node_modules", "*.class", ".bop")


def git_commit(repo: Path) -> str | None:
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return out.stdout.strip() if out.returncode == 0 else None


def snapshot(source: Path, dest: Path) -> str | None:
    """Copy ``source`` to ``dest`` (which must not exist). Returns the git commit if there is one."""
    if not (source / "pom.xml").is_file():
        raise FileNotFoundError(f"{source} has no pom.xml; only Maven projects are supported")
    shutil.copytree(source, dest, ignore=IGNORED, symlinks=False)
    return git_commit(source)


def remove_file_and_empty_parents(path: Path, stop: Path) -> None:
    """Delete ``path`` and any parent directories it leaves empty, up to (not including) ``stop``."""
    path.unlink(missing_ok=True)
    parent = path.parent
    stop = stop.resolve()
    while parent.resolve() != stop and stop in parent.resolve().parents:
        try:
            parent.rmdir()
        except OSError:
            break
        parent = parent.parent


class FileCheckpoint:
    """Remembers the original bytes of files so an attempt can be rolled back exactly."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self._saved: dict[Path, bytes | None] = {}

    def remember(self, path: Path) -> None:
        if path not in self._saved:
            self._saved[path] = path.read_bytes() if path.exists() else None

    def restore(self) -> None:
        for path, original in self._saved.items():
            if original is None:
                path.unlink(missing_ok=True)
            else:
                path.write_bytes(original)
        self._saved.clear()

    def forget(self) -> None:
        self._saved.clear()
