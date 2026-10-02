"""Copies the target repository into the run directory, and restores files after an attempt."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from bop.errors import BopError, ConfigError, SandboxError

_ALWAYS = shutil.ignore_patterns(".git", ".idea", ".vscode", "node_modules", "*.class", ".bop")
_BUILD_OUTPUT = {"target", "build"}


def _ignore(directory: str, names: list[str]) -> set[str]:
    """Skip VCS and IDE folders everywhere, build output only next to a pom.xml, and every symlink.

    Symlinks are never followed: a link in an untrusted repository could otherwise copy host
    files (or the agent's own configuration) into the snapshot.
    """
    ignored = set(_ALWAYS(directory, names))
    if "pom.xml" in names:
        ignored |= _BUILD_OUTPUT & set(names)
    ignored |= {n for n in names if os.path.islink(os.path.join(directory, n))}
    return ignored


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
    check_maven_project(source)
    try:
        shutil.copytree(source, dest, ignore=_ignore, symlinks=True)
    except (shutil.Error, OSError) as exc:
        raise BopError(f"could not snapshot {source}: {exc}") from exc
    return git_commit(source)


def check_maven_project(source: Path) -> None:
    if not source.is_dir():
        raise ConfigError(f"{source} is not a directory")
    if not (source / "pom.xml").is_file():
        raise ConfigError(f"{source} has no pom.xml; only Maven projects are supported")


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
        """Put every remembered file back, without following links planted since.

        Builds of the target's code run between ``remember`` and ``restore`` with the snapshot
        writable. A file swapped for a symlink is replaced by a regular file again. A parent directory
        that now leads outside the snapshot stops the run, because writing there would write to the host.
        """
        root = os.path.realpath(self.root)
        for path, original in self._saved.items():
            parent = os.path.realpath(path.parent)
            if parent != os.path.abspath(path.parent) or not (parent == root or parent.startswith(root + os.sep)):
                raise SandboxError(f"{path.parent} was replaced by a link during a build; refusing to restore it")
            if path.is_symlink() or original is None:
                path.unlink(missing_ok=True)
            if original is not None:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
                with os.fdopen(fd, "wb") as handle:
                    handle.write(original)
        self._saved.clear()

    def forget(self) -> None:
        self._saved.clear()
