"""Builds a minimal filesystem view inside fresh namespaces, then runs the command in it.

``LocalNamespaceRunner`` starts this module as the namespace's root user, in new user, PID, mount
and (optionally) network namespaces::

    unshare --user --map-root-user --pid --fork --kill-child --mount [--net] \
        python -m bop.runner.jail '<json spec>'

The spec lists host paths to expose read-only (the toolchain) and read-write (the snapshot, the
Maven repository, the scan output). Everything else, including the user's home directory, the
project's ``.env``, the run database and other runs, is simply absent. ``/tmp`` and ``$HOME`` are
empty tmpfs mounts. With the network namespace, only the loopback interface exists and it is
brought up so tests that talk to localhost still work.
"""

from __future__ import annotations

import ctypes
import fcntl
import json
import os
import socket
import struct
import sys
from pathlib import Path

MS_RDONLY = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
MS_REMOUNT = 32
MS_BIND = 4096
MS_REC = 16384
MS_PRIVATE = 1 << 18

_libc = ctypes.CDLL(None, use_errno=True)


def _mount(source: str | None, target: str, fstype: str | None, flags: int, data: str | None = None) -> None:
    rc = _libc.mount(
        source.encode() if source else None,
        target.encode(),
        fstype.encode() if fstype else None,
        ctypes.c_ulong(flags),
        data.encode() if data else None,
    )
    if rc != 0:
        err = ctypes.get_errno()
        raise OSError(err, f"mount {source or fstype} on {target}: {os.strerror(err)}")


def _locked_flags(path: str) -> int:
    """Flags a remount inside a user namespace must keep, or the kernel refuses it."""
    st = os.statvfs(path)
    flags = 0
    for st_flag, ms_flag in ((os.ST_NOSUID, MS_NOSUID), (os.ST_NODEV, MS_NODEV), (os.ST_NOEXEC, MS_NOEXEC)):
        if st.f_flag & st_flag:
            flags |= ms_flag
    return flags


def _ensure_mountpoint(target: Path, is_dir: bool) -> None:
    if is_dir:
        target.mkdir(parents=True, exist_ok=True)
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.touch(exist_ok=True)


def _bind(source: str, root: Path, *, writable: bool) -> None:
    if os.path.islink(source):
        link = root / source.lstrip("/")
        link.parent.mkdir(parents=True, exist_ok=True)
        if not link.exists() and not link.is_symlink():
            link.symlink_to(os.readlink(source))
        return
    if not os.path.exists(source):
        return
    target = root / source.lstrip("/")
    _ensure_mountpoint(target, os.path.isdir(source))
    _mount(source, str(target), None, MS_BIND | MS_REC)
    if not writable:
        _mount(None, str(target), None, MS_BIND | MS_REMOUNT | MS_RDONLY | _locked_flags(source))


def _loopback_up() -> None:
    siocgifflags, siocsifflags, iff_up = 0x8913, 0x8914, 0x1
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        request = struct.pack("16sH14s", b"lo", 0, b"\x00" * 14)
        flags = struct.unpack("16sH14s", fcntl.ioctl(sock, siocgifflags, request))[1]
        fcntl.ioctl(sock, siocsifflags, struct.pack("16sH14s", b"lo", flags | iff_up, b"\x00" * 14))


def build_and_exec(spec: dict) -> None:
    root = Path(spec["root"])
    _mount(None, "/", None, MS_REC | MS_PRIVATE)  # nothing we do here leaks back to the host
    _mount("tmpfs", str(root), "tmpfs", MS_NOSUID | MS_NODEV, "mode=0755,size=64m")

    # Parents before children, so a tmpfs over $HOME does not hide a repository bound under it.
    entries = [("tmpfs", p, False) for p in spec["tmpfs"]]
    entries += [("ro", p, False) for p in spec["readable"]]
    entries += [("rw", p, True) for p in spec["writable"]]
    for kind, path, writable in sorted(entries, key=lambda e: (len(Path(e[1]).parts), e[0] != "tmpfs")):
        if kind == "tmpfs":
            target = root / path.lstrip("/")
            target.mkdir(parents=True, exist_ok=True)
            _mount("tmpfs", str(target), "tmpfs", MS_NOSUID | MS_NODEV, "mode=1777,size=2g")
        else:
            _bind(path, root, writable=writable)

    dev = root / "dev"
    dev.mkdir(exist_ok=True)
    for node in ("null", "zero", "full", "random", "urandom", "tty"):
        if os.path.exists(f"/dev/{node}"):
            _ensure_mountpoint(dev / node, is_dir=False)
            _mount(f"/dev/{node}", str(dev / node), None, MS_BIND)
    (dev / "shm").mkdir(exist_ok=True)
    _mount("tmpfs", str(dev / "shm"), "tmpfs", MS_NOSUID | MS_NODEV, "mode=1777,size=256m")
    for name, target in (
        ("fd", "/proc/self/fd"),
        ("stdin", "/proc/self/fd/0"),
        ("stdout", "/proc/self/fd/1"),
        ("stderr", "/proc/self/fd/2"),
    ):
        if not (dev / name).exists():
            (dev / name).symlink_to(target)
    (root / "proc").mkdir(exist_ok=True)
    _mount("proc", str(root / "proc"), "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC)

    if not spec["network"]:
        _loopback_up()

    os.chroot(root)
    os.chdir(spec["cwd"])
    argv = spec["argv"]
    os.execvpe(argv[0], argv, spec["env"])  # noqa: S606 (replacing this process is the point)


def main() -> None:
    spec = json.loads(sys.argv[1])
    try:
        build_and_exec(spec)
    except OSError as exc:
        print(f"bop sandbox: {exc}", file=sys.stderr)
        raise SystemExit(125) from exc


if __name__ == "__main__":
    main()
