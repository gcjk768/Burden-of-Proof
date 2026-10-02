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

Two steps make the view hold against code that tries to leave it:

- ``pivot_root`` moves the namespace onto the new root and the old root is detached, so the host
  tree is no longer mounted anywhere in this mount namespace. A ``chroot`` alone leaves it mounted,
  and a process with ``CAP_SYS_CHROOT`` can climb back out.
- Before ``exec`` every capability is dropped (bounding, ambient, effective, permitted and
  inheritable sets), the securebits that would give root its capabilities back on ``exec`` are set
  and locked, and ``no_new_privs`` is set. The command runs as uid 0 of the namespace but cannot
  remount, unmount, chroot or regain privileges through setuid binaries. The state is checked
  through ``/proc/self/status`` before ``exec``, and the jail refuses to run anything if it differs.
"""

from __future__ import annotations

import ctypes
import fcntl
import json
import os
import platform
import socket
import struct
import sys
from pathlib import Path

from bop.runner.privileges import privilege_state, privileges_dropped

MS_RDONLY = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
MS_REMOUNT = 32
MS_BIND = 4096
MS_REC = 16384
MS_PRIVATE = 1 << 18
MNT_DETACH = 2

PR_CAPBSET_DROP = 24
PR_SET_SECUREBITS = 28
PR_SET_NO_NEW_PRIVS = 38
PR_CAP_AMBIENT = 47
PR_CAP_AMBIENT_CLEAR_ALL = 4
# NOROOT, NO_SETUID_FIXUP and NO_CAP_AMBIENT_RAISE, each with its lock, plus KEEP_CAPS_LOCKED.
SECUREBITS = 0b1110_1111
CAPABILITY_VERSION_3 = 0x20080522
SYS_PIVOT_ROOT = {"x86_64": 155, "aarch64": 41, "riscv64": 41}
SYS_MOUNT_SETATTR = 442  # the same number on every architecture (Linux 5.12+)
AT_FDCWD = -100
AT_RECURSIVE = 0x8000
MOUNT_ATTR_RDONLY = 0x1

_libc = ctypes.CDLL(None, use_errno=True)


class _CapHeader(ctypes.Structure):
    _fields_ = (("version", ctypes.c_uint32), ("pid", ctypes.c_int))


class _CapData(ctypes.Structure):
    _fields_ = (("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32), ("inheritable", ctypes.c_uint32))


def _check(rc: int, what: str) -> None:
    if rc != 0:
        err = ctypes.get_errno()
        raise OSError(err, f"{what}: {os.strerror(err)}")


def _prctl(option: int, arg: int = 0) -> None:
    _check(_libc.prctl(option, ctypes.c_ulong(arg), ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0)), "prctl")


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


class _MountAttr(ctypes.Structure):
    _fields_ = (
        ("attr_set", ctypes.c_uint64),
        ("attr_clr", ctypes.c_uint64),
        ("propagation", ctypes.c_uint64),
        ("userns_fd", ctypes.c_uint64),
    )


def _read_only_tree(target: str, source: str, *, use_setattr: bool = True) -> None:
    """Make a bound tree read-only, including any mount nested inside it.

    A plain read-only remount changes only the top mount, so a writable mount below a bound toolchain
    path would stay writable. ``mount_setattr`` with ``AT_RECURSIVE`` covers the whole tree. Kernels
    older than 5.12 do not have it, so each mount under the target is remounted one by one instead.
    """
    attr = _MountAttr(MOUNT_ATTR_RDONLY, 0, 0, 0)
    rc = (
        -1
        if not use_setattr
        else _libc.syscall(
            ctypes.c_long(SYS_MOUNT_SETATTR),
            ctypes.c_int(AT_FDCWD),
            target.encode(),
            ctypes.c_uint(AT_RECURSIVE),
            ctypes.byref(attr),
            ctypes.c_size_t(ctypes.sizeof(attr)),
        )
    )
    if rc == 0:
        return
    for mount_point in [target, *_mounts_below(target)]:
        _mount(None, mount_point, None, MS_BIND | MS_REMOUNT | MS_RDONLY | _locked_flags(mount_point))


def _mounts_below(target: str) -> list[str]:
    below = []
    with open("/proc/self/mountinfo", encoding="utf-8") as handle:
        for line in handle:
            point = line.split()[4].replace("\\040", " ")
            if point.startswith(target.rstrip("/") + "/"):
                below.append(point)
    return below


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
        _read_only_tree(str(target), source)


def _pivot_into(root: Path) -> None:
    """Make ``root`` the namespace's root and detach the old one, so the host tree is unreachable."""
    number = SYS_PIVOT_ROOT.get(platform.machine())
    if number is None:
        raise OSError(0, f"pivot_root: unsupported architecture {platform.machine()}")
    os.chdir(root)
    # pivot_root(".", ".") stacks the old root on top of the new one; detaching "." removes it.
    _check(_libc.syscall(ctypes.c_long(number), b".", b"."), "pivot_root")
    _check(_libc.umount2(b".", MNT_DETACH), "umount old root")
    os.chdir("/")
    # The root itself only holds mount points. Writable places are their own mounts.
    _mount(None, "/", None, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV)


def _drop_privileges(last_cap: int) -> None:
    """Leave the command with no capabilities and no way to get them back."""
    _prctl(PR_SET_SECUREBITS, SECUREBITS)
    for cap in range(last_cap + 1):
        _prctl(PR_CAPBSET_DROP, cap)
    _prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL)
    header = _CapHeader(CAPABILITY_VERSION_3, 0)
    data = (_CapData * 2)()
    _check(_libc.capset(ctypes.byref(header), data), "capset")
    _prctl(PR_SET_NO_NEW_PRIVS, 1)


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

    last_cap = int(Path("/proc/sys/kernel/cap_last_cap").read_text())
    _pivot_into(root)
    _drop_privileges(last_cap)
    state = privilege_state(Path("/proc/self/status").read_text())
    if not privileges_dropped(state):
        raise OSError(0, f"capabilities were not dropped: {state}")
    os.closerange(3, 1 << 20)  # nothing opened while building the root reaches the command
    os.chdir(spec["cwd"])
    argv = spec["argv"]
    os.execvpe(argv[0], argv, dict(os.environ))  # noqa: S606 (replacing this process is the point)


def main() -> None:
    spec = json.loads(sys.argv[1])
    try:
        build_and_exec(spec)
    except OSError as exc:
        print(f"bop sandbox: {exc}", file=sys.stderr)
        raise SystemExit(125) from exc


if __name__ == "__main__":
    main()
