"""Runs commands in fresh Linux namespaces with a minimal filesystem view (no Docker daemon needed).

Each command gets new user, PID and mount namespaces, plus an empty network namespace unless the
step needs the network. Inside, ``bop.runner.jail`` builds a fresh root that contains only the
toolchain (read-only), the snapshot and the paths the caller declares, and empty tmpfs mounts for
``/tmp`` and ``$HOME``. Nothing else on the host, such as the project's ``.env``, the run database,
other runs or the user's home directory, is visible to the code under test.
"""

from __future__ import annotations

import json
import os
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from pathlib import Path

from bop.errors import SandboxError
from bop.runner.base import RunResult, sandbox_env

MAX_OUTPUT_CHARS = 400_000
JAIL_FAILURE = 125

# Read-only system paths every command may need: binaries, libraries, certificates, the JDK.
SYSTEM_PATHS = ("/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/etc", "/opt")


def _limits() -> None:  # runs in the child before exec
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    two_gib = 2 * 1024**3
    resource.setrlimit(resource.RLIMIT_FSIZE, (two_gib, two_gib))


def _execute(cmd: list[str], *, cwd: Path, timeout_s: int, env: Mapping[str, str]) -> tuple[int, str, str, bool]:
    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        env=dict(env),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
        start_new_session=True,
        preexec_fn=_limits,
    )
    try:
        out, err = proc.communicate(timeout=timeout_s)
        return proc.returncode, out, err, False
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        out, err = proc.communicate()
        return -9, out, err, True


def toolchain_paths() -> list[str]:
    """Read-only paths outside SYSTEM_PATHS that the tools live in (the Python env, JDK, Maven)."""
    paths = {sys.prefix, sys.base_prefix}
    for var in ("JAVA_HOME", "MAVEN_HOME", "M2_HOME"):
        if os.environ.get(var):
            paths.add(os.environ[var])
    for tool in ("java", "mvn", "semgrep"):
        found = shutil.which(tool)
        if found:
            paths.add(str(Path(found).resolve().parent.parent))
    return sorted(p for p in paths if p and not any(p == s or p.startswith(s + "/") for s in SYSTEM_PATHS))


class LocalNamespaceRunner:
    name = "local-namespace"

    def __init__(self, unshare: str | None = None) -> None:
        self.unshare = unshare or shutil.which("unshare") or "unshare"

    def _command(self, spec: dict, network: bool) -> list[str]:
        cmd = [self.unshare, "--user", "--map-root-user", "--pid", "--fork", "--kill-child", "--mount"]
        if not network:
            cmd.append("--net")
        return [*cmd, sys.executable, "-m", "bop.runner.jail", json.dumps(spec)]

    def _spec(
        self,
        argv: Sequence[str],
        cwd: Path,
        network: bool,
        env: Mapping[str, str],
        writable: Sequence[Path],
        readable: Sequence[Path],
        root: str,
    ) -> dict:
        home = env.get("HOME", "/root")
        return {
            "root": root,
            # Fresh, empty tmpfs mounts inside the private root, not the host /tmp.
            "tmpfs": ["/tmp", home] if home not in ("/", "") else ["/tmp"],  # noqa: S108
            "readable": [*SYSTEM_PATHS, *toolchain_paths(), *(str(Path(p).resolve()) for p in readable)],
            "writable": [str(cwd.resolve()), *(str(Path(p).resolve()) for p in writable)],
            "cwd": str(cwd.resolve()),
            "network": network,
            "env": dict(env),
            "argv": list(argv),
        }

    def available(self) -> tuple[bool, str]:
        if not shutil.which(self.unshare):
            return False, "unshare is not installed (util-linux)"
        with tempfile.TemporaryDirectory(prefix="bop-probe-") as tmp:
            work = Path(tmp) / "work"
            work.mkdir()
            secret = Path(tmp) / "outside.txt"
            secret.write_text("must stay invisible")
            probe = self.run(["cat", str(secret)], cwd=work, timeout_s=30)
            if probe.exit_code == JAIL_FAILURE or "bop sandbox:" in probe.stderr:
                return False, f"cannot build the sandbox filesystem: {probe.stderr.strip()[-300:]}"
            if probe.exit_code == 0:
                return False, "the sandbox can read host files outside the snapshot"
            ok = self.run(["true"], cwd=work, timeout_s=30)
            if not ok.ok:
                return False, f"unprivileged namespaces are not usable here: {ok.stderr.strip()[-300:]}"
        return True, "user, PID, mount and network namespaces with a private filesystem view"

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        timeout_s: int,
        network: bool = False,
        env: Mapping[str, str] | None = None,
        writable: Sequence[Path] = (),
        readable: Sequence[Path] = (),
    ) -> RunResult:
        started = time.monotonic()
        full_env = sandbox_env(network=network, extra=env)
        root = tempfile.mkdtemp(prefix="bop-root-")
        try:
            spec = self._spec(argv, cwd, network, full_env, writable, readable, root)
            code, out, err, timed_out = _execute(
                self._command(spec, network), cwd=cwd, timeout_s=timeout_s, env=full_env
            )
        finally:
            shutil.rmtree(root, ignore_errors=True)
        return RunResult(
            list(argv),
            code,
            out[-MAX_OUTPUT_CHARS:],
            err[-MAX_OUTPUT_CHARS:],
            time.monotonic() - started,
            timed_out,
            network,
            self.name,
        )


class UnsandboxedRunner:
    """Development fallback for machines without user namespaces. It isolates nothing."""

    name = "unsandboxed"

    def available(self) -> tuple[bool, str]:
        return True, "NO ISOLATION: commands run directly on this machine with network and file access"

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        timeout_s: int,
        network: bool = False,
        env: Mapping[str, str] | None = None,
        writable: Sequence[Path] = (),
        readable: Sequence[Path] = (),
    ) -> RunResult:
        started = time.monotonic()
        code, out, err, timed_out = _execute(
            list(argv), cwd=cwd, timeout_s=timeout_s, env=sandbox_env(network=True, extra=env)
        )
        return RunResult(
            list(argv),
            code,
            out[-MAX_OUTPUT_CHARS:],
            err[-MAX_OUTPUT_CHARS:],
            time.monotonic() - started,
            timed_out,
            True,
            self.name,
        )


def make_runner(*, allow_unsandboxed: bool = False) -> LocalNamespaceRunner | UnsandboxedRunner:
    runner = LocalNamespaceRunner()
    ok, reason = runner.available()
    if ok:
        return runner
    if allow_unsandboxed:
        return UnsandboxedRunner()
    raise SandboxError(
        f"no sandbox available: {reason}. Run on Linux with unprivileged user namespaces, "
        "or set BOP_ALLOW_UNSANDBOXED=1 to accept running target code without isolation."
    )
