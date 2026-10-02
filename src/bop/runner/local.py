"""Runs commands in fresh Linux user, PID and network namespaces (no Docker daemon needed).

With ``network=False`` the command gets its own empty network namespace: no interfaces
except loopback, so nothing it runs can reach the internet or the host's services.
"""

from __future__ import annotations

import os
import resource
import shutil
import signal
import subprocess
import time
from collections.abc import Mapping, Sequence
from pathlib import Path

from bop.errors import SandboxError
from bop.runner.base import RunResult, sandbox_env

MAX_OUTPUT_CHARS = 400_000


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


class LocalNamespaceRunner:
    name = "local-namespace"

    def __init__(self, unshare: str | None = None) -> None:
        self.unshare = unshare or shutil.which("unshare") or "unshare"

    def _prefix(self, network: bool) -> list[str]:
        cmd = [self.unshare, "--user", "--map-root-user", "--pid", "--fork", "--kill-child"]
        if not network:
            cmd.append("--net")
        return cmd

    def available(self) -> tuple[bool, str]:
        if not shutil.which(self.unshare):
            return False, "unshare is not installed (util-linux)"
        try:
            probe = subprocess.run(
                [*self._prefix(network=False), "true"], capture_output=True, text=True, timeout=20, check=False
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, f"unshare failed: {exc}"
        if probe.returncode != 0:
            return False, f"unprivileged user namespaces are not allowed here: {probe.stderr.strip()[:200]}"
        return True, "user, PID and network namespaces available"

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        timeout_s: int,
        network: bool = False,
        env: Mapping[str, str] | None = None,
    ) -> RunResult:
        started = time.monotonic()
        code, out, err, timed_out = _execute(
            [*self._prefix(network), *argv],
            cwd=cwd,
            timeout_s=timeout_s,
            env=sandbox_env(network=network, extra=env),
        )
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
    """Development fallback for machines without user namespaces. It cannot block the network."""

    name = "unsandboxed"

    def available(self) -> tuple[bool, str]:
        return True, "NO ISOLATION: commands run directly on this machine with network access"

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        timeout_s: int,
        network: bool = False,
        env: Mapping[str, str] | None = None,
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
