"""The interface every sandbox implements, and the environment code under test may see."""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

# Variables passed into the sandbox. Everything else, including every API key, is dropped.
SAFE_ENV = ("PATH", "HOME", "LANG", "LC_ALL", "TZ", "TMPDIR", "JAVA_HOME", "MAVEN_HOME", "M2_HOME", "USER")
# Only passed when the step needs the network (dependency resolution), so proxies keep working.
NETWORK_ENV = (
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "https_proxy",
    "http_proxy",
    "no_proxy",
    "JAVA_TOOL_OPTIONS",
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
)


def sandbox_env(
    *, network: bool, extra: Mapping[str, str] | None = None, source: Mapping[str, str] | None = None
) -> dict[str, str]:
    source = os.environ if source is None else source
    keys = SAFE_ENV + (NETWORK_ENV if network else ())
    env = {k: source[k] for k in keys if k in source}
    env.setdefault("LANG", "C.UTF-8")
    env.update(extra or {})
    return env


@dataclass
class RunResult:
    argv: list[str]
    exit_code: int
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool
    network: bool
    runner: str

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out

    def output_tail(self, limit: int = 6000) -> str:
        text = (self.stdout or "") + ("\n" + self.stderr if self.stderr else "")
        return text[-limit:]


class Runner(Protocol):
    name: str

    def available(self) -> tuple[bool, str]: ...

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        timeout_s: int,
        network: bool = False,
        env: Mapping[str, str] | None = None,
    ) -> RunResult: ...
