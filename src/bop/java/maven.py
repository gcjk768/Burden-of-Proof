"""Maven driven through the sandbox runner.

``prepare`` is the only step with network access: it resolves every dependency and plugin
into a private repository and records the baseline test results. Every later build runs
offline (``-o``) inside a sandbox with no network interface.
"""

from __future__ import annotations

import shutil
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from bop.java.surefire import TestCase, parse_reports
from bop.runner.base import Runner, RunResult

JobHook = Callable[[str, RunResult], None]


@dataclass
class TestRun:
    result: RunResult
    cases: list[TestCase]


class Maven:
    def __init__(
        self,
        runner: Runner,
        repo: Path,
        *,
        executable: str = "mvn",
        prepare_timeout_s: int = 1800,
        test_timeout_s: int = 600,
        on_job: JobHook | None = None,
    ) -> None:
        self.runner = runner
        self.repo = repo
        self.executable = executable
        self.prepare_timeout_s = prepare_timeout_s
        self.test_timeout_s = test_timeout_s
        self.on_job = on_job

    def _argv(self, *goals: str, offline: bool) -> list[str]:
        argv = [self.executable, "-B", "-ntp", f"-Dmaven.repo.local={self.repo}", "-Dstyle.color=never"]
        if offline:
            argv.append("-o")
        return [*argv, *goals]

    def _run(self, purpose: str, argv: list[str], workdir: Path, *, network: bool, timeout_s: int) -> RunResult:
        result = self.runner.run(argv, cwd=workdir, timeout_s=timeout_s, network=network, writable=[self.repo])
        if self.on_job:
            self.on_job(purpose, result)
        return result

    @staticmethod
    def _reports_dir(workdir: Path) -> Path:
        return workdir / "target" / "surefire-reports"

    def prepare(self, workdir: Path) -> TestRun:
        """Resolve everything online once, then record the baseline suite.

        Runs the same ``test`` lifecycle that later runs offline. ``dependency:go-offline`` is not
        used: it fails on projects with artifacts outside Maven Central and still misses
        plugins that only resolve during the real lifecycle.
        """
        self.repo.mkdir(parents=True, exist_ok=True)
        shutil.rmtree(self._reports_dir(workdir), ignore_errors=True)
        result = self._run(
            "prepare",
            self._argv("test", "-Dmaven.test.failure.ignore=true", offline=False),
            workdir,
            network=True,
            timeout_s=self.prepare_timeout_s,
        )
        return TestRun(result, parse_reports(self._reports_dir(workdir)))

    def test(self, workdir: Path, *, selector: str | None = None, purpose: str = "test") -> TestRun:
        """Run the suite (or one test, ``Class#method``) offline with no network."""
        shutil.rmtree(self._reports_dir(workdir), ignore_errors=True)
        goals = ["test", "-Dmaven.test.failure.ignore=true"]
        if selector:
            goals += [f"-Dtest={selector}", "-Dsurefire.failIfNoSpecifiedTests=false"]
        result = self._run(
            purpose, self._argv(*goals, offline=True), workdir, network=False, timeout_s=self.test_timeout_s
        )
        return TestRun(result, parse_reports(self._reports_dir(workdir)))
