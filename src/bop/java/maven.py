"""Maven driven through the sandbox runner.

``prepare`` is the only step with network access. It resolves every dependency and plugin, and
Surefire's test provider, into a Maven repository that belongs to this one target repository,
without running any of the project's own tests. Every later build, the baseline included, runs
offline (``-o``) inside a sandbox with no network interface and the repository read-only.

A shared cache can be added as Maven's read-only "tail" repository (``maven.repo.local.tail``,
Maven 3.9+). Builds read from it but never write to it, so no target repository can plant an
artifact that another repository's build would load.
"""

from __future__ import annotations

import re
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from bop.java.surefire import TestCase, parse_reports
from bop.runner.base import Runner, RunResult

JobHook = Callable[[str, RunResult], None]

WARMUP_CLASS = "BopWarmupTest"
# No JUnit import, so it compiles in any project. Selecting it makes Surefire resolve the provider
# that matches the project's test classpath (JUnit 4, JUnit Platform or plain) without running
# any of the project's tests.
WARMUP_SOURCE = """/** Written by Burden of Proof to make Surefire resolve its test provider. Never committed. */
public class BopWarmupTest {
}
"""
PROVIDER_RE = re.compile(r"Using auto detected provider (\S+)")


@dataclass
class TestRun:
    result: RunResult
    cases: list[TestCase]


def detected_provider(output: str) -> str | None:
    """The Surefire provider class Maven reported, which tells JUnit 5 projects from JUnit 4 ones."""
    found = PROVIDER_RE.findall(output)
    return found[-1] if found else None


class Maven:
    def __init__(
        self,
        runner: Runner,
        repo: Path,
        *,
        seed: Path | None = None,
        executable: str = "mvn",
        prepare_timeout_s: int = 1800,
        test_timeout_s: int = 600,
        on_job: JobHook | None = None,
    ) -> None:
        self.runner = runner
        self.repo = repo
        self.seed = seed if seed is not None and seed.is_dir() else None
        self.executable = executable
        self.prepare_timeout_s = prepare_timeout_s
        self.test_timeout_s = test_timeout_s
        self.on_job = on_job

    def _argv(self, *goals: str, offline: bool) -> list[str]:
        argv = [self.executable, "-B", "-ntp", f"-Dmaven.repo.local={self.repo}", "-Dstyle.color=never"]
        if self.seed:
            argv.append(f"-Dmaven.repo.local.tail={self.seed}")
        if offline:
            argv.append("-o")
        return [*argv, *goals]

    def _run(self, purpose: str, argv: list[str], workdir: Path, *, network: bool, timeout_s: int) -> RunResult:
        # The repository belongs to this target alone and is writable only while resolving. The shared
        # seed is always read-only, so nothing a build runs can change what another repository loads.
        seed = [self.seed] if self.seed else []
        if network:
            result = self.runner.run(
                argv, cwd=workdir, timeout_s=timeout_s, network=True, writable=[self.repo], readable=seed
            )
        else:
            result = self.runner.run(argv, cwd=workdir, timeout_s=timeout_s, network=False, readable=[self.repo, *seed])
        if self.on_job:
            self.on_job(purpose, result)
        return result

    @staticmethod
    def _reports_dir(workdir: Path) -> Path:
        return workdir / "target" / "surefire-reports"

    def prepare(self, workdir: Path) -> RunResult:
        """Resolve everything the ``test`` lifecycle needs, online, without running the project's tests.

        Compiles main and test code and runs only a throwaway empty test class, so Surefire also
        downloads its provider. The project's own tests first run in the offline baseline, never
        with network access. ``dependency:go-offline`` is not used: it fails on projects with
        artifacts outside Maven Central and misses plugins that only resolve in the real lifecycle.
        """
        self.repo.mkdir(parents=True, exist_ok=True)
        test = workdir / "src" / "test" / "java" / f"{WARMUP_CLASS}.java"
        if test.exists():
            raise FileExistsError(f"{test} already exists; refusing to overwrite the project's file")
        created_dirs = [d for d in (test.parent, test.parent.parent, test.parent.parent.parent) if not d.exists()]
        test.parent.mkdir(parents=True, exist_ok=True)
        test.write_text(WARMUP_SOURCE, encoding="utf-8")
        try:
            return self._run(
                "prepare",
                self._argv(
                    "test",
                    f"-Dtest={WARMUP_CLASS}",
                    "-Dsurefire.failIfNoSpecifiedTests=false",
                    "-Dmaven.test.failure.ignore=true",
                    offline=False,
                ),
                workdir,
                network=True,
                timeout_s=self.prepare_timeout_s,
            )
        finally:
            test.unlink(missing_ok=True)
            (workdir / "target" / "test-classes" / f"{WARMUP_CLASS}.class").unlink(missing_ok=True)
            shutil.rmtree(self._reports_dir(workdir), ignore_errors=True)
            for d in created_dirs:
                if d.exists() and not any(d.iterdir()):
                    d.rmdir()

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
