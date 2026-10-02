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
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from bop.java.surefire import TestCase, parse_reports
from bop.repo.paths import PathEscape, confined, defuse_links
from bop.runner.base import Runner, RunResult

JobHook = Callable[[str, RunResult], None]

WARMUP_CLASS = "BopWarmupTest"
# No JUnit import, so it compiles in any project. Selecting it makes Surefire resolve the provider
# that matches the project's test classpath (JUnit 4, JUnit Platform or plain) without running
# any of the project's tests.
WARMUP_SOURCE = """/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0).
 * Written by Burden of Proof to make Surefire resolve its test provider. Never committed.
 */
public class BopWarmupTest {
}
"""
# Source checks that would reject the warm-up file. They are skipped in the online step only: their
# plugins still resolve there, and the offline baseline runs them on the project's own files.
SOURCE_CHECK_SKIPS = (
    "-Drat.skip=true",
    "-Dlicense.skip=true",
    "-Dcheckstyle.skip=true",
    "-Dspotless.check.skip=true",
    "-Dpmd.skip=true",
    "-Dcpd.skip=true",
    "-Dspotbugs.skip=true",
    "-Dformatter.skip=true",
    "-Dimpsort.skip=true",
)
PROVIDER_RE = re.compile(r"Using auto detected provider (\S+)")


@dataclass
class TestRun:
    result: RunResult
    cases: list[TestCase]


def _child(element: ET.Element, name: str) -> ET.Element | None:
    return next((c for c in element if c.tag.rsplit("}", 1)[-1] == name), None)


def test_modules(workdir: Path) -> list[Path]:
    """Directories of every module whose build runs Surefire: the project and each module reachable
    through ``<modules>``, except pom-packaged aggregators. Read before any build, from the snapshot."""
    found: list[Path] = []
    seen: set[Path] = set()

    def visit(directory: Path) -> None:
        if directory in seen:
            return
        seen.add(directory)
        pom = directory / "pom.xml"
        if pom.is_symlink() or not pom.is_file():
            return
        try:
            root = ET.parse(pom).getroot()  # noqa: S314 (the snapshot, before any of its code has run)
        except ET.ParseError:
            return
        packaging = _child(root, "packaging")
        if packaging is None or (packaging.text or "").strip() != "pom":
            found.append(directory)
        modules = _child(root, "modules")
        for module in modules if modules is not None else []:
            name = (module.text or "").strip()
            if not name:
                continue
            try:
                target = confined(workdir, (directory / name).relative_to(workdir).as_posix())
            except (PathEscape, ValueError):
                continue
            visit(target.parent if target.name.endswith(".xml") else target)

    visit(workdir.resolve())
    return found


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
        self._modules: list[Path] | None = None  # found by prepare, before any build has run

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

    def _module_dirs(self, workdir: Path) -> list[Path]:
        return self._modules if self._modules is not None else [workdir.resolve()]

    def _clear_reports(self, workdir: Path) -> None:
        for module in self._module_dirs(workdir):
            reports = self._reports_dir(module)
            defuse_links(workdir, reports)  # a build may have left target/ as a link to a host path
            shutil.rmtree(reports, ignore_errors=True)

    def _read_reports(self, workdir: Path) -> list[TestCase]:
        cases: list[TestCase] = []
        for module in self._module_dirs(workdir):
            cases += parse_reports(self._reports_dir(module), root=workdir)
        return cases

    def prepare(self, workdir: Path) -> RunResult:
        """Resolve everything the ``test`` lifecycle needs, online, without running the project's tests.

        Compiles main and test code and runs only a throwaway empty test class in every module that
        runs Surefire, so Surefire also downloads its provider. The project's own tests first run in
        the offline baseline, never with network access. ``dependency:go-offline`` is not used: it
        fails on projects with artifacts outside Maven Central and misses plugins that only resolve in
        the real lifecycle.
        """
        self.repo.mkdir(parents=True, exist_ok=True)
        self._modules = test_modules(workdir) or [workdir.resolve()]
        tests = [m / "src" / "test" / "java" / f"{WARMUP_CLASS}.java" for m in self._modules]
        for test in tests:
            if test.exists() or test.is_symlink():
                raise FileExistsError(f"{test} already exists; refusing to overwrite the project's file")
        created: list[Path] = []
        for test in tests:
            for d in (test.parent.parent.parent, test.parent.parent, test.parent):
                if not d.exists():
                    created.append(d)
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
                    *SOURCE_CHECK_SKIPS,
                    offline=False,
                ),
                workdir,
                network=True,
                timeout_s=self.prepare_timeout_s,
            )
        finally:
            # The project's build plugins ran with the snapshot writable, so links are removed first.
            for test, module in zip(tests, self._modules, strict=True):
                for leftover in (test, module / "target" / "test-classes" / f"{WARMUP_CLASS}.class"):
                    defuse_links(workdir, leftover)
                    leftover.unlink(missing_ok=True)
            self._clear_reports(workdir)
            for d in reversed(created):
                try:
                    defuse_links(workdir, d)
                    if d.is_dir() and not any(d.iterdir()):
                        d.rmdir()
                except OSError:
                    pass

    def test(self, workdir: Path, *, selector: str | None = None, purpose: str = "test") -> TestRun:
        """Run the suite (or one test, ``Class#method``) offline with no network."""
        self._clear_reports(workdir)
        goals = ["test", "-Dmaven.test.failure.ignore=true"]
        if selector:
            goals += [f"-Dtest={selector}", "-Dsurefire.failIfNoSpecifiedTests=false"]
        result = self._run(
            purpose, self._argv(*goals, offline=True), workdir, network=False, timeout_s=self.test_timeout_s
        )
        return TestRun(result, self._read_reports(workdir))
