"""Runs Semgrep inside the sandbox with this project's own rules, offline."""

from __future__ import annotations

import re
import shutil
import sys
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

from bop.runner.base import Runner, RunResult
from bop.scanners.sarif import Finding, load_sarif


def default_rules() -> Path:
    return Path(str(resources.files("bop.rules").joinpath("java-security.yaml")))


def rule_ids(rules_file: Path) -> list[str]:
    return re.findall(r"^\s*-\s*id:\s*(\S+)\s*$", rules_file.read_text(encoding="utf-8"), re.M)


def semgrep_executable() -> str:
    found = shutil.which("semgrep")
    if found:
        return found
    candidate = Path(sys.executable).with_name("semgrep")
    return str(candidate) if candidate.exists() else "semgrep"


@dataclass
class ScanResult:
    run: RunResult
    sarif_path: Path
    findings: list[Finding]

    @property
    def ok(self) -> bool:
        # Semgrep exits 0 whether or not it finds anything; 2 and above mean it failed.
        return not self.run.timed_out and self.run.exit_code in (0, 1) and self.sarif_path.is_file()


def run_semgrep(
    runner: Runner, workdir: Path, out: Path, *, rules: Path | None = None, timeout_s: int = 900
) -> ScanResult:
    rules = rules or default_rules()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.unlink(missing_ok=True)
    argv = [
        semgrep_executable(),
        "scan",
        "--config",
        str(rules),
        "--metrics=off",
        "--disable-version-check",
        "--sarif-output",
        str(out),
        "--quiet",
        "--timeout",
        "60",
        "--exclude",
        "src/test",
        ".",
    ]
    result = runner.run(
        argv,
        cwd=workdir,
        timeout_s=timeout_s,
        network=False,
        env={"SEMGREP_ENABLE_VERSION_CHECK": "0", "SEMGREP_SEND_METRICS": "off"},
    )
    findings = load_sarif(out, known_rules=rule_ids(rules)) if out.is_file() else []
    return ScanResult(result, out, findings)
