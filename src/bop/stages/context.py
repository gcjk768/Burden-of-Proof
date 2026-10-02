"""State shared by every stage of one run."""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

from bop.config import Settings
from bop.db.store import Store
from bop.java.maven import Maven
from bop.java.surefire import PROOF_MARKER, TestCase
from bop.llm.client import ChatClient
from bop.repo.paths import PathEscape, confined
from bop.repo.tools import RepoTools, number_lines
from bop.runner.base import Runner
from bop.scanners.sarif import Finding


@dataclass
class RunContext:
    settings: Settings
    store: Store
    run_id: str
    run_dir: Path
    workdir: Path
    runner: Runner
    maven: Maven
    llm: ChatClient
    rules: Path
    log: Callable[[str], None]
    baseline: list[TestCase] = field(default_factory=list)
    marker: str = PROOF_MARKER
    initial_base_counts: Counter[str] = field(default_factory=Counter)
    current_group: str | None = None
    test_provider: str | None = None

    @property
    def tools(self) -> RepoTools:
        return RepoTools(self.workdir)

    def scrub(self, text: str) -> str:
        """Build output with the run's own paths removed. It goes back into prompts, and a path that
        changes every run would stop cached replies from ever matching again."""
        for path in sorted({str(self.workdir.resolve()), str(self.workdir)}, key=len, reverse=True):
            text = text.replace(path + "/", "").replace(path, ".")
        return text

    def group_dir(self, group_id: str) -> Path:
        path = self.run_dir / "groups" / group_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def write_artifact(self, group_id: str, name: str, content: str | dict[str, Any] | list[Any]) -> Path:
        path = self.group_dir(group_id) / name
        text = content if isinstance(content, str) else json.dumps(content, indent=2)
        path.write_text(text, encoding="utf-8")
        return path


def prompt(name: str, **values: str) -> str:
    text = resources.files("bop.llm.prompts").joinpath(f"{name}.md").read_text(encoding="utf-8")
    for key, value in values.items():
        text = text.replace("{" + key + "}", value)
    return text


def code_window(root: Path, finding: Finding, before: int = 15, after: int = 15) -> str:
    path = root / finding.file
    if not path.is_file():
        return f"(file {finding.file} not found)"
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(1, finding.start_line - before)
    end = min(len(lines), finding.end_line + after)
    return number_lines("\n".join(lines[start - 1 : end]), start)


def file_block(root: Path, rel: str, limit: int = 30_000) -> str:
    try:
        path = confined(root, rel)  # the path may come from a model's taint_path
    except PathEscape:
        return ""
    if not path.is_file():
        return ""
    text = path.read_text(encoding="utf-8", errors="replace")
    return f"--- {rel}\n{text[:limit]}\n"


def build_conventions(root: Path, provider: str | None = None) -> dict[str, Any]:
    """What the proof test must look like. Surefire's detected provider is the most reliable signal,
    because JUnit often arrives transitively (spring-boot-starter-test) or from a parent pom. The pom
    text is only a fallback."""
    pom = (root / "pom.xml").read_text(encoding="utf-8", errors="replace") if (root / "pom.xml").is_file() else ""
    provider = provider or ""
    if "junitplatform" in provider or (not provider and "junit-jupiter" in pom):
        junit = "JUnit 5 (org.junit.jupiter.api)"
    elif "junit4" in provider or "junit47" in provider or (not provider and "<artifactId>junit</artifactId>" in pom):
        junit = "JUnit 4 (org.junit)"
    else:
        junit = "unknown; use JUnit 5 if it is on the classpath"
    artifacts = sorted(set(re.findall(r"<artifactId>([^<]+)</artifactId>", pom)))
    sample = ""
    tests = sorted((root / "src" / "test" / "java").rglob("*Test.java")) if (root / "src/test/java").is_dir() else []
    if tests:
        rel = tests[0].relative_to(root).as_posix()
        sample = file_block(root, rel, limit=3000)
    return {"junit": junit, "artifacts": artifacts, "sample_test": sample}


def finding_payload(root: Path, group_id: str, finding: Finding) -> dict[str, Any]:
    return {
        "finding_id": group_id,
        "rule": finding.rule_id,
        "cwe": finding.cwe,
        "category": finding.category,
        "message": finding.message,
        "file": finding.file,
        "lines": f"{finding.start_line}-{finding.end_line}",
        "code": code_window(root, finding),
    }
