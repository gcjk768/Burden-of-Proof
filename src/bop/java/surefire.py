"""Reads Surefire XML reports and decides what a test run proved.

A proof test counts as proven only if it fails with an assertion whose message carries
the marker. Compile errors, other exceptions and timeouts never count.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from bop.runner.base import RunResult

PROOF_MARKER = "[BOP-PROOF]"
_ASSERTION_TYPES = ("AssertionFailedError", "AssertionError", "ComparisonFailure", "MultipleFailuresError")
_COMPILE_LINE = re.compile(r"^\[ERROR\].*\.java:\[\d+,\d+\].*$", re.M)
_OFFLINE_MISSING = re.compile(r"has not been downloaded from it before|in offline mode|Cannot access \S+ in offline")


@dataclass(frozen=True)
class TestCase:
    __test__ = False  # not a pytest test class

    classname: str
    name: str
    status: str  # passed | failed | error | skipped
    failure_type: str | None = None
    message: str | None = None
    detail: str | None = None

    @property
    def key(self) -> str:
        return f"{self.classname}#{self.name}"


def _method_name(name: str) -> str:
    return re.sub(r"\(.*\)$", "", name or "").strip()


def parse_reports(directory: Path) -> list[TestCase]:
    cases: list[TestCase] = []
    if not directory.is_dir():
        return cases
    for report in sorted(directory.glob("TEST-*.xml")):
        try:
            root = ET.parse(report).getroot()  # noqa: S314
        except ET.ParseError:
            continue
        for case in root.iter("testcase"):
            classname = case.get("classname") or ""
            name = _method_name(case.get("name") or "")
            status, ftype, message, detail = "passed", None, None, None
            for tag in ("failure", "error"):
                node = case.find(tag)
                if node is not None:
                    status = "failed" if tag == "failure" else "error"
                    ftype = node.get("type")
                    message = node.get("message")
                    detail = (node.text or "")[:4000]
                    break
            if status == "passed" and case.find("skipped") is not None:
                status = "skipped"
            cases.append(TestCase(classname, name, status, ftype, message, detail))
    return cases


def compile_errors(output: str, limit: int = 40) -> list[str]:
    return _COMPILE_LINE.findall(output or "")[:limit]


def _is_assertion(case: TestCase) -> bool:
    ftype = case.failure_type or ""
    return case.status == "failed" or any(ftype.endswith(t) for t in _ASSERTION_TYPES)


def classify_proof(
    result: RunResult, cases: Iterable[TestCase], test_class: str, test_method: str, marker: str = PROOF_MARKER
) -> tuple[str, str]:
    """Returns (outcome, detail) for a single proof test run."""
    if result.timed_out:
        return "timeout", "the test run hit its time limit"
    method = _method_name(test_method)
    match = next((c for c in cases if c.classname == test_class and c.name == method), None)
    if match is None:
        output = result.output_tail(40_000)
        if _OFFLINE_MISSING.search(output):
            return "not_run", "a dependency or plugin is missing from the offline cache (an environment problem)"
        errors = compile_errors(output)
        if errors or result.exit_code != 0:
            detail = "\n".join(errors) if errors else result.output_tail(3000)
            return "compile_error", detail
        return "not_run", f"no Surefire result for {test_class}#{method}"
    if match.status == "passed":
        return "passed", "the test passed"
    if match.status == "skipped":
        return "not_run", "the test was skipped"
    message = match.message or ""
    if _is_assertion(match) and marker in message:
        return "failed_right_reason", message
    reason = f"{match.failure_type or match.status}: {message}".strip()
    if _is_assertion(match):
        reason += f" (assertion message lacks the marker {marker})"
    return "failed_other", (reason + "\n" + (match.detail or ""))[:3000]


def regressions(baseline: Iterable[TestCase], current: Iterable[TestCase]) -> list[str]:
    """Tests that passed in the baseline but do not pass now (missing counts as a regression)."""
    now = {c.key: c for c in current}
    out = []
    for case in baseline:
        if case.status != "passed":
            continue
        after = now.get(case.key)
        if after is None:
            out.append(f"{case.key} no longer runs")
        elif after.status != "passed":
            out.append(f"{case.key} {after.status}: {after.message or ''}".strip())
    return out
