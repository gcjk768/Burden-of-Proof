"""Scores findings against the OWASP Benchmark's expected results.

The OWASP Benchmark for Java (https://github.com/OWASP-Benchmark/BenchmarkJava, GPL-2.0) is cloned at
run time and never copied into this repository. Each ``BenchmarkTestNNNNN`` is one test case with a
category and a ground truth in ``expectedresults-1.2.csv``. A case counts as flagged for a category
when any finding in its file maps to that category. Precision, recall (true positive rate), false
positive rate and the Benchmark's own score (TPR minus FPR) are computed per category.

This scorer is our own. The research for this project found that the Benchmark's SARIF reader
ignores SARIF suppressions, so a triaged run must be scored on a SARIF that drops the suppressed
results, and both numbers should be cross-checked against BenchmarkUtils before they are published.
"""

from __future__ import annotations

import csv
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from bop.scanners.sarif import Finding

# Benchmark category -> our finding category
CATEGORIES = {"sqli": "sql_injection", "pathtraver": "path_traversal"}
_TEST_NAME = re.compile(r"(BenchmarkTest\d{5})")


@dataclass(frozen=True)
class Score:
    category: str
    tp: int
    fp: int
    tn: int
    fn: int

    @property
    def cases(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 0.0

    @property
    def recall(self) -> float:
        """True positive rate."""
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 0.0

    @property
    def fpr(self) -> float:
        return self.fp / (self.fp + self.tn) if self.fp + self.tn else 0.0

    @property
    def benchmark_score(self) -> float:
        """The OWASP Benchmark's score: true positive rate minus false positive rate."""
        return self.recall - self.fpr


def load_expected(path: Path) -> dict[str, tuple[str, bool]]:
    """Test case name -> (Benchmark category, is a real vulnerability)."""
    expected: dict[str, tuple[str, bool]] = {}
    with path.open(encoding="utf-8", newline="") as handle:
        for row in csv.reader(handle):
            if not row or row[0].lstrip().startswith("#"):
                continue
            expected[row[0].strip()] = (row[1].strip(), row[2].strip().lower() == "true")
    return expected


def flagged_cases(findings: Iterable[Finding]) -> dict[str, set[str]]:
    """Benchmark category -> names of the test cases with at least one finding in that category."""
    by_ours = {ours: bench for bench, ours in CATEGORIES.items()}
    flagged: dict[str, set[str]] = {bench: set() for bench in CATEGORIES}
    for finding in findings:
        bench = by_ours.get(finding.category)
        match = _TEST_NAME.search(finding.file)
        if bench and match:
            flagged[bench].add(match.group(1))
    return flagged


def score(
    expected: Mapping[str, tuple[str, bool]],
    flagged: Mapping[str, set[str]],
    categories: Sequence[str] = tuple(CATEGORIES),
) -> list[Score]:
    scores = []
    for category in categories:
        tp = fp = tn = fn = 0
        hits = flagged.get(category, set())
        for name, (case_category, real) in expected.items():
            if case_category != category:
                continue
            hit = name in hits
            if hit and real:
                tp += 1
            elif hit:
                fp += 1
            elif real:
                fn += 1
            else:
                tn += 1
        scores.append(Score(category, tp, fp, tn, fn))
    return scores


def render(scores: Sequence[Score], title: str) -> str:
    lines = [
        f"### {title}",
        "",
        "| Category | Cases | TP | FP | TN | FN | Precision | Recall | FPR | Benchmark score |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for s in scores:
        lines.append(
            f"| {s.category} | {s.cases} | {s.tp} | {s.fp} | {s.tn} | {s.fn} | {s.precision:.3f} "
            f"| {s.recall:.3f} | {s.fpr:.3f} | {s.benchmark_score:+.3f} |"
        )
    return "\n".join(lines) + "\n"
