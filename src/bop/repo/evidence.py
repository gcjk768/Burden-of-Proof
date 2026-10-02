"""Checks that every piece of evidence a model cites really is in the checkout."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from bop.llm.schemas import Evidence
from bop.repo.paths import PathEscape, confined

SLACK_LINES = 3  # models are often a line or two off; the excerpt must still match nearby


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


@dataclass
class EvidenceCheck:
    ok: bool
    problem: str | None = None
    start_line: int | None = None
    end_line: int | None = None


def verify(root: Path, ev: Evidence) -> EvidenceCheck:
    try:
        path = confined(root, ev.file)
    except PathEscape as exc:
        return EvidenceCheck(False, str(exc))
    if not path.is_file():
        return EvidenceCheck(False, f"{ev.file} does not exist")
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    if ev.start_line > len(lines):
        return EvidenceCheck(False, f"{ev.file} has {len(lines)} lines; evidence starts at {ev.start_line}")
    excerpt = _norm(ev.excerpt)
    if not excerpt:
        return EvidenceCheck(False, f"empty excerpt for {ev.file}:{ev.start_line}")
    span = max(0, ev.end_line - ev.start_line)
    first = max(1, ev.start_line - SLACK_LINES)
    last = min(len(lines), ev.start_line + SLACK_LINES)
    for start in [ev.start_line, *range(first, last + 1)]:
        end = min(len(lines), start + span)
        if excerpt in _norm("\n".join(lines[start - 1 : end])):
            return EvidenceCheck(True, None, start, end)
    return EvidenceCheck(False, f"excerpt not found at {ev.file}:{ev.start_line}-{ev.end_line}: {ev.excerpt[:80]!r}")


def verify_all(root: Path, evidence: list[Evidence]) -> tuple[list[EvidenceCheck], list[str]]:
    checks = [verify(root, ev) for ev in evidence]
    return checks, [c.problem for c in checks if c.problem]
