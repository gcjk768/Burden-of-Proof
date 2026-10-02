"""Checks that every piece of evidence a model cites really is in the checkout."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from bop.llm.schemas import Evidence
from bop.repo.paths import PathEscape, confined

SLACK_LINES = 3  # models are often a line or two off; the excerpt must still match nearby
_GUTTER = re.compile(r"(?m)^\s*\d+\s{2}")  # the "  42  " line-number column the tools add


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def strip_java_comments(text: str) -> str:
    """Blank out // and /* */ comments, keeping string, text-block and char literals and every newline."""
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if ch == "/" and nxt == "/":
            while i < n and text[i] != "\n":
                out.append(" ")
                i += 1
        elif ch == "/" and nxt == "*":
            end = text.find("*/", i + 2)
            end = n if end == -1 else end + 2
            out.extend("\n" if c == "\n" else " " for c in text[i:end])
            i = end
        elif text.startswith('"""', i):
            # A text block runs to the next unescaped """, across lines.
            j = i + 3
            while j < n and not text.startswith('"""', j):
                j += 2 if text[j] == "\\" else 1
            end = min(j + 3, n)
            out.append(text[i:end])
            i = end
        elif ch in "\"'":
            quote, start = ch, i
            i += 1
            while i < n and text[i] != quote and text[i] != "\n":
                i += 2 if text[i] == "\\" else 1
            i = min(i + 1, n)
            out.append(text[start:i])
        else:
            out.append(ch)
            i += 1
    return "".join(out)


_BLOCK_COMMENTS = {
    "xml": re.compile(r"<!--.*?-->", re.S),
    "sql": re.compile(r"/\*.*?\*/|--[^\n]*", re.S),
    "hash": re.compile(r"(?m)^\s*[#!][^\n]*|(?<=\s)#[^\n]*"),
}
_COMMENT_STYLE = {
    **dict.fromkeys((".java", ".kt", ".kts", ".groovy", ".gradle", ".scala", ".js", ".ts"), "java"),
    **dict.fromkeys((".xml", ".html", ".jsp", ".xhtml", ".vm", ".ftl"), "xml"),
    ".sql": "sql",
    **dict.fromkeys((".properties", ".yaml", ".yml", ".sh", ".conf", ".cfg", ".toml", ".ini"), "hash"),
}


def strip_comments(text: str, suffix: str) -> str:
    """Comments blanked out (newlines kept) for the file types evidence usually comes from.

    Unknown types are returned unchanged.
    """
    style = _COMMENT_STYLE.get(suffix.lower())
    if style == "java":
        return strip_java_comments(text)
    if style in _BLOCK_COMMENTS:
        return _BLOCK_COMMENTS[style].sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)
    return text


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
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    code_lines = strip_comments(text, path.suffix).splitlines()
    if ev.start_line > len(lines):
        return EvidenceCheck(False, f"{ev.file} has {len(lines)} lines; evidence starts at {ev.start_line}")
    excerpt = _norm(_GUTTER.sub("", ev.excerpt))
    if not excerpt:
        return EvidenceCheck(False, f"empty excerpt for {ev.file}:{ev.start_line}")
    span = max(0, ev.end_line - ev.start_line)
    first = max(1, ev.start_line - SLACK_LINES)
    last = min(len(lines), ev.start_line + SLACK_LINES)
    in_comment = False
    for start in [ev.start_line, *range(first, last + 1)]:
        end = min(len(lines), start + span)
        if excerpt in _norm("\n".join(lines[start - 1 : end])):
            if excerpt in _norm("\n".join(code_lines[start - 1 : end])):
                return EvidenceCheck(True, None, start, end)
            in_comment = True
    if in_comment:
        # Repository text can say anything; only code counts as evidence.
        return EvidenceCheck(False, f"excerpt at {ev.file}:{ev.start_line} is inside a comment, not code")
    return EvidenceCheck(False, f"excerpt not found at {ev.file}:{ev.start_line}-{ev.end_line}: {ev.excerpt[:80]!r}")


def verify_all(root: Path, evidence: list[Evidence]) -> tuple[list[EvidenceCheck], list[str]]:
    checks = [verify(root, ev) for ev in evidence]
    return checks, [c.problem for c in checks if c.problem]
