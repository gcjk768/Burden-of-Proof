"""Read-only repository tools offered to the models during analysis."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from bop.repo.paths import PathEscape, confined, relative

MAX_RESULT_CHARS = 14_000
SKIP_DIRS = {".git", "target", "build", "node_modules", ".idea"}


class BadArgument(ValueError):
    pass


def _walk(root: Path, pattern: str | None) -> list[Path]:
    pattern = pattern or "**/*"
    if Path(pattern).is_absolute() or ".." in Path(pattern).parts:
        raise BadArgument("glob must be a relative pattern inside the repository")
    files = []
    for path in sorted(root.glob(pattern)):
        try:
            rel = path.resolve().relative_to(root)
        except ValueError:
            continue  # a symlink that points outside the repository
        if path.is_file() and not any(part in SKIP_DIRS for part in rel.parts):
            files.append(path)
    return files


def number_lines(text: str, start: int = 1) -> str:
    return "\n".join(f"{n:>5}  {line}" for n, line in enumerate(text.splitlines(), start))


class RepoTools:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()

    # ------------------------------------------------------------------ tools
    def list_files(self, glob: str | None = "**/*.java", limit: int = 300) -> str:
        files = [relative(self.root, p) for p in _walk(self.root, glob)]
        more = f"\n... {len(files) - limit} more" if len(files) > limit else ""
        return "\n".join(files[:limit]) + more if files else "no files match"

    def read_file(self, path: str, start_line: int = 1, end_line: int | None = None) -> str:
        target = confined(self.root, path)
        if not target.is_file():
            return f"error: {path} is not a file"
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        start = max(1, int(start_line))
        end = min(len(lines), int(end_line) if end_line else start + 399)
        body = number_lines("\n".join(lines[start - 1 : end]), start)
        footer = f"\n[{path}: lines {start}-{end} of {len(lines)}]"
        return body[:MAX_RESULT_CHARS] + footer

    def search_code(self, pattern: str, glob: str | None = "**/*.java", max_results: int = 60) -> str:
        try:
            regex = re.compile(pattern)
        except re.error as exc:
            return f"error: invalid regular expression: {exc}"
        hits = []
        for path in _walk(self.root, glob):
            for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                if regex.search(line):
                    hits.append(f"{relative(self.root, path)}:{number}: {line.strip()}")
                    if len(hits) >= max_results:
                        return "\n".join(hits) + "\n... more results truncated"
        return "\n".join(hits) if hits else "no matches"

    def find_symbol(self, name: str) -> str:
        """Declarations of a class, interface, enum, record or method with this name."""
        safe = re.escape(name)
        pattern = (
            rf"\b(class|interface|enum|record)\s+{safe}\b"
            rf"|\b[\w<>\[\],.? ]+\s+{safe}\s*\([^;]*$"
        )
        return self.search_code(pattern)

    def find_callers(self, method: str) -> str:
        return self.search_code(rf"[.\s]{re.escape(method)}\s*\(")

    # ------------------------------------------------------------------ dispatch
    def call(self, name: str, arguments: dict[str, Any]) -> str:
        handlers: dict[str, Callable[..., str]] = {
            "list_files": self.list_files,
            "read_file": self.read_file,
            "search_code": self.search_code,
            "find_symbol": self.find_symbol,
            "find_callers": self.find_callers,
        }
        handler = handlers.get(name)
        if handler is None:
            return f"error: unknown tool {name!r}"
        try:
            return handler(**arguments)[:MAX_RESULT_CHARS]
        except PathEscape as exc:
            return f"error: {exc}"
        except (TypeError, ValueError) as exc:
            return f"error: bad arguments for {name}: {exc}"
        except Exception as exc:  # every tool is read-only; report the problem to the model instead
            return f"error: {name} failed: {type(exc).__name__}: {exc}"


def _fn(name: str, description: str, properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required,
                "additionalProperties": False,
            },
        },
    }


TOOL_SPECS: list[dict[str, Any]] = [
    _fn(
        "list_files",
        "List repository files matching a glob, relative to the repository root.",
        {"glob": {"type": "string", "description": "for example **/*.java"}},
        [],
    ),
    _fn(
        "read_file",
        "Read a file with line numbers. Reads up to 400 lines from start_line.",
        {"path": {"type": "string"}, "start_line": {"type": "integer"}, "end_line": {"type": "integer"}},
        ["path"],
    ),
    _fn(
        "search_code",
        "Search file contents with a regular expression; returns path:line: text.",
        {"pattern": {"type": "string"}, "glob": {"type": "string"}},
        ["pattern"],
    ),
    _fn("find_symbol", "Find where a class, interface or method is declared.", {"name": {"type": "string"}}, ["name"]),
    _fn("find_callers", "Find call sites of a method by name.", {"method": {"type": "string"}}, ["method"]),
]


def describe_tools() -> str:
    return json.dumps([t["function"]["name"] for t in TOOL_SPECS])
