"""Applies model-written search-and-replace edits under a strict policy."""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from pathlib import Path

from bop.llm.schemas import Edit, Patch, ProofTest
from bop.repo.paths import PathEscape, confined
from bop.repo.snapshot import FileCheckpoint

MAX_CHANGED_LINES = 80
SUPPRESSION_MARKERS = re.compile(r"nosemgrep|NOSONAR|@SuppressWarnings|@SuppressFBWarnings|noinspection", re.I)
# Proof tests must stay unit-level: no network, no processes, no reflection tricks on the JVM.
FORBIDDEN_IN_TESTS = re.compile(
    r"\bRuntime\s*\.\s*getRuntime|\bProcessBuilder\b|\bjava\.net\.|\bSocket\b|\bHttpClient\b|\bURL\s*\("
    r"|\bSystem\s*\.\s*exit\b|\bsetAccessible\s*\(|\bjavax\.script\b|\bThread\s*\.\s*sleep\b"
)


@dataclass
class AppliedPatch:
    files: list[str] = field(default_factory=list)
    diff: str = ""
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


def _changed_lines(before: str, after: str) -> int:
    return sum(1 for line in difflib.ndiff(before.splitlines(), after.splitlines()) if line[:1] in "+-")


def apply_patch(
    root: Path, patch: Patch, checkpoint: FileCheckpoint, *, allowed_prefixes: tuple[str, ...] = ("src/main/",)
) -> AppliedPatch:
    """Apply all edits or none. On any problem the checkpoint is restored and problems returned."""
    applied = AppliedPatch()
    new_contents: dict[Path, str] = {}
    originals: dict[Path, str] = {}
    for edit in patch.edits:
        problem = _check_edit(root, edit, allowed_prefixes)
        if problem:
            applied.problems.append(problem)
            continue
        path = confined(root, edit.file)
        if path not in originals:
            originals[path] = path.read_text(encoding="utf-8")
        current = new_contents.get(path, originals[path])
        count = current.count(edit.search)
        if count != 1:
            applied.problems.append(f"search text occurs {count} times in {edit.file}; it must occur exactly once")
            continue
        new_contents[path] = current.replace(edit.search, edit.replace, 1)

    total = sum(_changed_lines(originals[p], c) for p, c in new_contents.items())
    if total > MAX_CHANGED_LINES:
        applied.problems.append(f"patch changes {total} lines; keep it under {MAX_CHANGED_LINES}")
    if applied.problems:
        return applied

    diffs = []
    for path, content in new_contents.items():
        rel = path.relative_to(root.resolve()).as_posix()
        checkpoint.remember(path)
        path.write_text(content, encoding="utf-8")
        applied.files.append(rel)
        diffs.append(
            "".join(
                difflib.unified_diff(
                    originals[path].splitlines(keepends=True),
                    content.splitlines(keepends=True),
                    fromfile=f"a/{rel}",
                    tofile=f"b/{rel}",
                )
            )
        )
    applied.diff = "".join(diffs)
    return applied


def _check_edit(root: Path, edit: Edit, allowed_prefixes: tuple[str, ...]) -> str | None:
    try:
        path = confined(root, edit.file)
    except PathEscape as exc:
        return str(exc)
    rel = edit.file.lstrip("./")
    if not rel.startswith(allowed_prefixes):
        return f"{edit.file} is outside {', '.join(allowed_prefixes)}; patches may only change production code"
    if not path.is_file():
        return f"{edit.file} does not exist"
    if not edit.search:
        return f"empty search text for {edit.file}"
    if SUPPRESSION_MARKERS.search(edit.replace) and not SUPPRESSION_MARKERS.search(edit.search):
        return "patches may not add scanner suppression comments or annotations"
    return None


# ---------------------------------------------------------------- proof test placement
@dataclass
class TestPlacement:
    path: Path | None
    problems: list[str]


def place_proof_test(root: Path, proof: ProofTest, marker: str) -> TestPlacement:
    problems = []
    rel = proof.test_path.lstrip("./")
    if not rel.startswith("src/test/java/") or not rel.endswith(".java"):
        problems.append("test_path must be a .java file under src/test/java/")
    simple = proof.test_class.rsplit(".", 1)[-1]
    package = proof.test_class.rsplit(".", 1)[0] if "." in proof.test_class else ""
    expected = "src/test/java/" + (package.replace(".", "/") + "/" if package else "") + simple + ".java"
    if rel != expected:
        problems.append(f"test_path should be {expected} for class {proof.test_class}")
    if package and not re.search(rf"^\s*package\s+{re.escape(package)}\s*;", proof.source, re.M):
        problems.append(f"source must declare package {package}")
    if not re.search(rf"\bclass\s+{re.escape(simple)}\b", proof.source):
        problems.append(f"source must declare class {simple}")
    if not re.search(rf"\b{re.escape(proof.test_method)}\s*\(", proof.source):
        problems.append(f"source must define the method {proof.test_method}")
    if marker not in proof.source:
        problems.append(f"the failing assertion message must contain the marker {marker}")
    bad = FORBIDDEN_IN_TESTS.search(proof.source)
    if bad:
        problems.append(f"proof tests must stay unit-level; {bad.group(0)!r} is not allowed")
    path = None
    if not problems:
        try:
            path = confined(root, rel)
        except PathEscape as exc:
            problems.append(str(exc))
        else:
            if path.exists():
                problems.append(f"{rel} already exists; choose a new class name")
                path = None
    return TestPlacement(path, problems)
