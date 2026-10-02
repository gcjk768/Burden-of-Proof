"""Applies model-written search-and-replace edits under a strict policy."""

from __future__ import annotations

import difflib
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from bop.llm.schemas import Edit, Patch, ProofTest
from bop.repo.paths import PathEscape, confined, relative
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
    before: dict[str, str] = field(default_factory=dict)  # repository-relative path -> text
    after: dict[str, str] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.problems

    def map_line(self, file: str, line: int) -> int | None:
        """Where a line of the original file sits after the patch, or None if the patch changed it."""
        if file not in self.before:
            return line
        old, new = self.before[file].splitlines(), self.after[file].splitlines()
        for tag, i1, i2, j1, _j2 in difflib.SequenceMatcher(None, old, new, autojunk=False).get_opcodes():
            if tag == "equal" and i1 <= line - 1 < i2:
                return j1 + (line - 1 - i1) + 1
        return None


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
            try:
                originals[path] = path.read_bytes().decode("utf-8")
            except UnicodeDecodeError:
                applied.problems.append(f"{edit.file} is not UTF-8; it cannot be patched safely")
                continue
        current = new_contents.get(path, originals[path])
        search, replace = edit.search, edit.replace
        count = current.count(search)
        if count == 0 and "\r\n" in current and "\n" in search:
            # The model cannot see carriage returns. Try the search with the file's Windows line
            # endings, and keep them in the replacement. Files with mixed endings match as written.
            crlf_search = search.replace("\r\n", "\n").replace("\n", "\r\n")
            if current.count(crlf_search):
                search, count = crlf_search, current.count(crlf_search)
                replace = replace.replace("\r\n", "\n").replace("\n", "\r\n")
        if count != 1:
            applied.problems.append(f"search text occurs {count} times in {edit.file}; it must occur exactly once")
            continue
        new_contents[path] = current.replace(search, replace, 1)

    total = sum(_changed_lines(originals[p], c) for p, c in new_contents.items())
    if total > MAX_CHANGED_LINES:
        applied.problems.append(f"patch changes {total} lines; keep it under {MAX_CHANGED_LINES}")
    if applied.problems:
        return applied

    diffs = []
    for path, content in new_contents.items():
        rel = path.relative_to(root.resolve()).as_posix()
        checkpoint.remember(path)
        path.write_bytes(content.encode("utf-8"))  # bytes, so line endings stay exactly as they were
        applied.files.append(rel)
        applied.before[rel], applied.after[rel] = originals[path], content
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
    rel = relative(root, path)  # judge the real destination, not the string the model wrote
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
            path = _proof_destination(root, rel)
        except PathEscape as exc:
            problems.append(str(exc))
        else:
            if path.exists() or path.is_symlink():
                problems.append(f"{rel} already exists; choose a new class name")
                path = None
    return TestPlacement(path, problems)


def _proof_destination(root: Path, rel: str) -> Path:
    """Where a proof test really lands. A symlinked directory could send it into src/main, so the
    resolved path is judged, the same way patches are."""
    path = confined(root, rel)
    real = relative(root, path)
    if real != rel or not real.startswith("src/test/java/"):
        raise PathEscape(f"{rel} resolves to {real}; proof tests must be written under src/test/java/")
    return path


def write_proof_test(root: Path, rel: str, source: str) -> Path:
    """(Re)write a proof test, refusing symlinks. Builds of the target's code run between writes and
    could have replaced the file or a parent directory with a link to production code."""
    path = _proof_destination(root, rel)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
    fd = os.open(path, flags, 0o644)
    with os.fdopen(fd, "wb") as handle:
        handle.write(source.encode("utf-8"))
    return path
