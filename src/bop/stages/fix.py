"""Fix: the smallest patch that turns the proof test green without breaking anything else."""

from __future__ import annotations

import difflib
import json
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from bop.errors import ModelOutputError
from bop.java.surefire import classify_proof, regressions
from bop.llm.schemas import AnalysisVerdict, Patch
from bop.llm.structured import ask_structured
from bop.repo.edits import AppliedPatch, apply_patch, write_proof_test
from bop.repo.paths import PathEscape
from bop.repo.snapshot import FileCheckpoint
from bop.scanners.sarif import Finding, FindingGroup
from bop.stages.context import RunContext, file_block, prompt
from bop.stages.ingest import scan
from bop.stages.prove import ProofResult, related_files

MAX_FIX_ATTEMPTS = 5


@dataclass
class FixResult:
    fixed: bool
    diff: str = ""
    attempts: int = 0
    summary: str = ""
    history: list[str] = field(default_factory=list)


def _try_patch(
    ctx: RunContext,
    group: FindingGroup,
    proof: ProofResult,
    patch: Patch,
    checkpoint: FileCheckpoint,
    group_bases: Counter[str],
    attempt: int,
) -> tuple[AppliedPatch, str | None, tuple[str | None, ...]]:
    """Apply one patch and run the three checks. Returns (applied, failure or None, outcomes)."""
    assert proof.proof is not None and proof.path is not None
    applied = apply_patch(ctx.workdir, patch, checkpoint)
    if not applied.ok:
        return applied, "The patch was rejected:\n- " + "\n- ".join(applied.problems), (None, None, None)

    # The patch policy keeps edits inside src/main; rewriting the proof test from its source as well
    # means nothing can have weakened it before it judges the patch.
    try:
        write_proof_test(ctx.workdir, proof.proof.test_path.lstrip("./"), proof.proof.source)
    except (PathEscape, OSError) as exc:
        return applied, f"The proof test could not be rewritten safely: {exc}", (None, None, None)
    proof_run = ctx.maven.test(ctx.workdir, selector=proof.selector, purpose="fix-proof")
    proof_outcome, detail = classify_proof(
        proof_run.result, proof_run.cases, proof.proof.test_class, proof.proof.test_method, ctx.marker
    )
    if proof_outcome != "passed":
        return applied, f"After the patch the proof test is {proof_outcome}:\n{detail}", (proof_outcome, None, None)

    suite = ctx.maven.test(ctx.workdir, purpose="fix-suite")
    broken = regressions(ctx.baseline, suite.cases)
    if not suite.result.ok or broken:
        detail = "\n".join(broken) if broken else suite.result.output_tail(3000)
        return applied, "The existing test suite regressed:\n" + detail, (proof_outcome, "regressed", None)

    rescan = scan(ctx, phase="rescan", group_id=group.id, attempt=attempt)
    still, new = rescan_verdict(
        ctx.initial_base_counts,
        group_bases,
        rescan.findings,
        applied.files,
        members=group.members,
        line_map=applied.map_line,
    )
    if still:
        failure = "The scanner still reports the finding:\n" + "\n".join(f.key for f in still)
        return applied, failure, (proof_outcome, "passed", "still_reported")
    if new:
        failure = "The patch introduces new findings:\n" + "\n".join(f"{f.key} {f.rule_id}" for f in new)
        return applied, failure, (proof_outcome, "passed", "new_findings")
    return applied, None, (proof_outcome, "passed", "clean")


def rescan_verdict(
    initial: Counter[str],
    group_bases: Counter[str],
    findings: list[Finding],
    edited_files: list[str],
    *,
    members: Sequence[Finding] = (),
    line_map: Callable[[str, int], int | None] | None = None,
) -> tuple[list[Finding], list[Finding]]:
    """Which findings the rescan still reports for this group, and which in-scope findings are new.

    Identical matches (same rule, file and code) are told apart only by order, so fixing the first
    of two would shift the second into its fingerprint. Counting by base fingerprint avoids that:
    the group is fixed when the count for its code drops by the number of group members. Counting
    alone cannot tell which duplicate went away, so a match with the same rule and code still at a
    member's own line (followed through the patch) also counts as still reported.
    """
    counts = Counter(f.base_fingerprint for f in findings)
    still_bases = {b for b, n in group_bases.items() if counts[b] > initial[b] - n}
    still = [f for f in findings if f.base_fingerprint in still_bases]
    for member in members:
        line = line_map(member.file, member.start_line) if line_map else member.start_line
        if line is None:
            continue  # the patch rewrote that line
        for f in findings:
            same = f.base_fingerprint == member.base_fingerprint and f.file == member.file and f.start_line == line
            if same and f not in still:
                still.append(f)
    new_bases = {
        f.base_fingerprint
        for f in findings
        if (f.in_scope or f.suppressed_in_source)  # a match the patch hid behind nosemgrep still counts
        and f.file in edited_files
        and f.base_fingerprint not in group_bases
        and counts[f.base_fingerprint] > initial[f.base_fingerprint]
    }
    new = [f for f in findings if f.base_fingerprint in new_bases]
    return still, new


def _proof_diff(proof: ProofResult) -> str:
    assert proof.proof is not None
    rel = proof.proof.test_path
    return "".join(
        difflib.unified_diff([], proof.proof.source.splitlines(keepends=True), fromfile="/dev/null", tofile=f"b/{rel}")
    )


def fix(ctx: RunContext, group: FindingGroup, verdict: AnalysisVerdict, proof: ProofResult) -> FixResult:
    assert proof.proof is not None
    group_bases = Counter(f.base_fingerprint for f in group.members)
    files = related_files(verdict, group.primary.file)
    messages = [
        {"role": "system", "content": prompt("fix")},
        {
            "role": "user",
            "content": (
                "Verdict:\n"
                + json.dumps(verdict.model_dump(), indent=2)
                + f"\n\nProof test ({proof.proof.test_path}), currently failing with:\n{proof.failure_message}\n\n"
                + proof.proof.source
                + "\n\nProduction files you may change:\n"
                + "".join(file_block(ctx.workdir, f) for f in files)
            ),
        },
    ]
    result = FixResult(fixed=False)
    for attempt in range(1, MAX_FIX_ATTEMPTS + 1):
        result.attempts = attempt
        context = {"key": group.primary.key, "group_id": group.id, "attempt": attempt}
        try:
            patch, call = ask_structured(ctx.llm, "fix", messages, Patch, context=context)
        except ModelOutputError as exc:
            result.history.append(f"attempt {attempt}: no valid patch: {exc}")
            ctx.store.add_patch(
                group_id=group.id, attempt=attempt, policy_ok=0, accepted=0, failure_summary=str(exc)[:2000]
            )
            break

        checkpoint = FileCheckpoint(ctx.workdir)
        try:
            applied, failure, outcomes = _try_patch(ctx, group, proof, patch, checkpoint, group_bases, attempt)
        except BaseException:
            checkpoint.restore()  # never leave a half-checked patch in the snapshot
            raise
        failure = ctx.scrub(failure) if failure else None
        proof_outcome, suite_outcome, rescan_outcome = outcomes

        diff_path = (
            ctx.write_artifact(group.id, f"patch-attempt-{attempt}.diff", applied.diff) if applied.diff else None
        )
        ctx.store.add_patch(
            group_id=group.id,
            attempt=attempt,
            diff_path=str(diff_path) if diff_path else None,
            files_json=json.dumps(applied.files),
            policy_ok=int(applied.ok),
            proof_outcome=proof_outcome,
            suite_outcome=suite_outcome,
            rescan_outcome=rescan_outcome,
            accepted=int(failure is None),
            failure_summary=failure[:4000] if failure else None,
            llm_call_id=call.call_id,
        )
        if failure is None:
            result.fixed, result.diff, result.summary = True, applied.diff, patch.explanation
            ctx.write_artifact(group.id, "fix.diff", applied.diff + _proof_diff(proof))
            result.history.append(f"attempt {attempt}: accepted")
            ctx.log(f"fix: {group.id} attempt {attempt}: accepted")
            checkpoint.restore()  # leave the snapshot clean for the next finding
            return result

        checkpoint.restore()
        result.history.append(f"attempt {attempt}: {failure.splitlines()[0]}")
        ctx.log(f"fix: {group.id} attempt {attempt}: {failure.splitlines()[0]}")
        messages += [
            {"role": "assistant", "content": patch.model_dump_json()},
            {
                "role": "user",
                "content": failure + "\nThe files are back to their original state. "
                "Reply with a corrected patch as the same JSON object.",
            },
        ]
    result.summary = result.history[-1] if result.history else "no attempts"
    return result
