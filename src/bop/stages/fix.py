"""Fix: the smallest patch that turns the proof test green without breaking anything else."""

from __future__ import annotations

import difflib
import json
from dataclasses import dataclass, field

from bop.errors import ModelOutputError
from bop.java.surefire import classify_proof, regressions
from bop.llm.schemas import AnalysisVerdict, Patch
from bop.llm.structured import ask_structured
from bop.repo.edits import apply_patch
from bop.repo.snapshot import FileCheckpoint
from bop.scanners.sarif import FindingGroup
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


def _proof_diff(proof: ProofResult) -> str:
    assert proof.proof is not None
    rel = proof.proof.test_path
    return "".join(
        difflib.unified_diff([], proof.proof.source.splitlines(keepends=True), fromfile="/dev/null", tofile=f"b/{rel}")
    )


def fix(ctx: RunContext, group: FindingGroup, verdict: AnalysisVerdict, proof: ProofResult) -> FixResult:
    assert proof.proof is not None
    group_fps = {f.fingerprint for f in group.members}
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
        applied = apply_patch(ctx.workdir, patch, checkpoint)
        failure, proof_outcome, suite_outcome, rescan_outcome = None, None, None, None
        if not applied.ok:
            failure = "The patch was rejected:\n- " + "\n- ".join(applied.problems)
        else:
            proof_run = ctx.maven.test(ctx.workdir, selector=proof.selector, purpose="fix-proof")
            proof_outcome, detail = classify_proof(
                proof_run.result, proof_run.cases, proof.proof.test_class, proof.proof.test_method, ctx.marker
            )
            if proof_outcome != "passed":
                failure = f"After the patch the proof test is {proof_outcome}:\n{detail}"
            else:
                suite = ctx.maven.test(ctx.workdir, purpose="fix-suite")
                broken = regressions(ctx.baseline, suite.cases)
                suite_outcome = "passed" if suite.result.ok and not broken else "regressed"
                if suite_outcome != "passed":
                    failure = "The existing test suite regressed:\n" + (
                        "\n".join(broken) if broken else suite.result.output_tail(3000)
                    )
                else:
                    rescan = scan(ctx, phase="rescan", group_id=group.id, attempt=attempt)
                    still = [f for f in rescan.findings if f.fingerprint in group_fps]
                    new = [
                        f
                        for f in rescan.findings
                        if f.in_scope and f.fingerprint not in ctx.initial_fingerprints and f.file in applied.files
                    ]
                    rescan_outcome = "clean" if not still and not new else "still_reported"
                    if still:
                        failure = "The scanner still reports the finding:\n" + "\n".join(f.key for f in still)
                    elif new:
                        failure = "The patch introduces new findings:\n" + "\n".join(
                            f"{f.key} {f.rule_id}" for f in new
                        )

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
