"""Proof: a JUnit test that fails, for the right reason, while the weakness is present."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from bop.errors import ModelOutputError
from bop.java.surefire import classify_proof
from bop.llm.schemas import AnalysisVerdict, ProofTest
from bop.llm.structured import ask_structured
from bop.repo.edits import place_proof_test, write_proof_test
from bop.repo.snapshot import remove_file_and_empty_parents
from bop.scanners.sarif import FindingGroup
from bop.stages.context import RunContext, build_conventions, file_block, prompt

MAX_PROOF_ATTEMPTS = 3


@dataclass
class ProofResult:
    proven: bool
    proof: ProofTest | None = None
    path: Path | None = None
    failure_message: str = ""
    attempts: int = 0
    history: list[str] = field(default_factory=list)

    @property
    def selector(self) -> str:
        assert self.proof is not None
        return f"{self.proof.test_class}#{self.proof.test_method}"


def related_files(verdict: AnalysisVerdict, primary_file: str) -> list[str]:
    files = [primary_file]
    for hop in verdict.taint_path:
        files.append(hop.rsplit(":", 1)[0])
    files += [e.file for e in verdict.evidence]
    seen: list[str] = []
    for f in files:
        if f and f not in seen and not f.startswith("src/test/"):
            seen.append(f)
    return seen


def prove(ctx: RunContext, group: FindingGroup, verdict: AnalysisVerdict) -> ProofResult:
    conventions = build_conventions(ctx.workdir, ctx.test_provider)
    sources = "".join(file_block(ctx.workdir, f) for f in related_files(verdict, group.primary.file))
    messages = [
        {"role": "system", "content": prompt("prove", marker=ctx.marker)},
        {
            "role": "user",
            "content": (
                "Verdict:\n"
                + json.dumps(verdict.model_dump(), indent=2)
                + "\n\nTest conventions:\n"
                + json.dumps({k: v for k, v in conventions.items() if k != "sample_test"})
                + "\n\nExample existing test:\n"
                + conventions["sample_test"]
                + "\n\nSource files on the path:\n"
                + sources
            ),
        },
    ]
    result = ProofResult(proven=False)
    for attempt in range(1, MAX_PROOF_ATTEMPTS + 1):
        result.attempts = attempt
        context = {"key": group.primary.key, "group_id": group.id, "attempt": attempt}

        def check(p: ProofTest) -> list[str]:
            return place_proof_test(ctx.workdir, p, ctx.marker).problems

        try:
            proof, call = ask_structured(ctx.llm, "prove", messages, ProofTest, context=context, check=check)
        except ModelOutputError as exc:
            ctx.store.add_proof_test(
                group_id=group.id, phase="before_fix", attempt=attempt, outcome="rejected", detail=str(exc)[:2000]
            )
            result.history.append(f"attempt {attempt}: rejected: {exc}")
            break
        placement = place_proof_test(ctx.workdir, proof, ctx.marker)
        assert placement.path is not None
        placement.path.parent.mkdir(parents=True, exist_ok=True)
        write_proof_test(ctx.workdir, proof.test_path.lstrip("./"), proof.source)
        saved = ctx.write_artifact(group.id, f"proof-attempt-{attempt}.java", proof.source)

        try:
            run = ctx.maven.test(ctx.workdir, selector=f"{proof.test_class}#{proof.test_method}", purpose="proof")
        except BaseException:
            remove_file_and_empty_parents(placement.path, ctx.workdir)
            raise
        outcome, detail = classify_proof(run.result, run.cases, proof.test_class, proof.test_method, ctx.marker)
        detail = ctx.scrub(detail)
        log = ctx.write_artifact(group.id, f"proof-attempt-{attempt}.log", run.result.output_tail(60_000))
        ctx.store.add_proof_test(
            group_id=group.id,
            phase="before_fix",
            attempt=attempt,
            test_path=proof.test_path,
            test_class=proof.test_class,
            test_method=proof.test_method,
            source_path=str(saved),
            outcome=outcome,
            detail=detail[:4000],
            log_path=str(log),
            llm_call_id=call.call_id,
        )
        result.history.append(f"attempt {attempt}: {outcome}")
        ctx.log(f"prove: {group.id} attempt {attempt}: {outcome}")
        if outcome == "failed_right_reason":
            result.proven, result.proof, result.path, result.failure_message = True, proof, placement.path, detail
            ctx.write_artifact(group.id, "ProofTest.java", proof.source)
            return result

        remove_file_and_empty_parents(placement.path, ctx.workdir)
        feedback = {
            "passed": "The test PASSED, so it does not demonstrate the weakness. Make it exercise the vulnerable "
            "path with attacker input and assert the safe behaviour.",
            "compile_error": "The test did not compile:\n" + detail,
            "failed_other": "The test failed for the wrong reason:\n"
            + detail
            + f"\nIt must fail on an assertion whose message contains {ctx.marker}.",
            "not_run": "The test did not run: " + detail,
            "timeout": "The test timed out. Keep it fast and self-contained.",
        }[outcome]
        messages += [
            {"role": "assistant", "content": proof.model_dump_json()},
            {"role": "user", "content": feedback + "\nReply with a corrected test as the same JSON object."},
        ]
    return result
