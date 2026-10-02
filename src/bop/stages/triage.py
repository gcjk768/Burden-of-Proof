"""First pass on every in-scope finding with the fast model."""

from __future__ import annotations

import json
from collections.abc import Sequence

from bop.errors import BudgetExceeded, ModelOutputError
from bop.llm.schemas import TriageBatch, TriageVerdict, check_triage
from bop.llm.structured import ask_structured
from bop.repo.evidence import verify_all
from bop.scanners.sarif import FindingGroup
from bop.stages.context import RunContext, finding_payload, prompt

BATCH_SIZE = 6


def store_evidence(ctx: RunContext, verdict, checks) -> list[dict]:  # type: ignore[no-untyped-def]
    rows = []
    for ev, check in zip(verdict.evidence, checks, strict=True):
        rows.append(
            {
                "role": ev.role,
                "file": ev.file,
                "start_line": check.start_line or ev.start_line,
                "end_line": check.end_line or ev.end_line,
                "excerpt": ev.excerpt,
                "why": ev.why,
                "verified": int(check.ok),
            }
        )
    return rows


def triage(
    ctx: RunContext, groups: Sequence[FindingGroup], verdicts: dict[str, TriageVerdict] | None = None
) -> dict[str, TriageVerdict]:
    """Triage in batches. Verdicts go into ``verdicts`` as each batch finishes, so a caller still
    has the earlier batches' decisions when a later batch stops the run."""
    verdicts = {} if verdicts is None else verdicts
    for start in range(0, len(groups), BATCH_SIZE):
        batch = list(groups[start : start + BATCH_SIZE])
        ids = {g.id for g in batch}
        payload = [finding_payload(ctx.workdir, g.id, g.primary) for g in batch]

        def check(result: TriageBatch, ids: set[str] = ids) -> list[str]:
            problems = []
            answered = [v.finding_id for v in result.verdicts]
            missing = ids - set(answered)
            extra = set(answered) - ids
            if missing:
                problems.append(f"missing verdicts for {sorted(missing)}")
            if extra:
                problems.append(f"unknown finding ids {sorted(extra)}")
            if len(answered) != len(set(answered)):
                problems.append("each finding_id must appear exactly once")
            for v in result.verdicts:
                problems += [f"{v.finding_id}: {p}" for p in check_triage(v)]
            return problems

        def evidence_check(result: TriageBatch) -> list[str]:
            return [f"{v.finding_id}: {p}" for v in result.verdicts for p in verify_all(ctx.workdir, v.evidence)[1]]

        messages = [
            {"role": "system", "content": prompt("triage")},
            {"role": "user", "content": "Findings:\n" + json.dumps(payload, indent=2)},
        ]
        context = {"findings": [{"id": g.id, "key": g.primary.key} for g in batch]}
        try:
            result, call = ask_structured(
                ctx.llm, "triage", messages, TriageBatch, context=context, check=check, soft_check=evidence_check
            )
        except ModelOutputError as exc:
            for g in batch:
                ctx.store.set_group_state(g.id, "undetermined", f"triage failed: {exc}")
            ctx.log(f"triage: batch failed: {exc}")
            continue
        except BudgetExceeded:
            for g in groups[start:]:
                ctx.store.set_group_state(g.id, "stopped", "budget cap reached during triage")
            raise
        for v in result.verdicts:
            checks, problems = verify_all(ctx.workdir, v.evidence)
            ctx.store.add_verdict(
                group_id=v.finding_id,
                stage="triage",
                model=call.model,
                verdict=v.verdict,
                confidence=v.confidence,
                summary=v.summary,
                reasoning=v.reasoning,
                fp_reason=v.false_positive_reason,
                taint_path_json=None,
                evidence_ok=int(not problems),
                evidence_problems_json=json.dumps(problems),
                llm_call_id=call.call_id,
                evidence=store_evidence(ctx, v, checks),
            )
            ctx.store.set_group_state(v.finding_id, "triaged", v.verdict)
            verdicts[v.finding_id] = v
            ctx.log(f"triage: {v.finding_id} {v.verdict} ({v.confidence:.2f}) {v.summary}")
    return verdicts
