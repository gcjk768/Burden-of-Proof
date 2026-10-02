"""Deep analysis: the 1M-context model traces input to sink with read-only repository tools."""

from __future__ import annotations

import json
from typing import Any

from bop.errors import ModelOutputError
from bop.llm.client import ChatResult
from bop.llm.schemas import AnalysisVerdict, TriageVerdict, check_analysis
from bop.llm.structured import ask_structured
from bop.repo.evidence import verify_all
from bop.repo.tools import TOOL_SPECS
from bop.scanners.sarif import FindingGroup
from bop.stages.context import RunContext, finding_payload, prompt
from bop.stages.triage import store_evidence

MAX_TOOL_TURNS = 12


def _unfinished(result: ChatResult) -> str | None:
    """Why a tool-free reply is not a usable conclusion, or None if it is one."""
    if result.finish_reason == "length":
        return "Your reply was cut off at the token limit. Continue, and keep the conclusion short."
    if result.malformed_tool_call:
        return "Your tool call could not be parsed. Call the tool again with valid arguments."
    if not result.content.strip():
        return "Your reply was empty. Either call a tool or give your conclusion."
    return None


def _investigate(ctx: RunContext, group: FindingGroup, triage: TriageVerdict | None) -> tuple[str, list[Any]]:
    finding = finding_payload(ctx.workdir, group.prompt_id, group.primary)
    intro = {"finding": finding, "triage": triage.model_dump() if triage else None}
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": prompt("analyze")},
        {
            "role": "user",
            "content": "Investigate this finding.\n"
            + json.dumps(intro, indent=2)
            + "\n\nRepository files:\n"
            + ctx.tools.list_files(),
        },
    ]
    context = {"key": group.primary.key, "group_id": group.id}
    transcript: list[Any] = []
    tools = ctx.tools
    for _turn in range(MAX_TOOL_TURNS):
        result: ChatResult = ctx.llm.chat("analyze", messages, tools=TOOL_SPECS, context=context)
        transcript.append(
            {
                "content": result.content,
                "reasoning": result.reasoning,
                "tool_calls": [c.__dict__ for c in result.tool_calls],
                "model": result.model,
                "call_id": result.call_id,
            }
        )
        if not result.tool_calls:
            problem = _unfinished(result)
            if problem is None:
                return result.content, transcript
            messages.append(result.assistant_message())
            messages.append({"role": "user", "content": problem})
            continue
        messages.append(result.assistant_message())
        text_results = []
        for call in result.tool_calls:
            output = tools.call(call.name, call.arguments)
            transcript.append({"tool": call.name, "arguments": call.arguments, "output": output[:2000]})
            if call.from_text:
                text_results.append(f"Result of {call.name}({json.dumps(call.arguments)}):\n{output}")
            else:
                messages.append({"role": "tool", "tool_call_id": call.id, "content": output})
        if text_results:
            messages.append({"role": "user", "content": "\n\n".join(text_results)})
    messages.append({"role": "user", "content": "Stop using tools now and give your conclusion."})
    for _attempt in range(2):
        result = ctx.llm.chat("analyze", messages, context=context)
        transcript.append(
            {"content": result.content, "reasoning": result.reasoning, "model": result.model, "call_id": result.call_id}
        )
        problem = "You cannot call tools now. Give your conclusion." if result.tool_calls else _unfinished(result)
        if problem is None:
            return result.content, transcript
        messages.append({"role": "assistant", "content": result.content})
        messages.append({"role": "user", "content": problem + " Keep it under 300 words."})
    raise ModelOutputError("the investigation ended without a usable conclusion")


def analyze(ctx: RunContext, group: FindingGroup, triage: TriageVerdict | None) -> AnalysisVerdict | None:
    try:
        notes, transcript = _investigate(ctx, group, triage)
    except ModelOutputError as exc:
        ctx.store.set_group_state(group.id, "undetermined", f"investigation failed: {exc}")
        ctx.log(f"analyze: {group.id} investigation failed: {exc}")
        return None
    ctx.write_artifact(group.id, "analysis-transcript.json", transcript)
    if not notes.strip():
        ctx.store.set_group_state(group.id, "undetermined", "the investigation produced no conclusion")
        ctx.log(f"analyze: {group.id} produced no conclusion")
        return None

    def check(v: AnalysisVerdict) -> list[str]:
        problems = check_analysis(v)
        if v.finding_id != group.prompt_id:
            problems.append(f"finding_id must be {group.prompt_id}")
        return problems

    def evidence_check(v: AnalysisVerdict) -> list[str]:
        return verify_all(ctx.workdir, v.evidence)[1]

    messages = [
        {"role": "system", "content": prompt("analyze_verdict")},
        {
            "role": "user",
            "content": json.dumps(
                {
                    "finding": finding_payload(ctx.workdir, group.prompt_id, group.primary),
                    "investigation_notes": notes,
                },
                indent=2,
            ),
        },
    ]
    context = {"key": group.primary.key, "group_id": group.id, "finding_id": group.prompt_id}
    try:
        verdict, call = ask_structured(
            ctx.llm,
            "analyze_verdict",
            messages,
            AnalysisVerdict,
            context=context,
            check=check,
            soft_check=evidence_check,
        )
    except ModelOutputError as exc:
        ctx.store.set_group_state(group.id, "undetermined", f"analysis failed: {exc}")
        ctx.log(f"analyze: {group.id} failed: {exc}")
        return None
    checks, problems = verify_all(ctx.workdir, verdict.evidence)
    ctx.store.add_verdict(
        group_id=group.id,
        stage="analysis",
        model=call.model,
        verdict=verdict.verdict,
        confidence=verdict.confidence,
        summary=verdict.summary,
        reasoning=verdict.reasoning,
        fp_reason=verdict.false_positive_reason,
        taint_path_json=json.dumps(verdict.taint_path),
        evidence_ok=int(not problems),
        evidence_problems_json=json.dumps(problems),
        llm_call_id=call.call_id,
        evidence=store_evidence(ctx, verdict, checks),
    )
    ctx.write_artifact(group.id, "analysis-verdict.json", verdict.model_dump())
    ctx.store.set_group_state(group.id, "analysed", verdict.verdict)
    ctx.log(f"analyze: {group.id} {verdict.verdict} ({verdict.confidence:.2f}) via {' -> '.join(verdict.taint_path)}")
    return verdict
