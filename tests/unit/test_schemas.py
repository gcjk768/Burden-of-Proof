import json

from bop.llm.schemas import (
    AnalysisVerdict,
    Evidence,
    Patch,
    TriageBatch,
    TriageVerdict,
    check_analysis,
    check_triage,
    response_schema,
)


def ev(role, line=1):
    return Evidence(role=role, file="A.java", start_line=line, end_line=line, excerpt="x", why="y")


def test_response_schema_is_self_contained_and_closed():
    for model in (TriageBatch, AnalysisVerdict, Patch):
        schema = response_schema(model)
        text = json.dumps(schema)
        assert "$ref" not in text and "$defs" not in text and '"title"' not in text
        assert schema["additionalProperties"] is False


def test_triage_false_positive_needs_reason():
    v = TriageVerdict(
        finding_id="G",
        verdict="likely_false_positive",
        confidence=0.9,
        weakness="sql_injection",
        summary="s",
        evidence=[ev("sink")],
        reasoning="r",
    )
    assert check_triage(v)
    assert not check_triage(v.model_copy(update={"false_positive_reason": "constant_input"}))


def test_reachable_needs_source_sink_and_path():
    base = dict(
        finding_id="G", confidence=0.9, weakness="sql_injection", summary="s", reasoning="r", suggested_proof="p"
    )
    bad = AnalysisVerdict(verdict="reachable", evidence=[ev("sink")], taint_path=[], **base)
    problems = check_analysis(bad)
    assert any("taint_path" in p for p in problems) and any("source" in p for p in problems)
    good = AnalysisVerdict(verdict="reachable", evidence=[ev("source"), ev("sink", 2)], taint_path=["A.java:1"], **base)
    assert check_analysis(good) == []
    unreachable = AnalysisVerdict(verdict="unreachable", evidence=[ev("context")], taint_path=[], **base)
    assert any("false_positive_reason" in p for p in check_analysis(unreachable))
