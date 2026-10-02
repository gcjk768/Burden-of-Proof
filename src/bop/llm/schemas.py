"""Structured outputs the models must produce, and helpers to send them as JSON Schema.

Triage and analysis use separate models so each stage can only return its own verdict
values. Rules that JSON Schema cannot express (evidence must match the checkout, a
reachable verdict needs a source and a sink) are enforced in code by ``check_*``.
"""

from __future__ import annotations

import copy
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Weakness = Literal["sql_injection", "path_traversal", "vulnerable_dependency", "other"]
EvidenceRole = Literal["source", "propagation", "sink", "sanitizer", "guard", "context"]
FalsePositiveReason = Literal[
    "sanitized",
    "parameterized",
    "constant_input",
    "unreachable_code",
    "test_code",
    "framework_handles",
    "wrong_sink",
    "duplicate",
    "other",
]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Evidence(Strict):
    role: EvidenceRole
    file: str = Field(description="Path relative to the repository root")
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    excerpt: str = Field(description="Code copied verbatim from those lines")
    why: str


class TriageVerdict(Strict):
    finding_id: str
    verdict: Literal["likely_real", "likely_false_positive", "needs_deep_analysis"]
    confidence: float = Field(ge=0, le=1)
    weakness: Weakness
    summary: str
    evidence: list[Evidence] = Field(min_length=1)
    false_positive_reason: FalsePositiveReason | None = None
    reasoning: str


class TriageBatch(Strict):
    verdicts: list[TriageVerdict]


class AnalysisVerdict(Strict):
    finding_id: str
    verdict: Literal["reachable", "unreachable", "undetermined"]
    confidence: float = Field(ge=0, le=1)
    weakness: Weakness
    summary: str
    evidence: list[Evidence] = Field(min_length=1)
    taint_path: list[str] = Field(description="Ordered file:line hops from untrusted input to the sink")
    false_positive_reason: FalsePositiveReason | None = None
    reasoning: str
    suggested_proof: str = Field(description="One sentence: what a failing unit test should demonstrate")


class ProofTest(Strict):
    test_path: str = Field(description="Path of the new test file, under src/test/java")
    test_class: str = Field(description="Fully qualified class name")
    test_method: str
    source: str = Field(description="Complete Java source of the test file")
    setup_notes: str = ""


class Edit(Strict):
    file: str = Field(description="Path relative to the repository root")
    search: str = Field(description="Exact text to replace; must occur exactly once in the file")
    replace: str


class Patch(Strict):
    edits: list[Edit] = Field(min_length=1)
    explanation: str
    risk_notes: str = ""


# ---------------------------------------------------------------- invariants checked in code
def check_triage(v: TriageVerdict) -> list[str]:
    problems = []
    if v.verdict == "likely_false_positive" and v.false_positive_reason is None:
        problems.append("likely_false_positive needs a false_positive_reason")
    return problems


def check_analysis(v: AnalysisVerdict) -> list[str]:
    problems = []
    roles = {e.role for e in v.evidence}
    if v.verdict == "reachable":
        if not v.taint_path:
            problems.append("reachable needs a non-empty taint_path")
        if not {"source", "sink"} <= roles:
            problems.append("reachable needs at least one source and one sink in the evidence")
    if v.verdict == "unreachable" and v.false_positive_reason is None:
        problems.append("unreachable needs a false_positive_reason")
    for e in v.evidence:
        if e.end_line < e.start_line:
            problems.append(f"evidence {e.file}:{e.start_line}-{e.end_line} ends before it starts")
    return problems


# ---------------------------------------------------------------- JSON Schema for response_format
def response_schema(model: type[BaseModel]) -> dict[str, Any]:
    """Self-contained JSON Schema: $refs inlined, titles and defaults dropped.

    Constrained decoders handle a flat schema more reliably than one with $defs.
    Optional fields stay optional; validation happens again with Pydantic.
    """
    raw = model.model_json_schema()
    defs = raw.pop("$defs", {})

    def resolve(node: Any) -> Any:
        if isinstance(node, dict):
            if "$ref" in node:
                name = node["$ref"].split("/")[-1]
                return resolve(copy.deepcopy(defs[name]))
            out = {k: resolve(v) for k, v in node.items() if k not in {"title", "default"}}
            if out.get("type") == "object":
                out.setdefault("additionalProperties", False)
            return out
        if isinstance(node, list):
            return [resolve(x) for x in node]
        return node

    return resolve(raw)
