"""A scripted stand-in for the model, used by tests and by replaying recorded demos.

Script format (JSON):

    {"model": "scripted",
     "replies": [
        {"stage": "triage", "verdicts": {"<file>:<line>": {...TriageVerdict without finding_id...}}},
        {"stage": "analyze", "match": {"key": "<file>:<line>"}, "turns": [
             {"tool_calls": [{"name": "read_file", "arguments": {"path": "..."}}]},
             {"content": "notes ..."}]},
        {"stage": "analyze_verdict", "match": {"key": "..."}, "turns": [{"json": {...}}]},
        {"stage": "prove", "match": {"key": "..."}, "turns": [{"json": {...}}, {"json": {...}}]},
        {"stage": "fix", "match": {"key": "..."}, "turns": [{"json": {...}}]}
     ]}

Each matching entry hands out its turns in order. ``{finding_id}`` placeholders in JSON
replies are filled from the request context.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from bop.errors import ModelOutputError
from bop.llm.client import ChatResult, Message, Usage
from bop.llm.toolcalls import ToolCall


def _fill(value: Any, context: dict[str, Any]) -> Any:
    if isinstance(value, str):
        for key, replacement in context.items():
            if isinstance(replacement, str):
                value = value.replace("{" + key + "}", replacement)
        return value
    if isinstance(value, list):
        return [_fill(v, context) for v in value]
    if isinstance(value, dict):
        return {k: _fill(v, context) for k, v in value.items()}
    return value


class ScriptedClient:
    def __init__(self, script: dict[str, Any], *, recorder: Any = None) -> None:
        self.model = script.get("model", "scripted")
        self.entries = script.get("replies", [])
        self._cursor: dict[int, int] = {}
        self.recorder = recorder
        self.calls: list[tuple[str, dict[str, Any]]] = []

    @classmethod
    def from_file(cls, path: Path, **kwargs: Any) -> ScriptedClient:
        return cls(json.loads(Path(path).read_text(encoding="utf-8")), **kwargs)

    def _find(self, stage: str, context: dict[str, Any]) -> int:
        for index, entry in enumerate(self.entries):
            if entry.get("stage") != stage:
                continue
            match = entry.get("match", {})
            if all(context.get(k) == v for k, v in match.items()):
                turns = entry.get("turns")
                if turns is not None and self._cursor.get(index, 0) >= len(turns):
                    continue
                return index
        raise ModelOutputError(f"script has no reply for stage {stage!r} with context {context}")

    def chat(
        self,
        stage: str,
        messages: Sequence[Message],
        *,
        schema: dict[str, Any] | None = None,
        tools: Sequence[dict[str, Any]] | None = None,
        context: dict[str, Any] | None = None,
    ) -> ChatResult:
        context = dict(context or {})
        self.calls.append((stage, context))
        index = self._find(stage, context)
        entry = self.entries[index]

        if "verdicts" in entry:  # a triage batch: answer for each finding in the request
            verdicts = []
            for finding in context.get("findings", []):
                verdict = entry["verdicts"].get(finding["key"])
                if verdict is None:
                    raise ModelOutputError(f"script has no triage verdict for {finding['key']}")
                verdicts.append({**verdict, "finding_id": finding["id"]})
            content, calls = json.dumps({"verdicts": verdicts}), []
        else:
            turn = entry["turns"][self._cursor.get(index, 0)]
            self._cursor[index] = self._cursor.get(index, 0) + 1
            calls = [
                ToolCall(f"call-{index}-{n}", c["name"], c.get("arguments", {}))
                for n, c in enumerate(turn.get("tool_calls", []))
            ]
            content = json.dumps(_fill(turn["json"], context)) if "json" in turn else turn.get("content", "")

        result = ChatResult(
            stage=stage,
            role="scripted",
            model=self.model,
            content=content,
            tool_calls=calls,
            usage=Usage(),
            finish_reason="tool_calls" if calls else "stop",
        )
        if self.recorder is not None:
            result.call_id = self.recorder(result, None, context, None)
        return result
