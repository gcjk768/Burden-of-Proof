"""Tool calls: the OpenAI form, plus a parser for calls that leak into the text.

Nemotron uses the Qwen3-Coder tool format. When a server does not parse it, calls arrive
in ``content`` as ``<tool_call><function=NAME><parameter=ARG>VALUE</parameter></function></tool_call>``,
or as JSON inside ``<tool_call>`` tags.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

_TOOL_CALL = re.compile(r"<tool_call>(.*?)</tool_call>", re.S)
_FUNCTION = re.compile(r"<function=([\w.\-]+)>(.*?)</function>", re.S)
_PARAMETER = re.compile(r"<parameter=([\w.\-]+)>(.*?)</parameter>", re.S)


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    from_text: bool = False


def _coerce(value: str) -> Any:
    text = value.strip()
    if text in {"true", "True"}:
        return True
    if text in {"false", "False"}:
        return False
    try:
        return json.loads(text)
    except ValueError:
        return text


def parse_arguments(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def parse_text_tool_calls(content: str) -> tuple[list[ToolCall], str]:
    """Returns the calls found in ``content`` and the content with them removed."""
    calls: list[ToolCall] = []
    for index, block in enumerate(_TOOL_CALL.findall(content or "")):
        function = _FUNCTION.search(block)
        if function:
            args = {name: _coerce(value) for name, value in _PARAMETER.findall(function.group(2))}
            calls.append(ToolCall(f"text-{index}", function.group(1), args, from_text=True))
            continue
        try:
            data = json.loads(block.strip())
        except ValueError:
            continue
        if isinstance(data, dict) and isinstance(data.get("name"), str):
            args = data.get("arguments") or {}
            if isinstance(args, str):
                args = parse_arguments(args)
            calls.append(ToolCall(f"text-{index}", data["name"], args if isinstance(args, dict) else {}, True))
    remaining = _TOOL_CALL.sub("", content or "").strip()
    return calls, remaining
