"""Ask for a Pydantic-shaped reply, validate it, and retry once with the problems listed."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Sequence
from typing import Any

from pydantic import BaseModel, ValidationError

from bop.errors import ModelOutputError
from bop.llm.client import ChatClient, ChatResult, Message
from bop.llm.schemas import response_schema

_FENCE = re.compile(r"^```(?:json)?\s*(.*?)\s*```$", re.S)


def extract_json(text: str) -> Any:
    text = (text or "").strip()
    fenced = _FENCE.match(text)
    if fenced:
        text = fenced.group(1)
    try:
        return json.loads(text)
    except ValueError:
        start, end = text.find("{"), text.rfind("}")
        if start == -1 or end <= start:
            raise
        return json.loads(text[start : end + 1])


def ask_structured[T: BaseModel](
    client: ChatClient,
    stage: str,
    messages: Sequence[Message],
    model: type[T],
    *,
    context: dict[str, Any] | None = None,
    check: Callable[[T], list[str]] | None = None,
    soft_check: Callable[[T], list[str]] | None = None,
    retries: int = 1,
) -> tuple[T, ChatResult]:
    schema = {"name": model.__name__, "schema": response_schema(model)}
    conversation = list(messages)
    problems: list[str] = []
    # A reply that passed the hard checks and failed only the soft ones. It is still valid, so if
    # the retry comes back worse (cut off, malformed, or no reply at all) it is returned instead.
    fallback: tuple[T, ChatResult] | None = None
    for attempt in range(retries + 1):
        try:
            result = client.chat(stage, conversation, schema=schema, context=context)
        except ModelOutputError:
            if fallback is not None:
                return fallback
            raise
        hard_ok = False
        try:
            value = model.model_validate(extract_json(result.content))
            problems = check(value) if check else []
            if not problems:
                hard_ok = True
                if soft_check and attempt < retries:
                    # Soft problems (such as evidence that does not match the code) earn one more try,
                    # but never sink an otherwise valid reply: callers record them instead.
                    problems = soft_check(value)
                    if problems:
                        fallback = (value, result)
        except (ValueError, ValidationError) as exc:
            problems = [str(exc)[:2000]]
        if not problems:
            return value, result
        forget = getattr(client, "forget", None)
        if not hard_ok and forget is not None and result.request_hash:
            forget(result.request_hash)  # do not replay an invalid reply from the cache
        if result.finish_reason == "length":
            problems.append("The reply was cut off at the token limit; answer more briefly.")
        conversation = [
            *conversation,
            {"role": "assistant", "content": result.content},
            {
                "role": "user",
                "content": "Your reply was rejected:\n- "
                + "\n- ".join(problems)
                + "\nReply again with only the corrected JSON object.",
            },
        ]
    if fallback is not None:
        return fallback
    raise ModelOutputError(f"{stage}: no valid {model.__name__} after {retries + 1} tries: " + "; ".join(problems))
