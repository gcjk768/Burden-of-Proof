"""Chat client for Nebius Token Factory (OpenAI-compatible), with routing, caching, cost and fallback."""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field, replace
from typing import Any, Protocol

from bop.config import Settings
from bop.errors import BudgetExceeded, ConfigError, ModelOutputError, ModelUnavailable, RateLimited
from bop.llm.cache import ResponseCache, request_key
from bop.llm.cost import Budget, PriceTable, estimate_tokens
from bop.llm.router import Route, Router
from bop.llm.toolcalls import ToolCall, parse_arguments, parse_text_tool_calls

Message = dict[str, Any]
_THINK = re.compile(r"<think>(.*?)</think>", re.S)
MAX_TOKENS_CAP = 32768  # the most a cut-off reply's single retry may ask for


@dataclass
class Usage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    reasoning_tokens: int = 0


@dataclass
class ChatResult:
    stage: str
    role: str
    model: str
    content: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    usage: Usage = field(default_factory=Usage)
    finish_reason: str | None = None
    cached: bool = False
    cost_usd: float = 0.0
    latency_ms: int = 0
    request_hash: str | None = None
    fallback_from: str | None = None
    call_id: int | None = None
    malformed_tool_call: bool = False
    reasoning: str = ""  # thinking text the server returned, kept for the audit trail

    def assistant_message(self) -> Message:
        """The reply as a message to append to the conversation."""
        msg: Message = {"role": "assistant", "content": self.content or ""}
        native = [c for c in self.tool_calls if not c.from_text]
        if native:
            msg["tool_calls"] = [
                {"id": c.id, "type": "function", "function": {"name": c.name, "arguments": json.dumps(c.arguments)}}
                for c in native
            ]
        return msg


class ChatClient(Protocol):
    def chat(
        self,
        stage: str,
        messages: Sequence[Message],
        *,
        schema: dict[str, Any] | None = None,
        tools: Sequence[dict[str, Any]] | None = None,
        context: dict[str, Any] | None = None,
    ) -> ChatResult: ...


# (result, route, context, error) -> call id stored in the run ledger
CallRecorder = Callable[[ChatResult | None, Route, dict[str, Any], str | None], int | None]


def split_thinking(text: str | None) -> tuple[str, str]:
    """(answer, thinking) from a reply whose thinking leaked into the content."""
    if not text:
        return "", ""
    thoughts = [m.strip() for m in _THINK.findall(text)]
    text = _THINK.sub("", text)
    if "</think>" in text:  # the opening tag was part of the prompt template
        before, text = text.split("</think>", 1)
        thoughts.insert(0, before.strip())
    return text.strip(), "\n\n".join(t for t in thoughts if t)


def strip_thinking(text: str | None) -> str:
    return split_thinking(text)[0]


def _reasoning_field(message: Any) -> str:
    """The separate reasoning field, under whichever name the server uses today."""
    extra = getattr(message, "model_extra", None) or {}
    for name in ("reasoning_content", "reasoning"):
        value = extra.get(name) if isinstance(extra, dict) else None
        value = value or getattr(message, name, None)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _serialise(result: ChatResult) -> dict[str, Any]:
    data = asdict(result)
    for key in ("cached", "cost_usd", "call_id", "fallback_from", "request_hash"):
        data.pop(key, None)
    return data


def _deserialise(data: dict[str, Any]) -> ChatResult:
    calls = [ToolCall(**c) for c in data.pop("tool_calls", [])]
    usage = Usage(**data.pop("usage", {}))
    return ChatResult(tool_calls=calls, usage=usage, **data)


class TokenFactoryClient:
    """Talks to Token Factory through the OpenAI Python SDK.

    One SDK client per base URL, because models can be served from different regional hosts.
    """

    def __init__(
        self,
        settings: Settings,
        *,
        router: Router | None = None,
        cache: ResponseCache | None = None,
        prices: PriceTable | None = None,
        budget: Budget | None = None,
        recorder: CallRecorder | None = None,
        sdk_factory: Callable[[str], Any] | None = None,
    ) -> None:
        self.settings = settings
        self.router = router or Router(settings)
        self.cache = cache or ResponseCache(settings.cache_dir, settings.cache_mode)
        self.prices = prices or PriceTable()
        self.budget = budget or Budget(settings.budget_usd)
        self.recorder = recorder
        self._sdk_factory = sdk_factory or self._default_sdk
        self._sdks: dict[str, Any] = {}
        self._down: set[str] = set()
        # Reported by other Token Factory users: enable_thinking=false alone has not always stopped
        # Nemotron from reasoning, and adding reasoning_effort="none" did. Dropped for the rest of the
        # run if the server ever rejects the field.
        self._send_reasoning_effort = True

    def _default_sdk(self, base_url: str) -> Any:
        if not self.settings.api_key:
            raise ConfigError("NEBIUS_API_KEY is not set (put it in .env; see .env.example)")
        import httpx
        from openai import OpenAI

        # The SDK retries 408/409/429/5xx with backoff and honours Retry-After. A long read timeout
        # covers 16k-token replies; a short connect timeout fails fast on a dead host.
        timeout = httpx.Timeout(600.0, connect=10.0)
        return OpenAI(base_url=base_url, api_key=self.settings.api_key, max_retries=4, timeout=timeout)

    def _sdk(self, base_url: str) -> Any:
        if base_url not in self._sdks:
            self._sdks[base_url] = self._sdk_factory(base_url)
        return self._sdks[base_url]

    # ------------------------------------------------------------------ public API
    def chat(
        self,
        stage: str,
        messages: Sequence[Message],
        *,
        schema: dict[str, Any] | None = None,
        tools: Sequence[dict[str, Any]] | None = None,
        context: dict[str, Any] | None = None,
    ) -> ChatResult:
        route = self.router.route(stage)
        if route.fallback is not None and route.model in self._down:
            return self._chat(route.fallback, messages, schema, tools, context or {}, fallback_from=route.model)
        try:
            return self._chat(route, messages, schema, tools, context or {})
        except ModelUnavailable as exc:
            if route.fallback is None:
                raise
            if exc.permanent:
                self._down.add(route.model)  # stay on the fallback for the rest of the run
            return self._chat(route.fallback, messages, schema, tools, context or {}, fallback_from=route.model)

    def forget(self, request_hash: str) -> None:
        """Drop a cached reply that turned out to be unusable."""
        self.cache.delete(request_hash)

    def chat_route(
        self,
        route: Route,
        messages: Sequence[Message],
        *,
        schema: dict[str, Any] | None = None,
        tools: Sequence[dict[str, Any]] | None = None,
        context: dict[str, Any] | None = None,
    ) -> ChatResult:
        """Call one specific route, with no fallback (used by bop doctor --live)."""
        return self._chat(route, messages, schema, tools, context or {})

    # ------------------------------------------------------------------ internals
    def build_request(
        self,
        route: Route,
        messages: Sequence[Message],
        schema: dict[str, Any] | None,
        tools: Sequence[dict[str, Any]] | None,
    ) -> dict[str, Any]:
        request: dict[str, Any] = {
            "model": route.model,
            "messages": list(messages),
            "max_tokens": route.max_tokens,
            "temperature": route.temperature,
            "top_p": route.top_p,
            "extra_body": route.extra_body(),
        }
        if not route.thinking and self._send_reasoning_effort:
            request["extra_body"]["reasoning_effort"] = "none"
        if schema is not None:
            request["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": schema["name"], "schema": schema["schema"], "strict": True},
            }
        if tools:
            request["tools"] = list(tools)
            request["tool_choice"] = "auto"
            request["parallel_tool_calls"] = False
        return request

    def _record(self, result: ChatResult | None, route: Route, context: dict[str, Any], error: str | None) -> None:
        if self.recorder is not None:
            call_id = self.recorder(result, route, context, error)
            if result is not None:
                result.call_id = call_id

    def _chat(
        self,
        route: Route,
        messages: Sequence[Message],
        schema: dict[str, Any] | None,
        tools: Sequence[dict[str, Any]] | None,
        context: dict[str, Any],
        fallback_from: str | None = None,
    ) -> ChatResult:
        """One call, plus a single retry when the reply was cut off at the token limit.

        The retry doubles max_tokens and turns thinking off, because reasoning that eats the token
        budget is the usual cause. Both replies are recorded and cached, so a replay takes the same path.
        """
        result = self._call(route, messages, schema, tools, context, fallback_from)
        if result.finish_reason == "length" and not result.tool_calls and route.max_tokens < MAX_TOKENS_CAP:
            bigger = replace(route, max_tokens=min(route.max_tokens * 2, MAX_TOKENS_CAP), thinking=False)
            return self._call(bigger, messages, schema, tools, context, fallback_from)
        return result

    def _call(
        self,
        route: Route,
        messages: Sequence[Message],
        schema: dict[str, Any] | None,
        tools: Sequence[dict[str, Any]] | None,
        context: dict[str, Any],
        fallback_from: str | None = None,
    ) -> ChatResult:
        request = self.build_request(route, messages, schema, tools)
        key = request_key({**request, "base_url": route.base_url})

        cached = self.cache.get(key)
        if cached is not None:
            result = _deserialise(dict(cached))
            result.cached, result.request_hash, result.fallback_from = True, key, fallback_from
            self._record(result, route, context, None)
            return result
        if self.cache.mode == "read":
            raise ModelOutputError(f"no cached response for stage {route.stage!r} and BOP_CACHE=read")

        estimate = self.prices.cost(route.model, estimate_tokens(json.dumps(request["messages"])), route.max_tokens)
        self.budget.check(estimate)

        started = time.monotonic()
        try:
            response = self._sdk(route.base_url).chat.completions.create(**request)
        except Exception as exc:
            if self._send_reasoning_effort and "reasoning_effort" in request["extra_body"] and _rejects(exc):
                self._send_reasoning_effort = False  # this server does not take it; carry on without
                self._record(None, route, context, f"reasoning_effort rejected, retrying without it: {exc}")
                return self._call(route, messages, schema, tools, context, fallback_from)
            error = self._classify(exc)
            self._record(None, route, context, f"{type(exc).__name__}: {exc}")
            raise error from exc
        latency = int((time.monotonic() - started) * 1000)

        result = self._parse(route, response)
        result.latency_ms = latency
        result.request_hash = key
        result.fallback_from = fallback_from
        result.cost_usd = self.prices.cost(route.model, result.usage.prompt_tokens, result.usage.completion_tokens)
        self.budget.add(result.cost_usd)
        # Every reply is cached, cut-off and empty ones included. Callers answer a bad reply with a
        # different request (the reply plus feedback), so a replay follows the same conversation
        # turn by turn instead of being stuck on it, and BOP_CACHE=read can replay the whole run.
        self.cache.put(key, request, _serialise(result))
        self._record(result, route, context, None)
        return result

    @staticmethod
    def _classify(exc: Exception) -> Exception:
        import openai

        if isinstance(exc, openai.RateLimitError):
            return RateLimited("Token Factory kept rate-limiting requests (429) after retries")
        if isinstance(exc, openai.AuthenticationError):
            return ConfigError("Token Factory rejected the API key (401). Check NEBIUS_API_KEY.")
        if isinstance(exc, openai.APIStatusError):
            if exc.status_code == 402:
                return BudgetExceeded("Token Factory reports the account budget is exhausted (402)")
            if exc.status_code in (404, 409):
                return ModelUnavailable(f"model unavailable ({exc.status_code}): {exc.message}", permanent=True)
            if exc.status_code >= 500:
                return ModelUnavailable(f"Token Factory server error ({exc.status_code}): {exc.message}")
            return ModelOutputError(f"Token Factory error {exc.status_code}: {exc.message}")
        if isinstance(exc, (openai.APIConnectionError, openai.APITimeoutError)):
            return ModelUnavailable(f"could not reach Token Factory: {exc}")
        return exc

    @staticmethod
    def _parse(route: Route, response: Any) -> ChatResult:
        if not getattr(response, "choices", None):
            raise ModelOutputError(f"{route.model} returned no choices")
        choice = response.choices[0]
        message = choice.message
        content, leaked = split_thinking(getattr(message, "content", None))
        reasoning = _reasoning_field(message) or leaked
        calls = [
            ToolCall(tc.id, tc.function.name, parse_arguments(tc.function.arguments))
            for tc in (getattr(message, "tool_calls", None) or [])
        ]
        malformed = False
        if not calls and "<tool_call>" in content:
            calls, content = parse_text_tool_calls(content)
            malformed = not calls
        usage = getattr(response, "usage", None)
        details = getattr(usage, "completion_tokens_details", None) if usage else None
        return ChatResult(
            stage=route.stage,
            role=route.role,
            model=route.model,
            content=content,
            tool_calls=calls,
            usage=Usage(
                prompt_tokens=getattr(usage, "prompt_tokens", 0) or 0,
                completion_tokens=getattr(usage, "completion_tokens", 0) or 0,
                reasoning_tokens=getattr(details, "reasoning_tokens", 0) or 0,
            ),
            finish_reason=getattr(choice, "finish_reason", None),
            malformed_tool_call=malformed,
            reasoning=reasoning,
        )


def _rejects(exc: Exception) -> bool:
    """A 400 that names reasoning_effort: the server does not accept the parameter."""
    status = getattr(exc, "status_code", None)
    return status in (400, 422) and "reasoning_effort" in str(exc)
