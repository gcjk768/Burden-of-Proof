"""TokenFactoryClient against a fake OpenAI SDK: routing, thinking switch, cost, cache, budget, fallback."""

from types import SimpleNamespace

import httpx
import openai
import pytest

from bop.errors import BudgetExceeded, ConfigError, ModelOutputError
from bop.llm.cache import ResponseCache
from bop.llm.client import TokenFactoryClient, strip_thinking
from bop.llm.cost import Budget


def response(content="{}", tool_calls=None, prompt=1000, completion=200, reasoning=0, finish="stop"):
    message = SimpleNamespace(content=content, tool_calls=tool_calls)
    usage = SimpleNamespace(
        prompt_tokens=prompt,
        completion_tokens=completion,
        completion_tokens_details=SimpleNamespace(reasoning_tokens=reasoning),
    )
    return SimpleNamespace(choices=[SimpleNamespace(message=message, finish_reason=finish)], usage=usage)


class FakeSDK:
    def __init__(self, base_url, replies):
        self.base_url, self.replies, self.requests = base_url, replies, []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    def create(self, **request):
        self.requests.append(request)
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply


def make_client(settings, replies, *, cache_mode="off", budget=5.0):
    sdks = {}

    def factory(base_url):
        sdks[base_url] = FakeSDK(base_url, replies)
        return sdks[base_url]

    client = TokenFactoryClient(
        settings, cache=ResponseCache(settings.cache_dir, cache_mode), budget=Budget(budget), sdk_factory=factory
    )
    return client, sdks


def status_error(code, message="boom"):
    request = httpx.Request("POST", "https://api.example/v1/chat/completions")
    resp = httpx.Response(code, request=request, json={"detail": "x"})
    cls = {
        400: openai.BadRequestError,
        401: openai.AuthenticationError,
        409: openai.ConflictError,
        404: openai.NotFoundError,
    }.get(code, openai.APIStatusError)
    return cls(message, response=resp, body=None)


def test_triage_request_turns_thinking_off_and_uses_json_schema(settings):
    client, sdks = make_client(settings, [response('{"verdicts": []}')])
    schema = {"name": "TriageBatch", "schema": {"type": "object"}}
    result = client.chat("triage", [{"role": "user", "content": "hi"}], schema=schema)
    request = next(iter(sdks.values())).requests[0]
    assert request["model"] == "nvidia/Nemotron-3_5-Lightning"
    assert request["extra_body"] == {"chat_template_kwargs": {"enable_thinking": False}, "reasoning_effort": "none"}
    assert request["response_format"]["type"] == "json_schema"
    assert "tools" not in request
    # Lightning is $0.06 in / $0.24 out per million tokens
    assert result.cost_usd == pytest.approx((1000 * 0.06 + 200 * 0.24) / 1e6)


def test_analysis_turns_thinking_on_and_sends_tools(settings):
    client, sdks = make_client(settings, [response("notes")])
    client.chat("analyze", [{"role": "user", "content": "x"}], tools=[{"type": "function", "function": {}}])
    request = next(iter(sdks.values())).requests[0]
    assert request["model"] == "nvidia/Nemotron-3-Ultra-550b-a55b"
    assert request["extra_body"]["chat_template_kwargs"]["enable_thinking"] is True
    assert "reasoning_effort" not in request["extra_body"]
    assert request["parallel_tool_calls"] is False


def test_api_key_never_appears_in_the_request(settings):
    client, sdks = make_client(settings, [response()])
    client.chat("triage", [{"role": "user", "content": "x"}])
    assert "test-key-not-real" not in repr(next(iter(sdks.values())).requests)


def test_cache_hit_is_free_and_skips_the_api(settings):
    client, sdks = make_client(settings, [response("cached!")], cache_mode="readwrite")
    messages = [{"role": "user", "content": "same"}]
    first = client.chat("triage", messages)
    second = client.chat("triage", messages)
    assert not first.cached and second.cached
    assert second.content == "cached!" and second.cost_usd == 0
    assert len(next(iter(sdks.values())).requests) == 1


def test_read_only_cache_refuses_to_spend(settings):
    client, _ = make_client(settings, [response()], cache_mode="read")
    with pytest.raises(ModelOutputError):
        client.chat("triage", [{"role": "user", "content": "never seen"}])


def test_budget_is_checked_before_calling(settings):
    client, sdks = make_client(settings, [response()], budget=0.000001)
    with pytest.raises(BudgetExceeded):
        client.chat("analyze", [{"role": "user", "content": "x" * 3000}])
    assert not any(s.requests for s in sdks.values())


def test_ultra_failure_falls_back_to_super(settings):
    client, _ = make_client(settings, [status_error(409), response("from super")])
    result = client.chat("analyze", [{"role": "user", "content": "x"}])
    assert result.model == "nvidia/nemotron-3-super-120b-a12b"
    assert result.fallback_from == "nvidia/Nemotron-3-Ultra-550b-a55b"


def test_bad_key_is_a_config_error(settings):
    client, _ = make_client(settings, [status_error(401)])
    with pytest.raises(ConfigError):
        client.chat("triage", [{"role": "user", "content": "x"}])


def test_leaked_tool_calls_in_text_are_recovered(settings):
    text = "<tool_call>\n<function=read_file>\n<parameter=path>\nA.java\n</parameter>\n</function>\n</tool_call>"
    client, _ = make_client(settings, [response(text)])
    result = client.chat("analyze", [{"role": "user", "content": "x"}])
    assert [(c.name, c.arguments, c.from_text) for c in result.tool_calls] == [("read_file", {"path": "A.java"}, True)]


def test_native_tool_calls_are_parsed(settings):
    call = SimpleNamespace(id="c1", function=SimpleNamespace(name="search_code", arguments='{"pattern": "x"}'))
    client, _ = make_client(settings, [response(None, tool_calls=[call])])
    result = client.chat("analyze", [{"role": "user", "content": "x"}])
    assert result.tool_calls[0].arguments == {"pattern": "x"}
    assert result.assistant_message()["tool_calls"][0]["id"] == "c1"


def test_strip_thinking():
    assert strip_thinking("<think>hmm</think>\n{}") == "{}"
    assert strip_thinking("reasoning...</think>answer") == "answer"
    assert strip_thinking(None) == ""


def test_a_server_that_rejects_reasoning_effort_is_retried_without_it(settings):
    rejected = status_error(400, "Unrecognized request argument supplied: reasoning_effort")
    client, sdks = make_client(settings, [rejected, response("{}"), response("{}")])
    client.chat("triage", [{"role": "user", "content": "1"}])
    client.chat("triage", [{"role": "user", "content": "2"}])
    requests = next(iter(sdks.values())).requests
    assert "reasoning_effort" in requests[0]["extra_body"]
    assert "reasoning_effort" not in requests[1]["extra_body"] and "reasoning_effort" not in requests[2]["extra_body"]


def test_other_bad_requests_are_not_retried(settings):
    client, sdks = make_client(settings, [status_error(400, "messages: field required")])
    with pytest.raises(ModelOutputError):
        client.chat("triage", [{"role": "user", "content": "1"}])
    assert len(next(iter(sdks.values())).requests) == 1


def test_a_cut_off_reply_is_retried_once_with_more_tokens_and_thinking_off(settings):
    client, sdks = make_client(settings, [response('{"a": ', finish="length"), response('{"a": 1}')])
    result = client.chat("prove", [{"role": "user", "content": "x"}])
    first, second = next(iter(sdks.values())).requests
    assert result.content == '{"a": 1}'
    assert second["max_tokens"] == 2 * first["max_tokens"]
    assert first["extra_body"]["chat_template_kwargs"]["enable_thinking"] is True
    assert second["extra_body"]["chat_template_kwargs"]["enable_thinking"] is False


def test_a_reply_cut_off_twice_is_returned_as_cut_off(settings):
    client, sdks = make_client(settings, [response("a", finish="length"), response("ab", finish="length")])
    result = client.chat("prove", [{"role": "user", "content": "x"}])
    assert result.finish_reason == "length" and len(next(iter(sdks.values())).requests) == 2


def test_reasoning_is_kept_from_the_separate_field_or_leaked_tags(settings):
    separate = response("answer")
    separate.choices[0].message.model_extra = {"reasoning_content": "because X"}
    leaked = response("<think>because Y</think>answer")
    client, _ = make_client(settings, [separate, leaked])
    first = client.chat("triage", [{"role": "user", "content": "1"}])
    second = client.chat("triage", [{"role": "user", "content": "2"}])
    assert (first.content, first.reasoning) == ("answer", "because X")
    assert (second.content, second.reasoning) == ("answer", "because Y")
