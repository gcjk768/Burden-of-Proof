import pytest

from bop.errors import ModelOutputError
from bop.llm.client import ChatResult
from bop.llm.schemas import Patch
from bop.llm.structured import ask_structured, extract_json


class Replies:
    def __init__(self, *contents):
        self.contents = list(contents)
        self.seen = []

    def chat(self, stage, messages, *, schema=None, tools=None, context=None):
        self.seen.append(list(messages))
        return ChatResult(stage=stage, role="t", model="m", content=self.contents.pop(0))


GOOD = '{"edits": [{"file": "a", "search": "b", "replace": "c"}], "explanation": "e"}'


def test_extract_json_handles_fences_and_prose():
    assert extract_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert extract_json('Sure: {"a": 2} done') == {"a": 2}


def test_retries_once_with_the_problems():
    client = Replies('{"edits": []}', GOOD)
    patch, _ = ask_structured(client, "fix", [{"role": "user", "content": "x"}], Patch)
    assert patch.edits[0].file == "a"
    assert "rejected" in client.seen[1][-1]["content"]


def test_custom_check_failure_is_fed_back():
    client = Replies(GOOD, GOOD)
    calls = []

    def check(p):
        calls.append(p)
        return ["first try is never good enough"] if len(calls) == 1 else []

    ask_structured(client, "fix", [], Patch, check=check)
    assert "never good enough" in client.seen[1][-1]["content"]


def test_gives_up_after_retries():
    with pytest.raises(ModelOutputError):
        ask_structured(Replies("nope", "still nope"), "fix", [], Patch)
