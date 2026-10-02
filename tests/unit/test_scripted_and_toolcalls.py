import pytest

from bop.errors import ModelOutputError
from bop.llm.fake import ScriptedClient
from bop.llm.toolcalls import parse_text_tool_calls


def test_scripted_triage_answers_each_finding():
    client = ScriptedClient({"replies": [{"stage": "triage", "verdicts": {"A:1": {"verdict": "likely_real"}}}]})
    result = client.chat("triage", [], context={"findings": [{"id": "G-1", "key": "A:1"}]})
    assert '"finding_id": "G-1"' in result.content


def test_scripted_turns_in_order_and_placeholders():
    client = ScriptedClient(
        {
            "replies": [
                {
                    "stage": "analyze_verdict",
                    "match": {"key": "A:1"},
                    "turns": [{"json": {"finding_id": "{finding_id}"}}, {"content": "two"}],
                }
            ]
        }
    )
    first = client.chat("analyze_verdict", [], context={"key": "A:1", "finding_id": "G-9"})
    assert first.content == '{"finding_id": "G-9"}'
    assert client.chat("analyze_verdict", [], context={"key": "A:1"}).content == "two"
    with pytest.raises(ModelOutputError):
        client.chat("analyze_verdict", [], context={"key": "A:1"})


def test_text_tool_call_formats():
    xml = "<tool_call><function=search_code><parameter=pattern>a.b</parameter></function></tool_call> tail"
    calls, rest = parse_text_tool_calls(xml)
    assert calls[0].name == "search_code" and calls[0].arguments == {"pattern": "a.b"} and rest == "tail"
    js = '<tool_call>{"name": "read_file", "arguments": {"path": "x", "start_line": 3}}</tool_call>'
    calls, _ = parse_text_tool_calls(js)
    assert calls[0].arguments == {"path": "x", "start_line": 3}
    assert parse_text_tool_calls("<tool_call>not json</tool_call>")[0] == []
