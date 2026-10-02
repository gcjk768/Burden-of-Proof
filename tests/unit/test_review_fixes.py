"""Regression tests for the issues found in the first multi-lens review."""

from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import httpx
import openai
import pytest

from bop.cli import main as cli_main
from bop.errors import ConfigError, RateLimited
from bop.java.maven import Maven
from bop.llm.cache import ResponseCache
from bop.llm.client import ChatResult, TokenFactoryClient
from bop.llm.cost import Budget
from bop.llm.schemas import Edit, Evidence, Patch, TriageBatch
from bop.llm.structured import ask_structured
from bop.repo.edits import apply_patch
from bop.repo.evidence import strip_java_comments, verify
from bop.repo.snapshot import FileCheckpoint, snapshot
from bop.repo.tools import RepoTools
from bop.runner.base import RunResult
from bop.scanners.sarif import Finding
from bop.stages.analyze import _unfinished
from bop.stages.context import file_block
from bop.stages.fix import rescan_verdict

SRC = "src/main/java/a/A.java"


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "src/main/java/a").mkdir(parents=True)
    (tmp_path / SRC).write_text("package a;\n// String sql = owner; is fine\nclass A {\n    int x = 1;\n}\n")
    (tmp_path / "src/test/java/a").mkdir(parents=True)
    (tmp_path / "src/test/java/a/ATest.java").write_text("package a; class ATest {}")
    (tmp_path / "pom.xml").write_text("<project/>")
    return tmp_path


# ---------------------------------------------------------------- patch policy uses the resolved path
@pytest.mark.parametrize("target", ["src/main/../test/java/a/ATest.java", "src/main/../../pom.xml", "./src/test/x"])
def test_dot_dot_paths_cannot_leave_src_main(repo, target):
    if target.endswith("pom.xml"):
        search = "<project/>"
    elif "ATest" in target:
        search = "class ATest"
    else:
        search = "x"
    applied = apply_patch(
        repo, Patch(edits=[Edit(file=target, search=search, replace="y")], explanation="e"), FileCheckpoint(repo)
    )
    assert not applied.ok
    assert (repo / "src/test/java/a/ATest.java").read_text() == "package a; class ATest {}"
    assert (repo / "pom.xml").read_text() == "<project/>"


# ---------------------------------------------------------------- encodings and line endings
def test_crlf_files_keep_their_line_endings(repo):
    (repo / SRC).write_bytes(b"package a;\r\nclass A {\r\n    int x = 1;\r\n}\r\n")
    patch = Patch(
        edits=[Edit(file=SRC, search="class A {\n    int x = 1;", replace="class A {\n    int x = 2;")], explanation="e"
    )
    applied = apply_patch(repo, patch, FileCheckpoint(repo))
    assert applied.ok
    assert (repo / SRC).read_bytes() == b"package a;\r\nclass A {\r\n    int x = 2;\r\n}\r\n"


def test_non_utf8_files_are_refused_not_crashed(repo):
    (repo / SRC).write_bytes('class A { String s = "caf\xe9"; }'.encode("latin-1"))
    applied = apply_patch(
        repo,
        Patch(edits=[Edit(file=SRC, search="class", replace="final class")], explanation="e"),
        FileCheckpoint(repo),
    )
    assert not applied.ok and "not UTF-8" in applied.problems[0]


# ---------------------------------------------------------------- rescan counts duplicates correctly
def f(base, line, file="Q.java", in_scope=True):
    return Finding(
        id=f"F{line}",
        tool="t",
        rule_id="r",
        category="sql_injection",
        cwe=None,
        severity="high",
        file=file,
        start_line=line,
        end_line=line,
        message="",
        snippet="s",
        fingerprint=f"{base}-{line}",
        in_scope=in_scope,
        base_fingerprint=base,
    )


def test_fixing_the_first_of_two_identical_lines_counts_as_fixed():
    initial = Counter({"dup": 2})
    still, new = rescan_verdict(initial, Counter({"dup": 1}), [f("dup", 10)], ["Q.java"])
    assert still == [] and new == []


def test_unfixed_duplicate_is_still_reported():
    still, _ = rescan_verdict(Counter({"dup": 2}), Counter({"dup": 1}), [f("dup", 5), f("dup", 10)], ["Q.java"])
    assert len(still) == 2


def test_new_findings_only_count_in_edited_files():
    initial = Counter({"g": 1})
    _, new = rescan_verdict(initial, Counter({"g": 1}), [f("other", 3)], ["Q.java"])
    assert [x.base_fingerprint for x in new] == ["other"]
    _, new = rescan_verdict(initial, Counter({"g": 1}), [f("other", 3, file="Elsewhere.java")], ["Q.java"])
    assert new == []


# ---------------------------------------------------------------- evidence: gutters and comments
def ev(line, excerpt):
    return Evidence(role="sink", file=SRC, start_line=line, end_line=line, excerpt=excerpt, why="w")


def test_evidence_copied_with_line_number_gutter_still_matches(repo):
    assert verify(repo, ev(4, "    4      int x = 1;")).ok


def test_evidence_inside_a_comment_is_not_verified(repo):
    check = verify(repo, ev(2, "String sql = owner;"))
    assert not check.ok and "comment" in check.problem


def test_comment_stripper_keeps_strings_and_lines():
    text = "a = \"http://x\"; // tail\n/* one\ntwo */ b = '/';"
    stripped = strip_java_comments(text)
    assert '"http://x"' in stripped and "tail" not in stripped and "one" not in stripped
    assert stripped.count("\n") == text.count("\n") and "b = '/'" in stripped


# ---------------------------------------------------------------- soft checks never sink a valid reply
class Replies:
    def __init__(self, *contents):
        self.contents = list(contents)

    def chat(self, stage, messages, *, schema=None, tools=None, context=None):
        return ChatResult(stage=stage, role="t", model="m", content=self.contents.pop(0))


def test_soft_problems_get_one_retry_then_the_reply_is_accepted():
    reply = '{"verdicts": []}'
    batch, _ = ask_structured(Replies(reply, reply), "triage", [], TriageBatch, soft_check=lambda _: ["bad excerpt"])
    assert batch.verdicts == []


# ---------------------------------------------------------------- tools never crash the run
@pytest.mark.parametrize(
    ("name", "args"),
    [
        ("list_files", {"glob": ""}),
        ("list_files", {"glob": None}),
        ("list_files", {"glob": "/etc/*"}),
        ("list_files", {"glob": "../*"}),
        ("search_code", {"pattern": "x", "glob": "/etc/*"}),
        ("read_file", {"path": SRC, "start_line": "x"}),
        ("read_file", {"path": SRC, "nope": 1}),
    ],
)
def test_bad_tool_arguments_return_errors(repo, name, args):
    result = RepoTools(repo).call(name, args)
    assert isinstance(result, str)
    if name != "list_files" or args["glob"] not in ("", None):
        assert result.startswith("error:")


def test_file_block_refuses_paths_outside_the_snapshot(repo, tmp_path_factory):
    outside = tmp_path_factory.mktemp("o") / "secret.txt"
    outside.write_text("secret")
    assert file_block(repo, "../" * 10 + str(outside).lstrip("/")) == ""
    assert file_block(repo, str(outside)) == ""
    assert "class A" in file_block(repo, SRC)


# ---------------------------------------------------------------- snapshot
def test_snapshot_keeps_packages_named_build_and_skips_symlinks(repo, tmp_path_factory):
    (repo / "src/main/java/a/build").mkdir()
    (repo / "src/main/java/a/build/B.java").write_text("package a.build; class B {}")
    (repo / "target").mkdir()
    (repo / "target/junk.txt").write_text("x")
    secret = tmp_path_factory.mktemp("host") / "id_rsa"
    secret.write_text("PRIVATE KEY")
    (repo / "src/main/resources").mkdir()
    (repo / "src/main/resources/key").symlink_to(secret)
    dest = tmp_path_factory.mktemp("snap") / "work"
    snapshot(repo, dest)
    assert (dest / "src/main/java/a/build/B.java").exists()
    assert not (dest / "target").exists()
    assert not (dest / "src/main/resources/key").exists()


def test_snapshot_of_a_non_maven_directory_is_a_config_error(tmp_path):
    with pytest.raises(ConfigError):
        snapshot(tmp_path, tmp_path / "out")


def test_cli_reports_non_maven_path_without_traceback(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("BOP_HOME", str(tmp_path / "home"))
    assert cli_main(["run", str(tmp_path)]) == 2
    assert "no pom.xml" in capsys.readouterr().err


# ---------------------------------------------------------------- Maven warm-up for projects without tests
class FakeRunner:
    name = "fake"

    def __init__(self):
        self.calls = []

    def run(self, argv, *, cwd, timeout_s, network=False, env=None, writable=(), readable=()):
        self.calls.append((list(argv), network, (Path(cwd) / "src/test/java/BopWarmupTest.java").exists()))
        return RunResult(list(argv), 0, "", "", 0.1, False, network, "fake")


def test_warm_up_runs_once_online_and_cleans_up(tmp_path):
    (tmp_path / "pom.xml").write_text("<artifactId>junit-jupiter</artifactId>")
    runner = FakeRunner()
    Maven(runner, tmp_path / "m2").warm_test_provider(tmp_path)
    argv, network, existed = runner.calls[0]
    assert network and existed and "-Dtest=BopWarmupTest" in argv
    assert not (tmp_path / "src").exists()


# ---------------------------------------------------------------- investigation guards
def test_unfinished_investigation_turns_are_caught():
    def r(**kw):
        return ChatResult(stage="analyze", role="r", model="m", **{"content": "notes", **kw})

    assert _unfinished(r()) is None
    assert "cut off" in _unfinished(r(finish_reason="length"))
    assert "could not be parsed" in _unfinished(r(malformed_tool_call=True))
    assert "empty" in _unfinished(r(content="  "))


# ---------------------------------------------------------------- client: caching, rate limits, sticky fallback
def reply(content="{}", finish="stop"):
    usage = SimpleNamespace(prompt_tokens=10, completion_tokens=5, completion_tokens_details=None)
    message = SimpleNamespace(content=content, tool_calls=None)
    return SimpleNamespace(choices=[SimpleNamespace(message=message, finish_reason=finish)], usage=usage)


def error(cls, code):
    request = httpx.Request("POST", "https://x/v1/chat/completions")
    return cls("boom", response=httpx.Response(code, request=request), body=None)


def client_with(settings, replies, cache_mode="readwrite"):
    calls = []

    class SDK:
        def __init__(self, base_url):
            self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

        def create(self, **request):
            calls.append(request["model"])
            item = replies.pop(0)
            if isinstance(item, Exception):
                raise item
            return item

    client = TokenFactoryClient(
        settings, cache=ResponseCache(settings.cache_dir, cache_mode), budget=Budget(5), sdk_factory=SDK
    )
    return client, calls


def test_truncated_replies_are_not_cached(settings):
    client, calls = client_with(settings, [reply('{"a": ', finish="length"), reply('{"a": 1}')])
    messages = [{"role": "user", "content": "same"}]
    client.chat("triage", messages)
    assert client.chat("triage", messages).content == '{"a": 1}' and len(calls) == 2


def test_forget_drops_a_cached_reply(settings):
    client, _ = client_with(settings, [reply("first"), reply("second")])
    messages = [{"role": "user", "content": "same"}]
    first = client.chat("triage", messages)
    client.forget(first.request_hash)
    assert client.chat("triage", messages).content == "second"


def test_rate_limit_is_its_own_error(settings):
    client, _ = client_with(settings, [error(openai.RateLimitError, 429)], cache_mode="off")
    with pytest.raises(RateLimited):
        client.chat("triage", [{"role": "user", "content": "x"}])


def test_fallback_sticks_for_the_rest_of_the_run(settings):
    client, calls = client_with(settings, [error(openai.ConflictError, 409), reply("a"), reply("b")], "off")
    client.chat("analyze", [{"role": "user", "content": "1"}])
    client.chat("analyze", [{"role": "user", "content": "2"}])
    assert calls == [
        "nvidia/Nemotron-3-Ultra-550b-a55b",
        "nvidia/nemotron-3-super-120b-a12b",
        "nvidia/nemotron-3-super-120b-a12b",
    ]
