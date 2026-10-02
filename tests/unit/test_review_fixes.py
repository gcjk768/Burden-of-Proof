"""Regression tests for the issues found in the first multi-lens review."""

from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import httpx
import openai
import pytest

from bop.cli import main as cli_main
from bop.config import load_settings
from bop.errors import ConfigError, ModelOutputError, RateLimited
from bop.java.maven import Maven, detected_provider
from bop.llm.cache import ResponseCache
from bop.llm.client import ChatResult, TokenFactoryClient
from bop.llm.cost import Budget
from bop.llm.schemas import Edit, Evidence, Patch, TriageBatch
from bop.llm.structured import ask_structured
from bop.llm.toolcalls import ToolCall
from bop.repo.edits import apply_patch
from bop.repo.evidence import strip_java_comments, verify
from bop.repo.snapshot import FileCheckpoint, snapshot
from bop.repo.tools import RepoTools
from bop.runner.base import RunResult
from bop.scanners.sarif import Finding, FindingGroup
from bop.stages.analyze import _investigate, _unfinished
from bop.stages.context import build_conventions, file_block
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


def test_comment_after_a_text_block_is_still_a_comment(tmp_path):
    (tmp_path / "Q.java").write_text(
        'class Q {\n    static final String HELP = """\n        usage \\""" quoted\n        """;'
        " // owner = Integer.parseInt(owner); sanitized upstream\n}\n"
    )
    check = verify(
        tmp_path,
        Evidence(
            role="sanitizer",
            file="Q.java",
            start_line=4,
            end_line=4,
            excerpt="owner = Integer.parseInt(owner); sanitized upstream",
            why="w",
        ),
    )
    assert not check.ok and "comment" in check.problem
    stripped = strip_java_comments((tmp_path / "Q.java").read_text())
    assert "usage" in stripped and "parseInt" not in stripped


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("app.xml", "<bean/>\n<!-- owner = Integer.parseInt(owner) -->\n"),
        ("app.properties", "a=b\n# owner = Integer.parseInt(owner)\n"),
        ("schema.sql", "SELECT 1;\n-- owner = Integer.parseInt(owner)\n"),
    ],
)
def test_comments_in_other_file_types_are_not_evidence(tmp_path, name, text):
    (tmp_path / name).write_text(text)
    check = verify(
        tmp_path,
        Evidence(
            role="sanitizer", file=name, start_line=2, end_line=2, excerpt="owner = Integer.parseInt(owner)", why="w"
        ),
    )
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


class ForgettingReplies(Replies):
    def __init__(self, *results):
        self.results = list(results)
        self.forgotten = []

    def chat(self, stage, messages, *, schema=None, tools=None, context=None):
        item = self.results.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def forget(self, request_hash):
        self.forgotten.append(request_hash)


def result(content, finish="stop", request_hash="h"):
    return ChatResult(
        stage="triage", role="t", model="m", content=content, finish_reason=finish, request_hash=request_hash
    )


@pytest.mark.parametrize(
    "retry",
    [
        result('{"verdicts": [', finish="length", request_hash="h2"),  # cut off
        result("not json", request_hash="h2"),  # malformed
        ModelOutputError("the model returned no choices"),  # no reply at all
    ],
)
def test_a_failed_retry_falls_back_to_the_reply_that_failed_only_soft_checks(retry):
    client = ForgettingReplies(result('{"verdicts": []}', request_hash="h1"), retry)
    batch, call = ask_structured(client, "triage", [], TriageBatch, soft_check=lambda _: ["one excerpt not found"])
    assert batch.verdicts == [] and call.request_hash == "h1"
    assert "h1" not in client.forgotten  # a valid reply stays cached


def test_rejected_replies_stay_cached_and_hard_failures_still_raise():
    client = ForgettingReplies(result("nope", request_hash="h1"), result("still nope", request_hash="h2"))
    with pytest.raises(ModelOutputError):
        ask_structured(client, "triage", [], TriageBatch)
    assert client.forgotten == []  # the retry embeds the rejected reply, so a replay needs both


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
        self.mounts = (list(writable), list(readable))
        return RunResult(list(argv), 0, "", "", 0.1, False, network, "fake")


def test_prepare_resolves_online_without_running_project_tests_and_cleans_up(tmp_path):
    # JUnit only arrives transitively here, so the pom text says nothing about it.
    (tmp_path / "pom.xml").write_text("<artifactId>spring-boot-starter-test</artifactId>")
    runner = FakeRunner()
    Maven(runner, tmp_path / "m2").prepare(tmp_path)
    argv, network, existed = runner.calls[0]
    assert len(runner.calls) == 1
    assert network and existed and "-Dtest=BopWarmupTest" in argv
    assert not (tmp_path / "src").exists()


def test_prepare_refuses_to_overwrite_a_project_file(tmp_path):
    existing = tmp_path / "src/test/java/BopWarmupTest.java"
    existing.parent.mkdir(parents=True)
    existing.write_text("class Mine {}")
    with pytest.raises(FileExistsError):
        Maven(FakeRunner(), tmp_path / "m2").prepare(tmp_path)
    assert existing.read_text() == "class Mine {}"


def test_shared_seed_is_never_writable(tmp_path):
    seed = tmp_path / "seed"
    seed.mkdir()
    runner = FakeRunner()
    maven = Maven(runner, tmp_path / "m2" / "repo-a", seed=seed)
    maven.prepare(tmp_path)
    writable, readable = runner.mounts
    assert writable == [tmp_path / "m2" / "repo-a"] and readable == [seed]
    assert f"-Dmaven.repo.local.tail={seed}" in runner.calls[0][0]
    maven.test(tmp_path)
    writable, readable = runner.mounts
    assert writable == [] and set(readable) == {seed, tmp_path / "m2" / "repo-a"}


def test_each_target_repository_gets_its_own_maven_repository(tmp_path):
    settings = load_settings({"BOP_HOME": str(tmp_path / "home")}, dotenv=None)
    a, b = settings.maven_repo_for(tmp_path / "a"), settings.maven_repo_for(tmp_path / "b")
    assert a != b and a.parent == b.parent == tmp_path / "home" / "m2"
    assert settings.maven_repo_for(tmp_path / "a") == a


def test_detected_provider_drives_the_junit_convention(tmp_path):
    (tmp_path / "pom.xml").write_text("<artifactId>spring-boot-starter-test</artifactId>")
    output = "[INFO] Using auto detected provider org.apache.maven.surefire.junitplatform.JUnitPlatformProvider\n"
    assert build_conventions(tmp_path, detected_provider(output))["junit"].startswith("JUnit 5")
    output = "[INFO] Using auto detected provider org.apache.maven.surefire.junit4.provider.JUnit4Provider\n"
    assert build_conventions(tmp_path, detected_provider(output))["junit"].startswith("JUnit 4")
    assert detected_provider("no provider line") is None


# ---------------------------------------------------------------- investigation guards
def test_unfinished_investigation_turns_are_caught():
    def r(**kw):
        return ChatResult(stage="analyze", role="r", model="m", **{"content": "notes", **kw})

    assert _unfinished(r()) is None
    assert "cut off" in _unfinished(r(finish_reason="length"))
    assert "could not be parsed" in _unfinished(r(malformed_tool_call=True))
    assert "empty" in _unfinished(r(content="  "))


class AlwaysTools:
    """Calls a tool on every turn that offers tools, then cuts off the forced conclusion."""

    def __init__(self, final_replies):
        self.final_replies = list(final_replies)
        self.final_calls = 0

    def chat(self, stage, messages, *, tools=None, context=None, schema=None):
        if tools:
            call = ToolCall(id="c", name="list_files", arguments={"glob": "**/*.java"})
            return ChatResult(stage=stage, role="r", model="m", content="", tool_calls=[call])
        self.final_calls += 1
        content, finish = self.final_replies.pop(0)
        return ChatResult(stage=stage, role="r", model="m", content=content, finish_reason=finish)


def investigation_ctx(repo, llm):
    return SimpleNamespace(workdir=repo, tools=RepoTools(repo), llm=llm)


def test_cut_off_forced_conclusion_is_retried_then_rejected(repo):
    llm = AlwaysTools([("The input flows from id into s.execute; however the caller at", "length")] * 2)
    with pytest.raises(ModelOutputError, match="without a usable conclusion"):
        _investigate(investigation_ctx(repo, llm), FindingGroup("G1", "sql_injection", [f("b", 4, SRC)]), None)
    assert llm.final_calls == 2


def test_forced_conclusion_retry_can_recover(repo):
    llm = AlwaysTools([("cut", "length"), ("The query is built from a constant; not reachable.", "stop")])
    notes, _ = _investigate(investigation_ctx(repo, llm), FindingGroup("G1", "sql_injection", [f("b", 4, SRC)]), None)
    assert notes.startswith("The query is built from a constant")


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


def test_a_read_only_replay_follows_the_recorded_retry_chain(settings):
    from bop.llm.schemas import ProofTest

    good = (
        '{"test_path": "src/test/java/a/PTest.java", "test_class": "a.PTest", "test_method": "t", '
        '"source": "s", "setup_notes": ""}'
    )
    recording, calls = client_with(settings, [reply('{"test_path": ', finish="length"), reply(good)])
    first, _ = ask_structured(recording, "prove", [{"role": "user", "content": "x"}], ProofTest)
    assert len(calls) == 2
    files = sorted(settings.cache_dir.rglob("*.json"))
    replay, replay_calls = client_with(settings, [], cache_mode="read")
    second, _ = ask_structured(replay, "prove", [{"role": "user", "content": "x"}], ProofTest)
    assert second == first and replay_calls == []  # both turns, the cut-off one included, came from the cache
    assert sorted(settings.cache_dir.rglob("*.json")) == files


def test_a_read_only_cache_never_deletes(settings):
    recording, _ = client_with(settings, [reply("first")])
    first = recording.chat("triage", [{"role": "user", "content": "same"}])
    replay, _ = client_with(settings, [], cache_mode="read")
    replay.forget(first.request_hash)
    assert replay.chat("triage", [{"role": "user", "content": "same"}]).content == "first"


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


@pytest.mark.parametrize(
    "transient", [error(openai.RateLimitError, 429), error(openai.InternalServerError, 502)], ids=["429", "502"]
)
def test_transient_errors_do_not_pin_the_run_to_the_fallback(settings, transient):
    client, calls = client_with(settings, [transient, reply("a"), reply("b")], "off")
    if isinstance(transient, openai.RateLimitError):
        with pytest.raises(RateLimited):  # the fallback shares the account's limits; stop instead
            client.chat("analyze", [{"role": "user", "content": "1"}])
        assert calls == ["nvidia/Nemotron-3-Ultra-550b-a55b"]
        return
    client.chat("analyze", [{"role": "user", "content": "1"}])  # this one call falls back
    client.chat("analyze", [{"role": "user", "content": "2"}])  # the next tries Ultra again
    assert calls == [
        "nvidia/Nemotron-3-Ultra-550b-a55b",
        "nvidia/nemotron-3-super-120b-a12b",
        "nvidia/Nemotron-3-Ultra-550b-a55b",
    ]


def test_fallback_sticks_for_the_rest_of_the_run(settings):
    client, calls = client_with(settings, [error(openai.ConflictError, 409), reply("a"), reply("b")], "off")
    client.chat("analyze", [{"role": "user", "content": "1"}])
    client.chat("analyze", [{"role": "user", "content": "2"}])
    assert calls == [
        "nvidia/Nemotron-3-Ultra-550b-a55b",
        "nvidia/nemotron-3-super-120b-a12b",
        "nvidia/nemotron-3-super-120b-a12b",
    ]


# ---------------------------------------------------------------- second verification pass
def proof_for(path="src/test/java/com/PwnTest.java", cls="com.PwnTest"):
    from bop.llm.schemas import ProofTest

    source = 'package com;\nclass PwnTest { @Test void t() { fail("[BOP-PROOF] x"); } }'
    return ProofTest(test_path=path, test_class=cls, test_method="t", source=source)


def test_a_symlinked_test_directory_cannot_send_a_proof_test_into_production_code(repo):
    from bop.repo.edits import place_proof_test

    (repo / "src/main/java/com").mkdir(parents=True)
    (repo / "src/test/java/com").symlink_to(repo / "src/main/java/com")
    placement = place_proof_test(repo, proof_for(), "[BOP-PROOF]")
    assert placement.path is None and "src/test/java" in placement.problems[0]


def test_rewriting_a_proof_test_refuses_a_swapped_in_symlink(repo):
    from bop.repo.edits import write_proof_test
    from bop.repo.paths import PathEscape

    target = repo / SRC
    before = target.read_text()
    (repo / "src/test/java/a/PTest.java").symlink_to(target)
    with pytest.raises((PathEscape, OSError)):
        write_proof_test(repo, "src/test/java/a/PTest.java", "class PTest {}")
    assert target.read_text() == before


def test_mixed_line_endings_match_as_written(tmp_path):
    root = tmp_path
    (root / "src/main/java/a").mkdir(parents=True)
    path = root / SRC
    path.write_bytes(b"// Copyright\r\npackage a;\nclass A {\n    int x = 1;\n}\n")
    patch = Patch(
        edits=[Edit(file=SRC, search="class A {\n    int x = 1;", replace="class A {\n    int x = 2;")], explanation="e"
    )
    applied = apply_patch(root, patch, FileCheckpoint(root))
    assert applied.ok, applied.problems
    assert path.read_bytes() == b"// Copyright\r\npackage a;\nclass A {\n    int x = 2;\n}\n"


def test_removing_a_different_identical_line_is_not_a_fix(tmp_path):
    from bop.repo.edits import AppliedPatch

    before = "\n".join(["a", "b", "c", "d", "sink(x);", "e", "f", "g", "h", "sink(x);", "i"]) + "\n"
    after = before.replace("h\nsink(x);\n", "h\n")  # the patch removed line 10, not the group's line 5
    applied = AppliedPatch(files=["Q.java"], before={"Q.java": before}, after={"Q.java": after})
    member = f("b", 5)
    remaining = [f("b", 5)]  # the rescan still reports line 5
    still, _ = rescan_verdict(
        Counter({"b": 2}), Counter({"b": 1}), remaining, ["Q.java"], members=[member], line_map=applied.map_line
    )
    assert [x.start_line for x in still] == [5]
    # Fixing line 5 itself (which shifts nothing) is still a fix.
    fixed_after = before.replace("d\nsink(x);\n", "d\nsafe(x);\n")
    applied = AppliedPatch(files=["Q.java"], before={"Q.java": before}, after={"Q.java": fixed_after})
    still, _ = rescan_verdict(
        Counter({"b": 2}), Counter({"b": 1}), [f("b", 10)], ["Q.java"], members=[member], line_map=applied.map_line
    )
    assert still == []


EVIDENCE_FILE = '''class A {
    String q(String id) {
        String sql = "SELECT * FROM t WHERE id = " + id; // TODO
        // build the statement
        return sql;
    }
    static final String HELP = """
        see http://example.com
        """; // String id = sanitize(id); is safe
    Object r() {
        return repo.find(
            query,
            100
        );
    }
}
'''


@pytest.mark.parametrize(
    ("start", "end", "excerpt", "ok"),
    [
        (3, 3, 'String sql = "SELECT * FROM t WHERE id = " + id; // TODO', True),  # exact copy with its comment
        (
            3,
            5,
            'String sql = "SELECT * FROM t WHERE id = " + id; // TODO\n        // build the statement\n'
            "        return sql;",
            True,
        ),  # spans a comment line
        (8, 8, "see http://example.com", True),  # text-block content is not a comment
        (11, 14, "return repo.find(\n        query,\n        100\n    );", True),  # numbers at line starts
        (9, 9, "String id = sanitize(id); is safe", False),  # a comment after a text block
        (4, 4, "// build the statement", False),  # nothing but a comment
        (3, 3, "x; // String id = sanitize(id);", False),  # no real code left once the comment goes
    ],
)
def test_evidence_counts_the_code_part_of_an_excerpt(tmp_path, start, end, excerpt, ok):
    (tmp_path / "A.java").write_text(EVIDENCE_FILE)
    check = verify(
        tmp_path, Evidence(role="sink", file="A.java", start_line=start, end_line=end, excerpt=excerpt, why="w")
    )
    assert check.ok is ok, check.problem
    if ok:
        assert "TODO" not in (check.code or "") and "build the statement" not in (check.code or "")
