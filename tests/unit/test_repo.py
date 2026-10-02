"""Path confinement, repository tools, evidence checks and the patch/test placement policy."""

import os

import pytest

from bop.llm.schemas import Edit, Evidence, Patch, ProofTest
from bop.repo.edits import apply_patch, place_proof_test
from bop.repo.evidence import verify
from bop.repo.paths import PathEscape, confined
from bop.repo.snapshot import FileCheckpoint, remove_file_and_empty_parents
from bop.repo.tools import RepoTools

SRC = "src/main/java/a/Repo.java"
CODE = """package a;

public class Repo {
    String find(String owner) {
        String sql = "SELECT * FROM t WHERE o = '" + owner + "'";
        return sql;
    }
}
"""


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "src/main/java/a").mkdir(parents=True)
    (tmp_path / SRC).write_text(CODE)
    (tmp_path / "src/test/java/a").mkdir(parents=True)
    (tmp_path / "src/test/java/a/RepoTest.java").write_text("package a; class RepoTest {}")
    return tmp_path


@pytest.mark.parametrize("bad", ["../etc/passwd", "/etc/passwd", "src/../../x", ""])
def test_confined_rejects_escapes(repo, bad):
    with pytest.raises(PathEscape):
        confined(repo, bad)


def test_confined_rejects_symlink_escape(repo, tmp_path_factory):
    outside = tmp_path_factory.mktemp("outside")
    (outside / "secret").write_text("x")
    os.symlink(outside, repo / "link")
    with pytest.raises(PathEscape):
        confined(repo, "link/secret")


def test_tools_read_search_and_refuse_escape(repo):
    tools = RepoTools(repo)
    assert "    5  " in tools.read_file(SRC)
    assert f"{SRC}:5:" in tools.search_code(r"SELECT")
    assert "Repo.java" in tools.find_symbol("Repo")
    assert tools.call("read_file", {"path": "../x"}).startswith("error:")
    assert tools.call("nope", {}).startswith("error:")
    assert "invalid regular expression" in tools.search_code("(")


def ev(line, excerpt, file=SRC):
    return Evidence(role="sink", file=file, start_line=line, end_line=line, excerpt=excerpt, why="w")


def test_evidence_exact_and_slack(repo):
    assert verify(repo, ev(5, 'String sql = "SELECT * FROM t WHERE o = \'" + owner + "\'";')).ok
    shifted = verify(repo, ev(3, "String sql ="))  # two lines off
    assert shifted.ok and shifted.start_line == 5


def test_evidence_rejects_invented_code_and_bad_paths(repo):
    assert not verify(repo, ev(5, "executeQuery(sql)")).ok
    assert not verify(repo, ev(99, "x")).ok
    assert not verify(repo, ev(1, "x", file="../../etc/passwd")).ok
    assert not verify(repo, ev(1, "x", file="src/missing.java")).ok


def patch(*edits):
    return Patch(edits=[Edit(file=f, search=s, replace=r) for f, s, r in edits], explanation="e")


def test_apply_patch_and_restore(repo):
    cp = FileCheckpoint(repo)
    applied = apply_patch(repo, patch((SRC, "return sql;", "return sql.trim();")), cp)
    assert applied.ok and applied.files == [SRC] and "+        return sql.trim();" in applied.diff
    assert "trim()" in (repo / SRC).read_text()
    cp.restore()
    assert (repo / SRC).read_text() == CODE


@pytest.mark.parametrize(
    ("edit", "message"),
    [
        ((SRC, "not there", "x"), "occurs 0 times"),
        ((SRC, "String", "x"), "occurs 3 times"),
        (("src/test/java/a/RepoTest.java", "class", "x"), "outside src/main/"),
        (("pom.xml", "a", "b"), "outside src/main/"),
        ((SRC, "return sql;", "return sql; // nosemgrep"), "suppression"),
        ((SRC, "String find", '@SuppressWarnings("all") String find'), "suppression"),
        (("../outside.java", "a", "b"), "leaves the repository"),
    ],
)
def test_patch_policy(repo, edit, message):
    applied = apply_patch(repo, patch(edit), FileCheckpoint(repo))
    assert not applied.ok and any(message in p for p in applied.problems)
    assert (repo / SRC).read_text() == CODE  # nothing written


def test_patch_is_all_or_nothing(repo):
    applied = apply_patch(
        repo, patch((SRC, "return sql;", "return null;"), (SRC, "missing", "x")), FileCheckpoint(repo)
    )
    assert not applied.ok and (repo / SRC).read_text() == CODE


def test_patch_size_limit(repo):
    huge = "\n".join(f"// line {i}" for i in range(200))
    applied = apply_patch(repo, patch((SRC, "return sql;", "return sql;\n" + huge)), FileCheckpoint(repo))
    assert not applied.ok and any("keep it under" in p for p in applied.problems)


MARKER = "[BOP-PROOF]"
GOOD_TEST = """package a;
import static org.junit.jupiter.api.Assertions.assertEquals;
class RepoBopProofTest {
    @org.junit.jupiter.api.Test
    void proves() { assertEquals(1, 2, "[BOP-PROOF] it is broken"); }
}
"""


def proof(**changes):
    values = dict(
        test_path="src/test/java/a/RepoBopProofTest.java",
        test_class="a.RepoBopProofTest",
        test_method="proves",
        source=GOOD_TEST,
    )
    values.update(changes)
    return ProofTest(**values)


def test_proof_placement_accepts_a_good_test(repo):
    placement = place_proof_test(repo, proof(), MARKER)
    assert placement.problems == [] and placement.path == repo / "src/test/java/a/RepoBopProofTest.java"


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"test_path": "src/main/java/a/RepoBopProofTest.java"}, "under src/test/java"),
        ({"test_path": "src/test/java/b/RepoBopProofTest.java"}, "should be"),
        ({"source": GOOD_TEST.replace(MARKER, "")}, "marker"),
        ({"test_method": "other"}, "define the method"),
        ({"source": GOOD_TEST + '// Runtime.getRuntime().exec("x")'}, "unit-level"),
        ({"source": GOOD_TEST + "// new java.net.Socket()"}, "unit-level"),
        (
            {
                "test_class": "a.RepoTest",
                "test_path": "src/test/java/a/RepoTest.java",
                "source": GOOD_TEST.replace("RepoBopProofTest", "RepoTest"),
            },
            "already exists",
        ),
    ],
)
def test_proof_placement_policy(repo, changes, message):
    placement = place_proof_test(repo, proof(**changes), MARKER)
    assert placement.path is None and any(message in p for p in placement.problems)


def test_remove_file_and_empty_parents(repo):
    target = repo / "src/test/java/a/deep/er/X.java"
    target.parent.mkdir(parents=True)
    target.write_text("x")
    remove_file_and_empty_parents(target, repo)
    assert not (repo / "src/test/java/a/deep").exists()
    assert (repo / "src/test/java/a/RepoTest.java").exists()
