from bop.java.surefire import PROOF_MARKER, TestCase, classify_proof, parse_reports, regressions
from bop.runner.base import RunResult

REPORT = """<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="a.ProofTest" tests="3" failures="1" errors="1">
  <testcase name="right()" classname="a.ProofTest" time="0.01">
    <failure message="[BOP-PROOF] leaked ==&gt; expected: &lt;&gt; but was: &lt;alice,bob&gt;"
             type="org.opentest4j.AssertionFailedError">stack</failure>
  </testcase>
  <testcase name="wrong" classname="a.ProofTest" time="0.01">
    <error message="boom" type="java.lang.NullPointerException">stack</error>
  </testcase>
  <testcase name="green" classname="a.ProofTest" time="0.01"/>
  <testcase name="nomarker" classname="a.ProofTest" time="0.01">
    <failure message="expected 1 but was 2" type="org.opentest4j.AssertionFailedError"/>
  </testcase>
</testsuite>
"""


def run(exit_code=0, out="", timed_out=False):
    return RunResult(["mvn"], exit_code, out, "", 1.0, timed_out, False, "test")


def cases(tmp_path):
    (tmp_path / "TEST-a.ProofTest.xml").write_text(REPORT)
    return parse_reports(tmp_path)


def test_parse_reports(tmp_path):
    parsed = {c.name: c for c in cases(tmp_path)}
    assert parsed["right"].status == "failed" and PROOF_MARKER in parsed["right"].message
    assert parsed["wrong"].status == "error" and parsed["green"].status == "passed"


def test_classification(tmp_path):
    c = cases(tmp_path)
    assert classify_proof(run(), c, "a.ProofTest", "right")[0] == "failed_right_reason"
    assert classify_proof(run(), c, "a.ProofTest", "wrong")[0] == "failed_other"
    outcome, detail = classify_proof(run(), c, "a.ProofTest", "nomarker")
    assert outcome == "failed_other" and "lacks the marker" in detail
    assert classify_proof(run(), c, "a.ProofTest", "green")[0] == "passed"
    assert classify_proof(run(timed_out=True), c, "a.ProofTest", "right")[0] == "timeout"


def test_compile_errors_and_missing_results():
    out = "[ERROR] /w/src/test/java/a/ProofTest.java:[10,5] cannot find symbol\n[ERROR] BUILD FAILURE"
    outcome, detail = classify_proof(run(1, out), [], "a.ProofTest", "right")
    assert outcome == "compile_error" and "cannot find symbol" in detail
    assert classify_proof(run(0), [], "a.ProofTest", "right")[0] == "not_run"


def test_regressions():
    before = [TestCase("a.T", "x", "passed"), TestCase("a.T", "y", "passed"), TestCase("a.T", "z", "failed")]
    after = [TestCase("a.T", "x", "passed"), TestCase("a.T", "y", "failed", message="nope")]
    assert regressions(before, after) == ["a.T#y failed: nope"]
    assert regressions(before, []) == ["a.T#x no longer runs", "a.T#y no longer runs"]
