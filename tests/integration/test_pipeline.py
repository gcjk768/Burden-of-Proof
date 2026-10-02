"""The whole loop on the sample app, with recorded model replies and the real sandbox, Maven and Semgrep.

Needs Java 17+, Maven, Semgrep and Linux user namespaces. The first run downloads the sample
app's dependencies into a shared Maven repository (~/.cache/bop-test-m2 by default).
"""

from __future__ import annotations

import os
import shutil
import sqlite3
from pathlib import Path

import pytest

from bop.config import load_settings
from bop.orchestrator import Pipeline, RunOptions
from bop.runner.local import LocalNamespaceRunner
from bop.scanners.semgrep import semgrep_executable

pytestmark = pytest.mark.integration

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
APP = FIXTURES / "tiny-java-app"
SCRIPT = FIXTURES / "llm" / "tiny-java-app.json"


def _missing() -> str | None:
    if not shutil.which("mvn") or not shutil.which("java"):
        return "Java and Maven are required"
    if not shutil.which(semgrep_executable()):
        return "Semgrep is required (pip install -e '.[scan]')"
    if not LocalNamespaceRunner().available()[0]:
        return "Linux user namespaces are required"
    return None


@pytest.fixture(scope="module")
def finished_run(tmp_path_factory):
    reason = _missing()
    if reason:
        pytest.skip(reason)
    home = tmp_path_factory.mktemp("bop-home")
    m2 = os.environ.get("BOP_TEST_M2", str(Path.home() / ".cache" / "bop-test-m2"))
    settings = load_settings({"BOP_HOME": str(home), "BOP_MAVEN_REPO": m2})
    logs: list[str] = []
    summary = Pipeline(settings, log=logs.append).run(RunOptions(repo=APP, script=SCRIPT))
    db = sqlite3.connect(settings.db_path)
    db.row_factory = sqlite3.Row
    yield summary, db, logs
    db.close()


def group_id(db, file_suffix: str, line: int) -> str:
    row = db.execute(
        "SELECT group_id FROM findings WHERE file LIKE ? AND start_line = ?", (f"%{file_suffix}", line)
    ).fetchone()
    assert row, f"no finding at {file_suffix}:{line}"
    return row["group_id"]


def test_run_completes_with_two_fixes_and_one_suppression(finished_run):
    summary, _, logs = finished_run
    assert summary.status == "done", "\n".join(logs)
    assert summary.states == {"fixed": 2, "suppressed": 1}
    assert summary.report and summary.report.is_file()


def test_sql_injection_was_proven_then_fixed_after_feedback(finished_run):
    _, db, _ = finished_run
    gid = group_id(db, "AccountRepository.java", 26)
    proofs = [
        r["outcome"] for r in db.execute("SELECT outcome FROM proof_tests WHERE group_id = ? ORDER BY id", (gid,))
    ]
    assert proofs == ["compile_error", "failed_right_reason"]
    patches = db.execute("SELECT * FROM patches WHERE group_id = ? ORDER BY id", (gid,)).fetchall()
    assert [p["accepted"] for p in patches] == [0, 1]
    assert patches[0]["policy_ok"] == 0 and "occurs 0 times" in patches[0]["failure_summary"]
    accepted = patches[1]
    assert (accepted["proof_outcome"], accepted["suite_outcome"], accepted["rescan_outcome"]) == (
        "passed",
        "passed",
        "clean",
    )


def test_patch_that_only_silences_the_scanner_is_rejected(finished_run):
    _, db, _ = finished_run
    gid = group_id(db, "ReportStore.java", 18)
    patches = db.execute("SELECT * FROM patches WHERE group_id = ? ORDER BY id", (gid,)).fetchall()
    assert [p["accepted"] for p in patches] == [0, 1]
    first = patches[0]
    assert first["policy_ok"] == 1 and first["proof_outcome"] == "failed_right_reason"
    assert "proof test is failed_right_reason" in first["failure_summary"]


def test_false_positive_is_suppressed_with_verified_evidence(finished_run):
    summary, db, _ = finished_run
    gid = group_id(db, "AccountRepository.java", 47)
    verdict = db.execute("SELECT * FROM verdicts WHERE group_id = ?", (gid,)).fetchone()
    assert verdict["verdict"] == "likely_false_positive" and verdict["evidence_ok"] == 1
    text = (summary.run_dir / "suppressions.yaml").read_text()
    assert "Integer.parseInt" in text and "verified: true" in text


def test_only_dependency_resolution_had_network(finished_run):
    _, db, _ = finished_run
    jobs = db.execute("SELECT purpose, network FROM runner_jobs").fetchall()
    online = [j["purpose"] for j in jobs if j["network"]]
    assert online == ["mvn test"]
    assert any(j["purpose"].startswith("semgrep") for j in jobs)


def test_snapshot_is_left_exactly_as_it_was(finished_run):
    summary, _, _ = finished_run
    work = summary.run_dir / "work"
    original = {p.relative_to(APP) for p in APP.rglob("*") if p.is_file() and "target" not in p.parts}
    after = {p.relative_to(work) for p in work.rglob("*") if "target" not in p.relative_to(work).parts}
    after_files = {p for p in after if (work / p).is_file()}
    assert after_files == original
    for rel in original:
        assert (work / rel).read_bytes() == (APP / rel).read_bytes(), rel
    empty_dirs = [p for p in after if (work / p).is_dir() and not any((work / p).iterdir())]
    assert empty_dirs == []


def test_fix_diff_contains_patch_and_proof_test(finished_run):
    summary, db, _ = finished_run
    gid = group_id(db, "AccountRepository.java", 26)
    diff = (summary.run_dir / "groups" / gid / "fix.diff").read_text()
    assert "PreparedStatement" in diff and "AccountHandlerSqlInjectionBopProofTest" in diff
