"""The benchmark command on a two-case stand-in for the OWASP Benchmark, with recorded triage replies."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bop.cli import main

pytestmark = pytest.mark.integration

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
BENCH = FIXTURES / "bench-mini"
SCRIPT = FIXTURES / "llm" / "bench-mini.json"


@pytest.fixture
def bop_home(tmp_path, monkeypatch):
    from tests.integration.test_pipeline import _missing

    reason = _missing()
    if reason:
        pytest.skip(reason)
    monkeypatch.setenv("BOP_HOME", str(tmp_path / "home"))
    return tmp_path


def test_triage_suppresses_the_false_positive_and_the_score_moves(bop_home, capsys):
    out = bop_home / "out"
    assert main(["bench", "owasp", str(BENCH), "--triage", "--script", str(SCRIPT), "--out", str(out)]) == 0
    report = (out / "score.md").read_text()
    raw, after = report.split("### After triage")
    assert "| sqli | 2 | 1 | 1 | 0 | 0 | 0.500 | 1.000 | 1.000 | +0.000 |" in raw
    assert "| sqli | 2 | 1 | 0 | 1 | 0 | 1.000 | 1.000 | 0.000 | +1.000 |" in after
    scoring = json.loads((out / "scoring.sarif").read_text())
    assert scoring["runs"][0]["tool"]["driver"]["name"].startswith("Semgrep")
    uris = [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in scoring["runs"][0]["results"]]
    assert uris == ["BenchmarkTest00001.java"]
    assert not (out / "testcode").exists()  # the scanned copy is removed


def test_raw_mode_needs_no_model(bop_home):
    out = bop_home / "raw"
    assert main(["bench", "owasp", str(BENCH), "--out", str(out)]) == 0
    assert "| sqli | 2 | 1 | 1 | 0 | 0 |" in (out / "score.md").read_text()
    assert not (out / "scoring.sarif").exists()
