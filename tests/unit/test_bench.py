from bop.bench.owasp import flagged_cases, load_expected, render, score
from bop.scanners.sarif import Finding


def finding(name, category):
    return Finding(
        id="F",
        tool="t",
        rule_id="r",
        category=category,
        cwe=None,
        severity="high",
        file=f"src/main/java/org/owasp/benchmark/testcode/{name}.java",
        start_line=1,
        end_line=1,
        message="",
        snippet="s",
        fingerprint="f",
        in_scope=True,
    )


def test_scores_count_each_test_case_once_per_category(tmp_path):
    csv = tmp_path / "expected.csv"
    csv.write_text(
        "# test name, category, real vulnerability, cwe\n"
        "BenchmarkTest00001,sqli,true,89\n"
        "BenchmarkTest00002,sqli,false,89\n"
        "BenchmarkTest00003,sqli,true,89\n"
        "BenchmarkTest00004,sqli,false,89\n"
        "BenchmarkTest00005,pathtraver,true,22\n"
        "BenchmarkTest00006,xss,true,79\n"
    )
    expected = load_expected(csv)
    findings = [
        finding("BenchmarkTest00001", "sql_injection"),
        finding("BenchmarkTest00001", "sql_injection"),  # two results in one case count once
        finding("BenchmarkTest00002", "sql_injection"),
        finding("BenchmarkTest00005", "sql_injection"),  # wrong category for that case: ignored
        finding("BenchmarkTest00006", "path_traversal"),
    ]
    sqli, path = score(expected, flagged_cases(findings))
    assert (sqli.tp, sqli.fp, sqli.tn, sqli.fn) == (1, 1, 1, 1)
    assert sqli.precision == 0.5 and sqli.recall == 0.5 and sqli.fpr == 0.5 and sqli.benchmark_score == 0.0
    assert (path.tp, path.fn) == (0, 1)
    table = render([sqli, path], "t")
    assert "| sqli | 4 | 1 | 1 | 1 | 1 | 0.500 | 0.500 | 0.500 | +0.000 |" in table


def test_bench_command_refuses_a_directory_that_is_not_the_benchmark(tmp_path, capsys):
    from bop.cli import main

    assert main(["bench", "owasp", str(tmp_path)]) == 2
    assert "does not look like a BenchmarkJava checkout" in capsys.readouterr().err


def test_git_head_reads_refs_without_running_git(tmp_path):
    from bop.cli import _git_head

    (tmp_path / ".git" / "refs" / "heads").mkdir(parents=True)
    (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/master\n")
    (tmp_path / ".git" / "packed-refs").write_text("# pack-refs\nabc123 refs/heads/master\n")
    assert _git_head(tmp_path) == "abc123"
    (tmp_path / ".git" / "refs" / "heads" / "master").write_text("def456\n")
    assert _git_head(tmp_path) == "def456"
