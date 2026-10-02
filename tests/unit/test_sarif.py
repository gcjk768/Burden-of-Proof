from bop.scanners.sarif import canonical_rule_id, group_findings, load_sarif, parse_sarif
from bop.scanners.semgrep import default_rules, rule_ids

KNOWN = ["bop.java.sqli.tainted-query", "bop.java.path-traversal.tainted-path"]


def test_rule_ids_are_read_from_the_rules_file():
    assert rule_ids(default_rules()) == KNOWN


def test_canonical_rule_id_strips_the_config_prefix():
    assert canonical_rule_id("src.bop.rules.bop.java.sqli.tainted-query", KNOWN) == "bop.java.sqli.tainted-query"
    assert canonical_rule_id("someone.elses.rule", KNOWN) == "someone.elses.rule"


def test_recorded_semgrep_sarif(fixtures):
    findings = load_sarif(fixtures / "sarif/semgrep-tiny-java-app.sarif", known_rules=KNOWN)
    by_key = {f.key: f for f in findings}
    sqli = by_key["src/main/java/com/example/bank/AccountRepository.java:26"]
    assert sqli.rule_id == "bop.java.sqli.tainted-query" and sqli.cwe == "CWE-89"
    assert sqli.category == "sql_injection" and sqli.in_scope and sqli.severity == "high"
    path = by_key["src/main/java/com/example/bank/ReportStore.java:18"]
    assert path.category == "path_traversal" and path.cwe == "CWE-22"
    assert len({f.fingerprint for f in findings}) == len(findings) == 3
    # fingerprints are stable across parses
    again = load_sarif(fixtures / "sarif/semgrep-tiny-java-app.sarif", known_rules=KNOWN)
    assert [f.fingerprint for f in again] == [f.fingerprint for f in findings]


def test_grouping_merges_rules_on_the_same_statement(fixtures):
    findings = load_sarif(fixtures / "sarif/semgrep-tiny-java-app.sarif", known_rules=KNOWN)
    duplicate = findings[0].__class__(**{**findings[0].__dict__, "rule_id": "other.rule", "fingerprint": "zzz"})
    groups = group_findings([*findings, duplicate])
    assert len(groups) == 3
    assert max(len(g.members) for g in groups) == 2


def test_sql_sinks_cover_jdbc_and_spring():
    text = default_rules().read_text()
    for sink in ("executeQuery", "prepareStatement", "query", "queryForList", "update", "batchUpdate", "createQuery"):
        assert f"|{sink}|" in text or f"({sink}|" in text or f"|{sink})" in text, sink


def _result(snippet, suppressions=None):
    result = {
        "ruleId": "bop.java.path-traversal.tainted-path",
        "message": {"text": "m"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "src/main/java/R.java"},
                    "region": {"startLine": 18, "snippet": {"text": snippet}},
                }
            }
        ],
    }
    if suppressions is not None:
        result["suppressions"] = suppressions
    rules = [{"id": "bop.java.path-traversal.tainted-path", "properties": {"tags": ["CWE-22"]}}]
    return {"runs": [{"tool": {"driver": {"name": "Semgrep OSS", "rules": rules}}, "results": [result]}]}


def test_findings_suppressed_in_source_are_recorded_but_not_in_scope():
    # The shape Semgrep 1.179 writes for a line ending in "// nosemgrep: <rule>".
    line = "Path file = baseDir.resolve(reportName); // nosemgrep: bop.java.path-traversal.tainted-path"
    (finding,) = parse_sarif(_result(line, [{"kind": "inSource"}]))
    assert finding.suppressed_in_source and not finding.in_scope
    (plain,) = parse_sarif(_result("Path file = baseDir.resolve(reportName);"))
    assert plain.in_scope and not plain.suppressed_in_source
    assert finding.fingerprint == plain.fingerprint  # adding the comment does not change its identity


def test_patches_may_not_add_the_short_nosem_marker(tmp_path):
    from bop.llm.schemas import Edit, Patch
    from bop.repo.edits import apply_patch
    from bop.repo.snapshot import FileCheckpoint

    (tmp_path / "src/main/java").mkdir(parents=True)
    (tmp_path / "src/main/java/R.java").write_text("class R { int x = 1; }\n")
    edit = Edit(file="src/main/java/R.java", search="int x = 1;", replace="int x = 1; // nosem")
    applied = apply_patch(tmp_path, Patch(edits=[edit], explanation="e"), FileCheckpoint(tmp_path))
    assert not applied.ok and "suppression" in applied.problems[0]
