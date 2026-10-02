from bop.scanners.sarif import canonical_rule_id, group_findings, load_sarif
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
