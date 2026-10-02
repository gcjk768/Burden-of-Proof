"""Turns SARIF from Semgrep (and later Dependency-Check) into findings with stable fingerprints."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

IN_SCOPE = {"sql_injection", "path_traversal", "vulnerable_dependency"}
_CWE = re.compile(r"CWE-(\d+)")
CWE_CATEGORY = {
    "89": "sql_injection",
    "564": "sql_injection",
    "22": "path_traversal",
    "23": "path_traversal",
    "35": "path_traversal",
    "36": "path_traversal",
    "73": "path_traversal",
    "937": "vulnerable_dependency",
    "1035": "vulnerable_dependency",
    "1104": "vulnerable_dependency",
    "1395": "vulnerable_dependency",
}
LEVEL_SEVERITY = {"error": "high", "warning": "medium", "note": "low", "none": "info"}


@dataclass
class Finding:
    id: str
    tool: str
    rule_id: str
    category: str
    cwe: str | None
    severity: str
    file: str
    start_line: int
    end_line: int
    message: str
    snippet: str
    fingerprint: str
    in_scope: bool
    base_fingerprint: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        """Human-readable location key, also used to match scripted replies."""
        return f"{self.file}:{self.start_line}"


def normalise_snippet(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def fingerprint(tool: str, rule_id: str, file: str, snippet: str, occurrence: int = 0) -> str:
    raw = f"{tool}|{rule_id}|{file}|{normalise_snippet(snippet)}|{occurrence}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


def canonical_rule_id(raw: str, known: Iterable[str]) -> str:
    """Semgrep prefixes rule IDs with the dotted path of the config file; strip it for our rules."""
    for rule in sorted(known, key=len, reverse=True):
        if raw == rule or raw.endswith("." + rule):
            return rule
    return raw


def _rule_index(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rules = run.get("tool", {}).get("driver", {}).get("rules", []) or []
    return {r.get("id"): r for r in rules if r.get("id")}


def _cwe_and_category(rule: dict[str, Any], result: dict[str, Any]) -> tuple[str | None, str]:
    tags = list(rule.get("properties", {}).get("tags", []) or []) + list(
        result.get("properties", {}).get("tags", []) or []
    )
    for tag in tags:
        match = _CWE.search(str(tag))
        if match:
            return f"CWE-{match.group(1)}", CWE_CATEGORY.get(match.group(1), "other")
    return None, "other"


def parse_sarif(data: dict[str, Any], *, known_rules: Iterable[str] = ()) -> list[Finding]:
    known = list(known_rules)
    findings: list[Finding] = []
    seen: dict[str, int] = {}
    for run in data.get("runs", []):
        tool = run.get("tool", {}).get("driver", {}).get("name", "unknown")
        rules = _rule_index(run)
        for result in run.get("results", []) or []:
            locations = result.get("locations") or []
            if not locations:
                continue
            physical = locations[0].get("physicalLocation", {})
            file = physical.get("artifactLocation", {}).get("uri", "")
            file = file.removeprefix("file://").removeprefix("./")
            region = physical.get("region", {})
            start = int(region.get("startLine", 1))
            end = int(region.get("endLine", start))
            snippet = region.get("snippet", {}).get("text", "")
            raw_rule = result.get("ruleId", "unknown")
            rule = rules.get(raw_rule, {})
            rule_id = canonical_rule_id(raw_rule, known)
            cwe, category = _cwe_and_category(rule, result)
            level = result.get("level") or rule.get("defaultConfiguration", {}).get("level", "warning")
            base = fingerprint(tool, rule_id, file, snippet)
            occurrence = seen.get(base, 0)
            seen[base] = occurrence + 1
            fp = base if occurrence == 0 else fingerprint(tool, rule_id, file, snippet, occurrence)
            findings.append(
                Finding(
                    id=f"F-{fp[:12]}",
                    tool=tool,
                    rule_id=rule_id,
                    category=category,
                    cwe=cwe,
                    severity=LEVEL_SEVERITY.get(level, "medium"),
                    file=file,
                    start_line=start,
                    end_line=end,
                    message=(result.get("message", {}) or {}).get("text", ""),
                    snippet=snippet,
                    fingerprint=fp,
                    in_scope=category in IN_SCOPE,
                    base_fingerprint=base,
                )
            )
    return findings


def load_sarif(path: Path, *, known_rules: Iterable[str] = ()) -> list[Finding]:
    return parse_sarif(json.loads(path.read_text(encoding="utf-8")), known_rules=known_rules)


@dataclass
class FindingGroup:
    id: str
    category: str
    members: list[Finding]
    public_id: str = ""  # the ID before run scoping; models only ever see this one

    @property
    def prompt_id(self) -> str:
        """The ID shown to models. It stays the same across runs, so cached replies keep matching."""
        return self.public_id or self.id

    @property
    def primary(self) -> Finding:
        return self.members[0]


def group_findings(findings: Iterable[Finding]) -> list[FindingGroup]:
    """Findings from different rules on the same statement are one problem."""
    groups: dict[tuple[str, str, int], FindingGroup] = {}
    for f in sorted(findings, key=lambda f: (f.file, f.start_line, f.rule_id)):
        key = (f.category, f.file, f.start_line)
        if key not in groups:
            groups[key] = FindingGroup(id=f"G-{f.fingerprint[:12]}", category=f.category, members=[])
        groups[key].members.append(f)
    return list(groups.values())
