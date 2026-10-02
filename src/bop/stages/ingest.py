"""Scan the snapshot and turn the results into stored findings and groups."""

from __future__ import annotations

import hashlib
from collections import Counter

from bop.errors import BopError
from bop.scanners.sarif import FindingGroup, group_findings
from bop.scanners.semgrep import ScanResult, run_semgrep
from bop.stages.context import RunContext


def scan(ctx: RunContext, *, phase: str, group_id: str | None = None, attempt: int | None = None) -> ScanResult:
    name = f"semgrep-{phase}" + (f"-{group_id}-{attempt}" if group_id else "") + ".sarif"
    result = run_semgrep(ctx.runner, ctx.workdir, ctx.run_dir / "scans" / name, rules=ctx.rules)
    ctx.store.add_scan(
        run_id=ctx.run_id,
        tool="semgrep",
        phase=phase,
        group_id=group_id,
        exit_code=result.run.exit_code,
        sarif_path=str(result.sarif_path),
    )
    if not result.ok:
        raise BopError(f"Semgrep failed (exit {result.run.exit_code}): {result.run.output_tail(1500)}")
    return result


def ingest(ctx: RunContext) -> list[FindingGroup]:
    result = scan(ctx, phase="initial")
    groups = group_findings(result.findings)
    ctx.initial_base_counts = Counter(f.base_fingerprint for f in result.findings)
    # IDs come from the code, so the same repository scanned twice would collide; scope them to the run.
    token = hashlib.sha256(ctx.run_id.encode()).hexdigest()[:6]
    for group in groups:
        group.id = f"{group.id}-{token}"
        for f in group.members:
            f.id = f"{f.id}-{token}"
    for group in groups:
        in_scope = group.primary.in_scope
        ctx.store.add_group(
            id=group.id,
            run_id=ctx.run_id,
            category=group.category,
            primary_finding_id=group.primary.id,
            member_count=len(group.members),
            state="new" if in_scope else "out_of_scope",
            state_reason=None if in_scope else f"category {group.category} is not in scope yet",
        )
        for f in group.members:
            ctx.store.add_finding(
                id=f.id,
                run_id=ctx.run_id,
                group_id=group.id,
                fingerprint=f.fingerprint,
                rule_id=f.rule_id,
                cwe=f.cwe,
                category=f.category,
                severity=f.severity,
                file=f.file,
                start_line=f.start_line,
                end_line=f.end_line,
                message=f.message,
                snippet=f.snippet,
                in_scope=int(f.in_scope),
            )
    ctx.log(
        f"scan: {len(result.findings)} findings in {len(groups)} groups "
        f"({sum(g.primary.in_scope for g in groups)} in scope)"
    )
    return groups
