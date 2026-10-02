"""Triage-only runs on a benchmark: the real triage stage and the real suppression rule.

A finding is dropped from the "after triage" score exactly when a normal run would suppress it at
triage: verdict ``likely_false_positive``, confidence of at least ``TRIAGE_SUPPRESS_CONFIDENCE`` and
evidence that verified against the code. Nothing else changes, so the before and after numbers
measure the triage step alone.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from bop.config import Settings
from bop.db.store import Store
from bop.errors import BudgetExceeded
from bop.java.maven import Maven
from bop.llm.cache import ResponseCache
from bop.llm.client import ChatClient, TokenFactoryClient
from bop.llm.cost import Budget, PriceTable
from bop.llm.fake import ScriptedClient
from bop.llm.router import Router
from bop.llm.schemas import TriageVerdict
from bop.orchestrator import TRIAGE_SUPPRESS_CONFIDENCE, Pipeline, _price_table, new_run_id
from bop.runner.base import Runner
from bop.runner.local import make_runner
from bop.scanners.sarif import Finding, parse_sarif
from bop.scanners.semgrep import default_rules, rule_ids
from bop.stages import triage as triage_stage
from bop.stages.context import RunContext
from bop.stages.ingest import ingest

# Same per-finding triage share as the full-run estimate.
TRIAGE_PROMPT_TOKENS, TRIAGE_OUTPUT_TOKENS = 3_000, 800


@dataclass
class BenchTriage:
    run_id: str
    status: str  # done | budget_stopped | estimated | awaiting_confirmation
    estimate_usd: float
    findings: list[Finding] = field(default_factory=list)
    dropped: set[str] = field(default_factory=set)  # fingerprints of findings triage suppressed
    triaged_groups: int = 0
    in_scope_groups: int = 0
    raw_sarif: Path | None = None
    spent_usd: float = 0.0
    message: str = ""


def triage_benchmark(
    settings: Settings,
    work: Path,
    run_dir: Path,
    *,
    script: Path | None = None,
    yes: bool = False,
    estimate_only: bool = False,
    max_groups: int | None = None,
    llm: ChatClient | None = None,
    runner: Runner | None = None,
    log: Callable[[str], None] = print,
) -> BenchTriage:
    store = Store(settings.db_path)
    run_id = new_run_id().replace("run-", "bench-", 1)
    store.create_run(
        run_id,
        repo_path=str(work),
        commit_sha=None,
        mode="bench-replay" if script else "bench",
        workdir=str(work),
        budget_usd=settings.budget_usd,
        config=settings.redacted(),
    )
    recorder = Pipeline(settings, log=log)._recorder(store, run_id)
    prices = PriceTable() if script else _price_table(settings, log)
    if llm is None:
        if script:
            llm = ScriptedClient.from_file(script, recorder=recorder)
        else:
            llm = TokenFactoryClient(
                settings,
                router=Router(settings),
                prices=prices,
                cache=ResponseCache(settings.cache_dir, settings.cache_mode),
                budget=Budget(settings.budget_usd),
                recorder=recorder,
            )
    ctx = RunContext(
        settings=settings,
        store=store,
        run_id=run_id,
        run_dir=run_dir,
        workdir=work,
        runner=runner or make_runner(allow_unsandboxed=settings.allow_unsandboxed),
        maven=cast(Maven, None),  # triage never builds anything
        llm=llm,
        rules=default_rules(),
        log=log,
    )
    groups = ingest(ctx)
    raw = run_dir / "scans" / "semgrep-initial.sarif"
    in_scope = [g for g in groups if g.primary.in_scope]
    if max_groups is not None:
        in_scope = in_scope[:max_groups]
    estimate = len(in_scope) * prices.cost(settings.model_for("triage"), TRIAGE_PROMPT_TOKENS, TRIAGE_OUTPUT_TOKENS)
    result = BenchTriage(
        run_id=run_id,
        status="done",
        estimate_usd=estimate,
        findings=[f for g in groups for f in g.members],
        in_scope_groups=len(in_scope),
        raw_sarif=raw,
    )
    log(f"estimate: about ${estimate:.2f} to triage {len(in_scope)} finding groups (cap ${settings.budget_usd:.2f})")
    if estimate_only or (not script and estimate > settings.warn_usd and not yes):
        result.status = "estimated" if estimate_only else "awaiting_confirmation"
        if result.status == "awaiting_confirmation":
            result.message = f"Estimated ${estimate:.2f} is above ${settings.warn_usd:.2f}. Re-run with --yes."
        store.update_run(run_id, status=result.status, stage="estimate")
        return result

    store.update_run(run_id, stage="triage")
    verdicts: dict[str, TriageVerdict] = {}
    try:
        triage_stage.triage(ctx, in_scope, verdicts)
    except BudgetExceeded as exc:
        result.status, result.message = "budget_stopped", str(exc)
    suppressed = {
        g.id
        for g in in_scope
        if (v := verdicts.get(g.id)) is not None
        and v.verdict == "likely_false_positive"
        and v.confidence >= TRIAGE_SUPPRESS_CONFIDENCE
        and Pipeline._evidence_ok(ctx, g.id, "triage")
    }
    for group in in_scope:
        if group.id in suppressed:
            store.set_group_state(group.id, "suppressed", "triage (benchmark run)")
            result.dropped.update(f.fingerprint for f in group.members)
    result.triaged_groups = len(verdicts)
    run = store.get_run(run_id)
    result.spent_usd = float(run["spent_usd"]) if run else 0.0
    store.update_run(run_id, status=result.status, stage="report")
    return result


def scoring_sarif(raw: dict[str, Any], dropped: set[str], *, label: str = "Semgrep OSS + BoP triage") -> dict[str, Any]:
    """The raw SARIF without the results triage suppressed.

    BenchmarkUtils ignores SARIF suppressions, so a triaged result set must physically drop them to be
    scored. The tool name must still start with "Semgrep" for the scorecard to recognise it.
    """
    known = rule_ids(default_rules())
    out = json.loads(json.dumps(raw))
    for run in out.get("runs", []):
        located = [r for r in run.get("results", []) or [] if r.get("locations")]
        findings = parse_sarif({"runs": [{**run, "results": located}]}, known_rules=known)
        keep = [r for r, f in zip(located, findings, strict=True) if f.fingerprint not in dropped]
        run["results"] = keep
        run.setdefault("tool", {}).setdefault("driver", {})["name"] = label
    return out
