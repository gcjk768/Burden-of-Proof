"""Runs one repository through the whole loop: prepare, scan, triage, analyze, prove, fix, report."""

from __future__ import annotations

import json
import secrets
import sys
import traceback
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from bop.config import Settings
from bop.db.store import Store
from bop.errors import BopError, BudgetExceeded
from bop.java.maven import Maven
from bop.llm.cache import ResponseCache
from bop.llm.catalog import fetch_catalog
from bop.llm.client import ChatClient, ChatResult, TokenFactoryClient
from bop.llm.cost import Budget, PriceTable
from bop.llm.fake import ScriptedClient
from bop.llm.router import Route, Router
from bop.llm.schemas import AnalysisVerdict, TriageVerdict
from bop.repo.snapshot import check_maven_project, remove_file_and_empty_parents, snapshot
from bop.runner.base import Runner, RunResult
from bop.runner.local import make_runner
from bop.scanners.sarif import FindingGroup
from bop.scanners.semgrep import default_rules
from bop.stages import analyze as analyze_stage
from bop.stages import fix as fix_stage
from bop.stages import prove as prove_stage
from bop.stages import triage as triage_stage
from bop.stages.context import RunContext
from bop.stages.ingest import ingest
from bop.stages.report import write_report, write_suppressions

TRIAGE_SUPPRESS_CONFIDENCE = 0.8
ANALYSIS_SUPPRESS_CONFIDENCE = 0.7


@dataclass
class RunOptions:
    repo: Path
    script: Path | None = None
    yes: bool = False
    budget_usd: float | None = None
    max_groups: int | None = None
    estimate_only: bool = False


@dataclass
class RunSummary:
    run_id: str
    run_dir: Path
    status: str
    states: dict[str, int] = field(default_factory=dict)
    spent_usd: float = 0.0
    estimate_usd: float | None = None
    report: Path | None = None
    message: str = ""


class RecordingRunner:
    """Wraps a runner so every sandbox job lands in the ledger with its full log."""

    def __init__(self, inner: Runner, store: Store, run_id: str, logs: Path) -> None:
        self.inner, self.store, self.run_id, self.logs = inner, store, run_id, logs
        self.name = inner.name
        self.count = 0
        logs.mkdir(parents=True, exist_ok=True)

    def available(self) -> tuple[bool, str]:
        return self.inner.available()

    def run(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        timeout_s: int,
        network: bool = False,
        env: Mapping[str, str] | None = None,
        writable: Sequence[Path] = (),
        readable: Sequence[Path] = (),
    ) -> RunResult:
        result = self.inner.run(
            argv, cwd=cwd, timeout_s=timeout_s, network=network, env=env, writable=writable, readable=readable
        )
        self.count += 1
        tool = Path(argv[0]).name
        purpose = f"{tool} {next((a for a in argv[1:] if not a.startswith('-')), '')}".strip()
        log = self.logs / f"{self.count:03d}-{tool}.log"
        log.write_text(
            f"$ {' '.join(argv)}\n# network={network} exit={result.exit_code} "
            f"timed_out={result.timed_out} {result.duration_s:.1f}s\n\n"
            f"{result.stdout}\n--- stderr ---\n{result.stderr}",
            encoding="utf-8",
        )
        self.store.add_runner_job(
            run_id=self.run_id,
            runner=self.name,
            purpose=purpose,
            argv_json=json.dumps(list(argv)),
            network=int(result.network),
            timeout_s=timeout_s,
            exit_code=result.exit_code,
            timed_out=int(result.timed_out),
            duration_ms=int(result.duration_s * 1000),
            log_path=str(log),
        )
        return result


def new_run_id() -> str:
    return datetime.now(UTC).strftime("run-%Y%m%d-%H%M%S-") + secrets.token_hex(2)


def estimate_cost(groups: Sequence[FindingGroup], prices: PriceTable, settings: Settings) -> float:
    """Upper-end estimate for a full run, before any model is called.

    Per in-scope finding: one triage share, a tool-using investigation of about eight turns,
    and on average 1.5 proof attempts and 2 fix attempts. Thinking roughly triples output.
    """
    in_scope = [g for g in groups if g.primary.in_scope]
    triage = prices.cost(settings.model_for("triage"), 3_000, 800)
    analyze = prices.cost(settings.model_for("deep"), 8 * 12_000 + 15_000, 3 * 8 * 1_500 + 1_500)
    prove = 1.5 * prices.cost(settings.model_for("build"), 20_000, 3 * 4_000)
    fix = 2 * prices.cost(settings.model_for("build"), 25_000, 3 * 4_000)
    return len(in_scope) * (triage + analyze + prove + fix)


def _price_table(settings: Settings, log: Callable[[str], None]) -> PriceTable:
    try:
        catalog = fetch_catalog(settings.catalog_url, timeout=8)
        return PriceTable.from_catalog(catalog.models)
    except Exception as exc:  # the catalog is optional; prices fall back to the committed table
        log(f"catalog unavailable ({type(exc).__name__}); using fallback prices")
        return PriceTable()


class Pipeline:
    def __init__(
        self,
        settings: Settings,
        *,
        log: Callable[[str], None] | None = None,
        runner: Runner | None = None,
        llm: ChatClient | None = None,
    ) -> None:
        self.settings = settings
        self.log = log or (lambda msg: print(f"[bop] {msg}", file=sys.stderr))
        self._runner = runner
        self._llm = llm

    def _recorder(self, store: Store, run_id: str) -> Callable[..., int | None]:
        def record(result: ChatResult | None, route: Route | None, context: dict[str, Any], error: str | None) -> int:
            values: dict[str, Any] = {
                "run_id": run_id,
                "group_id": context.get("group_id"),
                "stage": route.stage if route else (result.stage if result else "unknown"),
                "role": route.role if route else "scripted",
                "model": route.model if route else (result.model if result else "unknown"),
                "base_url": route.base_url if route else None,
                "thinking": int(route.thinking) if route else None,
                "error": error,
            }
            if result is not None:
                values.update(
                    prompt_tokens=result.usage.prompt_tokens,
                    completion_tokens=result.usage.completion_tokens,
                    reasoning_tokens=result.usage.reasoning_tokens,
                    cost_usd=result.cost_usd,
                    cached=int(result.cached),
                    latency_ms=result.latency_ms,
                    request_hash=result.request_hash,
                    fallback_from=result.fallback_from,
                )
                store.add_spend(run_id, result.cost_usd)
            return store.add_llm_call(**values)

        return record

    def run(self, options: RunOptions) -> RunSummary:
        settings = self.settings
        if options.budget_usd is not None:
            settings = settings.with_overrides(budget_usd=options.budget_usd)
        check_maven_project(options.repo.resolve())
        store = Store(settings.db_path)
        run_id = new_run_id()
        run_dir = settings.runs_dir / run_id
        workdir = run_dir / "work"
        run_dir.mkdir(parents=True)
        commit = snapshot(options.repo.resolve(), workdir)
        mode = "replay" if options.script else "live"
        store.create_run(
            run_id,
            repo_path=str(options.repo.resolve()),
            commit_sha=commit,
            mode=mode,
            workdir=str(workdir),
            budget_usd=settings.budget_usd,
            config=settings.redacted(),
        )
        self.log(f"run {run_id} ({mode}) on {options.repo} -> {run_dir}")

        runner = RecordingRunner(
            self._runner or make_runner(allow_unsandboxed=settings.allow_unsandboxed), store, run_id, run_dir / "logs"
        )
        recorder = self._recorder(store, run_id)
        prices = PriceTable() if options.script else _price_table(settings, self.log)
        if self._llm is not None:
            llm = self._llm
        elif options.script:
            llm = ScriptedClient.from_file(options.script, recorder=recorder)
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
            workdir=workdir,
            runner=runner,
            maven=Maven(runner, settings.maven_repo),
            llm=llm,
            rules=default_rules(),
            log=self.log,
        )
        summary = RunSummary(run_id=run_id, run_dir=run_dir, status="running")
        try:
            self._prepare(ctx)
            groups = ingest(ctx)
            in_scope = [g for g in groups if g.primary.in_scope]
            if options.max_groups is not None:
                in_scope = in_scope[: options.max_groups]
            summary.estimate_usd = estimate_cost(in_scope, prices, settings)
            self.log(
                f"estimate: about ${summary.estimate_usd:.2f} for {len(in_scope)} findings at live prices "
                f"(cap ${settings.budget_usd:.2f})"
            )
            over = not options.script and summary.estimate_usd > settings.warn_usd and not options.yes
            if options.estimate_only or over:
                status = "estimated" if options.estimate_only else "awaiting_confirmation"
                store.update_run(run_id, status=status, stage="estimate")
                summary.status = status
                if over and not options.estimate_only:
                    summary.message = (
                        f"Estimated cost ${summary.estimate_usd:.2f} is above ${settings.warn_usd:.2f}. "
                        "Re-run with --yes to proceed."
                    )
                return summary
            self._loop(ctx, in_scope)
            summary.status = "done"
        except BudgetExceeded as exc:
            summary.status, summary.message = "budget_stopped", str(exc)
            if ctx.current_group:
                stage = (store.get_run(run_id) or {"stage": "?"})["stage"]
                store.set_group_state(ctx.current_group, "stopped", f"budget cap reached during {stage}")
            self.log(f"stopped: {exc}")
        except BopError as exc:
            summary.status, summary.message = "failed", str(exc)
            store.update_run(run_id, error=str(exc))
            self.log(f"failed: {exc}")
        except Exception as exc:  # never leave a run marked as running
            trace = run_dir / "error.log"
            trace.write_text(traceback.format_exc(), encoding="utf-8")
            summary.status = "failed"
            summary.message = f"internal error: {type(exc).__name__}: {exc} (traceback in {trace})"
            store.update_run(run_id, error=summary.message)
            self.log(f"failed: {summary.message}")
        finally:
            run = store.get_run(run_id)
            if summary.status not in {"estimated", "awaiting_confirmation"}:
                store.update_run(run_id, status=summary.status, stage="report")
                write_suppressions(ctx)
                summary.report = write_report(ctx)
            summary.states = store.group_states(run_id)
            summary.spent_usd = float(run["spent_usd"]) if run else 0.0
            store.close()
        return summary

    def _prepare(self, ctx: RunContext) -> None:
        ctx.store.update_run(ctx.run_id, stage="prepare")
        self.log("prepare: resolving dependencies (the only step with network access)")
        online = ctx.maven.prepare(ctx.workdir)
        if not online.result.ok:
            raise BopError("the project does not build:\n" + online.result.output_tail(2000))
        if not online.cases:
            ctx.maven.warm_test_provider(ctx.workdir)
        # The baseline that patches are judged against must come from the same offline sandbox.
        offline = ctx.maven.test(ctx.workdir, purpose="baseline")
        if not offline.result.ok:
            raise BopError("the project does not build offline after resolution:\n" + offline.result.output_tail(2000))
        ctx.baseline = offline.cases
        online_only = {c.key for c in online.cases if c.status == "passed"} - {
            c.key for c in offline.cases if c.status == "passed"
        }
        if online_only:
            self.log(f"prepare: {len(online_only)} tests pass only with network access; left out of the baseline")
        passed = sum(c.status == "passed" for c in offline.cases)
        ctx.store.update_run(ctx.run_id, baseline=[c.__dict__ for c in offline.cases])
        self.log(f"prepare: offline baseline {passed}/{len(offline.cases)} tests pass")

    def _suppress(
        self, ctx: RunContext, group: FindingGroup, verdict: TriageVerdict | AnalysisVerdict, stage: str
    ) -> None:
        verdict_row = ctx.store.query(
            "SELECT id FROM verdicts WHERE group_id = ? AND stage = ? ORDER BY id DESC LIMIT 1", (group.id, stage)
        )
        justification = f"{verdict.summary} {verdict.reasoning}".strip()
        ctx.store.add_suppression(
            group_id=group.id,
            verdict_id=verdict_row[0]["id"] if verdict_row else None,
            rule_id=group.primary.rule_id,
            file=group.primary.file,
            fingerprint=group.primary.fingerprint,
            justification=justification,
        )
        ctx.store.set_group_state(group.id, "suppressed", f"{stage}: {verdict.false_positive_reason}")

    @staticmethod
    def _evidence_ok(ctx: RunContext, group_id: str, stage: str) -> bool:
        rows = ctx.store.query(
            "SELECT evidence_ok FROM verdicts WHERE group_id = ? AND stage = ? ORDER BY id DESC LIMIT 1",
            (group_id, stage),
        )
        return bool(rows and rows[0]["evidence_ok"])

    def _loop(self, ctx: RunContext, groups: Sequence[FindingGroup]) -> None:
        ctx.store.update_run(ctx.run_id, stage="triage")
        triaged = triage_stage.triage(ctx, groups)

        # Pass 1: apply every triage decision first, so a later budget stop cannot lose them.
        deep: list[FindingGroup] = []
        for group in groups:
            verdict = triaged.get(group.id)
            if (
                verdict is not None
                and verdict.verdict == "likely_false_positive"
                and verdict.confidence >= TRIAGE_SUPPRESS_CONFIDENCE
                and self._evidence_ok(ctx, group.id, "triage")
            ):
                self._suppress(ctx, group, verdict, "triage")
            else:
                deep.append(group)  # includes findings whose triage batch failed

        # Pass 2: trace, prove and fix the rest, one finding at a time.
        for group in deep:
            ctx.current_group = group.id
            self._deep(ctx, group, triaged.get(group.id))
            ctx.current_group = None

    def _deep(self, ctx: RunContext, group: FindingGroup, verdict: TriageVerdict | None) -> None:
        ctx.store.update_run(ctx.run_id, stage=f"analyze {group.id}")
        analysis = analyze_stage.analyze(ctx, group, verdict)
        if analysis is None:
            return
        if analysis.verdict == "unreachable":
            if analysis.confidence >= ANALYSIS_SUPPRESS_CONFIDENCE and self._evidence_ok(ctx, group.id, "analysis"):
                self._suppress(ctx, group, analysis, "analysis")
            else:
                ctx.store.set_group_state(group.id, "undetermined", "unreachable, but not confidently enough")
            return
        if analysis.verdict == "undetermined":
            ctx.store.set_group_state(group.id, "undetermined", analysis.summary)
            return

        ctx.store.update_run(ctx.run_id, stage=f"prove {group.id}")
        proof = prove_stage.prove(ctx, group, analysis)
        if not proof.proven:
            ctx.store.set_group_state(group.id, "not_proven", "; ".join(proof.history))
            return
        ctx.store.set_group_state(group.id, "proven", proof.selector)

        ctx.store.update_run(ctx.run_id, stage=f"fix {group.id}")
        try:
            result = fix_stage.fix(ctx, group, analysis, proof)
        finally:
            if proof.path is not None:
                # each finding starts from the clean snapshot
                remove_file_and_empty_parents(proof.path, ctx.workdir)
        ctx.store.set_group_state(group.id, "fixed" if result.fixed else "unfixed", result.summary)
