"""Command line: bop doctor | scan | run | show."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from bop import __version__
from bop.config import load_settings
from bop.db.store import Store
from bop.errors import BopError


def _version(cmd: list[str]) -> str | None:
    if not shutil.which(cmd[0]):
        return None
    # Semgrep otherwise phones home for a version check, which can stall for minutes behind a proxy.
    env = {**os.environ, "SEMGREP_ENABLE_VERSION_CHECK": "0", "SEMGREP_SEND_METRICS": "off"}
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False, env=env)
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (out.stdout or out.stderr).strip().splitlines()
    lines = [line for line in text if "JAVA_TOOL_OPTIONS" not in line]
    return lines[0] if lines else None


def cmd_doctor(args: argparse.Namespace) -> int:
    from bop.llm.catalog import check_models, fetch_catalog
    from bop.runner.local import LocalNamespaceRunner
    from bop.scanners.semgrep import semgrep_executable

    settings = load_settings()
    problems = 0

    def line(ok: bool | None, label: str, detail: str) -> None:
        nonlocal problems
        mark = {True: "ok  ", False: "FAIL", None: "warn"}[ok]
        if ok is False:
            problems += 1
        print(f"[{mark}] {label}: {detail}")

    line(sys.version_info >= (3, 12), "python", sys.version.split()[0])
    ok, why = LocalNamespaceRunner().available()
    line(ok or (None if settings.allow_unsandboxed else False), "sandbox", why)
    for label, cmd in (
        ("java", ["java", "-version"]),
        ("maven", ["mvn", "-v"]),
        ("semgrep", [semgrep_executable(), "--version", "--disable-version-check"]),
    ):
        version = _version(cmd)
        line(version is not None, label, version or "not found on PATH")
    for name, value in settings.redacted().items():
        if name.isupper():
            line(value == "set" if name == "NEBIUS_API_KEY" else None if value != "set" else True, name, str(value))
    try:
        catalog = fetch_catalog(settings.catalog_url, timeout=10)
        for check in check_models(settings.models, catalog):
            line(
                check.ok if check.role != "triage_alt" else (check.ok or None),
                f"model {check.role}",
                f"{check.model}: {check.message}",
            )
    except Exception as exc:
        line(None, "catalog", f"could not read {settings.catalog_url} ({type(exc).__name__}); model IDs unchecked")

    if args.live:
        problems += _live_smoke(settings)
    print("\nall checks passed" if problems == 0 else f"\n{problems} problem(s) found")
    return 0 if problems == 0 else 1


def _live_smoke(settings) -> int:  # type: ignore[no-untyped-def]
    """One tiny JSON request per configured model, thinking off, to confirm IDs, JSON mode and cost."""
    from bop.llm.cache import ResponseCache
    from bop.llm.client import TokenFactoryClient
    from bop.llm.router import Router
    from bop.llm.structured import extract_json

    client = TokenFactoryClient(settings, cache=ResponseCache(settings.cache_dir, "off"))  # always a real call
    schema = {
        "name": "Ping",
        "schema": {
            "type": "object",
            "properties": {"ok": {"type": "boolean"}},
            "required": ["ok"],
            "additionalProperties": False,
        },
    }
    messages = [{"role": "user", "content": 'Reply with the JSON object {"ok": true} and nothing else.'}]
    failures = 0
    seen = set()
    for role in settings.models:
        route = Router(settings).route("smoke", role=role)
        if route.model in seen:
            continue
        seen.add(route.model)
        try:
            result = client.chat_route(route, messages, schema=schema)
            parsed = extract_json(result.content)
            print(
                f"[ok  ] live {role}: {route.model} json={parsed} reasoning_tokens={result.usage.reasoning_tokens}"
                f" {result.latency_ms} ms ${result.cost_usd:.6f}{' (cached)' if result.cached else ''}"
            )
        except Exception as exc:
            failures += 1
            print(f"[FAIL] live {role}: {route.model}: {type(exc).__name__}: {exc}")
    return failures


def cmd_scan(args: argparse.Namespace) -> int:
    import tempfile

    from bop.repo.snapshot import snapshot
    from bop.runner.local import make_runner
    from bop.scanners.sarif import group_findings
    from bop.scanners.semgrep import run_semgrep

    settings = load_settings()
    runner = make_runner(allow_unsandboxed=settings.allow_unsandboxed)
    with tempfile.TemporaryDirectory(prefix="bop-scan-") as tmp:
        work = Path(tmp) / "work"
        snapshot(Path(args.repo).resolve(), work)
        result = run_semgrep(runner, work, Path(tmp) / "semgrep.sarif")
        if not result.ok:
            raise BopError(f"Semgrep failed: {result.run.output_tail(1500)}")
        for group in group_findings(result.findings):
            f = group.primary
            scope = "in scope" if f.in_scope else "out of scope"
            print(f"{group.id}  {f.file}:{f.start_line}  {f.rule_id}  {f.cwe or ''}  ({scope})")
        print(f"\n{len(result.findings)} findings")
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    from bop.orchestrator import Pipeline, RunOptions

    settings = load_settings()
    summary = Pipeline(settings).run(
        RunOptions(
            repo=Path(args.repo),
            script=Path(args.script) if args.script else None,
            yes=args.yes,
            budget_usd=args.budget,
            max_groups=args.max_findings,
            estimate_only=args.estimate_only,
        )
    )
    print(f"\nrun {summary.run_id}: {summary.status}")
    if summary.message:
        print(summary.message)
    for state, n in sorted(summary.states.items()):
        print(f"  {state:<14} {n}")
    print(f"  spend          ${summary.spent_usd:.4f}")
    if summary.report:
        print(f"report: {summary.report}")
    return 0 if summary.status in {"done", "estimated"} else 2


def cmd_show(args: argparse.Namespace) -> int:
    settings = load_settings()
    store = Store(settings.db_path)
    run = store.get_run(args.run_id)
    if run is None:
        raise BopError(f"no run {args.run_id} in {settings.db_path}")
    print(json.dumps({k: run[k] for k in run.keys() if k not in {"baseline_json", "config_json"}}, indent=2))  # noqa: SIM118 (sqlite3.Row)
    print(json.dumps(store.group_states(args.run_id), indent=2))
    for row in store.spend_by_model(args.run_id):
        print(dict(row))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bop", description="Make every security finding prove itself.")
    parser.add_argument("--version", action="version", version=f"bop {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    doctor = sub.add_parser("doctor", help="check tools, sandbox, keys and model IDs")
    doctor.add_argument("--live", action="store_true", help="also send one tiny request to each model (costs < $0.001)")
    doctor.set_defaults(func=cmd_doctor)

    scan = sub.add_parser("scan", help="scan a Maven repository and list findings (no models)")
    scan.add_argument("repo")
    scan.set_defaults(func=cmd_scan)

    run = sub.add_parser("run", help="run the full loop on a Maven repository")
    run.add_argument("repo")
    run.add_argument("--script", help="replay scripted model replies from this JSON file instead of calling models")
    run.add_argument("--yes", action="store_true", help="proceed even if the estimate is above BOP_WARN_USD")
    run.add_argument("--budget", type=float, help="spending cap for this run in US dollars")
    run.add_argument("--max-findings", type=int, help="process at most this many in-scope findings")
    run.add_argument("--estimate-only", action="store_true", help="prepare, scan and print the cost estimate")
    run.set_defaults(func=cmd_run)

    show = sub.add_parser("show", help="print a stored run")
    show.add_argument("run_id")
    show.set_defaults(func=cmd_show)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except BopError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
