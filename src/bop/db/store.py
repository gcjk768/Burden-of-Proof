"""Thin SQLite access layer. One connection per Store; callers commit through it."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import Any


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class Store:
    def __init__(self, path: Path | str) -> None:
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(path))
        self.conn.row_factory = sqlite3.Row
        schema = resources.files("bop.db").joinpath("schema.sql").read_text(encoding="utf-8")
        self.conn.executescript(schema)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    # ------------------------------------------------------------------ generic helpers
    def _insert(self, table: str, values: Mapping[str, Any]) -> int:
        cols = ", ".join(values)
        marks = ", ".join("?" for _ in values)
        cur = self.conn.execute(f"INSERT INTO {table} ({cols}) VALUES ({marks})", tuple(values.values()))  # noqa: S608
        self.conn.commit()
        return int(cur.lastrowid or 0)

    def _update(self, table: str, key: str, key_value: Any, values: Mapping[str, Any]) -> None:
        sets = ", ".join(f"{col} = ?" for col in values)
        self.conn.execute(
            f"UPDATE {table} SET {sets} WHERE {key} = ?",  # noqa: S608
            (*values.values(), key_value),
        )
        self.conn.commit()

    def query(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        return list(self.conn.execute(sql, tuple(params)))

    # ------------------------------------------------------------------ runs
    def create_run(
        self,
        run_id: str,
        *,
        repo_path: str,
        commit_sha: str | None,
        mode: str,
        workdir: str,
        budget_usd: float,
        config: Mapping[str, Any],
    ) -> None:
        self._insert(
            "runs",
            {
                "id": run_id,
                "created_at": now(),
                "repo_path": repo_path,
                "commit_sha": commit_sha,
                "mode": mode,
                "status": "running",
                "stage": "created",
                "workdir": workdir,
                "budget_usd": budget_usd,
                "config_json": json.dumps(config, sort_keys=True),
            },
        )

    def update_run(self, run_id: str, **values: Any) -> None:
        if "baseline" in values:
            values["baseline_json"] = json.dumps(values.pop("baseline"))
        self._update("runs", "id", run_id, values)

    def get_run(self, run_id: str) -> sqlite3.Row | None:
        rows = self.query("SELECT * FROM runs WHERE id = ?", (run_id,))
        return rows[0] if rows else None

    def add_spend(self, run_id: str, usd: float) -> None:
        self.conn.execute("UPDATE runs SET spent_usd = spent_usd + ? WHERE id = ?", (usd, run_id))
        self.conn.commit()

    # ------------------------------------------------------------------ scans and findings
    def add_scan(self, **values: Any) -> int:
        values.setdefault("created_at", now())
        return self._insert("scans", values)

    def add_group(self, **values: Any) -> None:
        values.setdefault("updated_at", now())
        values.setdefault("state", "new")
        self._insert("finding_groups", values)

    def set_group_state(self, group_id: str, state: str, reason: str | None = None) -> None:
        self._update("finding_groups", "id", group_id, {"state": state, "state_reason": reason, "updated_at": now()})

    def add_finding(self, **values: Any) -> None:
        self._insert("findings", values)

    # ------------------------------------------------------------------ verdicts and evidence
    def add_verdict(self, *, evidence: Iterable[Mapping[str, Any]], **values: Any) -> int:
        values.setdefault("created_at", now())
        verdict_id = self._insert("verdicts", values)
        for item in evidence:
            self._insert("evidence", {"verdict_id": verdict_id, **item})
        return verdict_id

    def add_proof_test(self, **values: Any) -> int:
        values.setdefault("created_at", now())
        return self._insert("proof_tests", values)

    def add_patch(self, **values: Any) -> int:
        values.setdefault("created_at", now())
        return self._insert("patches", values)

    def add_suppression(self, **values: Any) -> int:
        values.setdefault("created_at", now())
        return self._insert("suppressions", values)

    # ------------------------------------------------------------------ cost and sandbox ledger
    def add_llm_call(self, **values: Any) -> int:
        values.setdefault("created_at", now())
        return self._insert("llm_calls", values)

    def add_runner_job(self, **values: Any) -> int:
        values.setdefault("created_at", now())
        return self._insert("runner_jobs", values)

    # ------------------------------------------------------------------ reporting queries
    def group_states(self, run_id: str) -> dict[str, int]:
        rows = self.query("SELECT state, COUNT(*) AS n FROM finding_groups WHERE run_id = ? GROUP BY state", (run_id,))
        return {row["state"]: row["n"] for row in rows}

    def spend_by_model(self, run_id: str) -> list[sqlite3.Row]:
        return self.query(
            """SELECT model, stage, COUNT(*) AS calls, SUM(prompt_tokens) AS prompt_tokens,
                      SUM(completion_tokens) AS completion_tokens, SUM(reasoning_tokens) AS reasoning_tokens,
                      SUM(cost_usd) AS cost_usd, SUM(cached) AS cached_calls
               FROM llm_calls WHERE run_id = ? GROUP BY model, stage ORDER BY cost_usd DESC""",
            (run_id,),
        )
