-- Burden of Proof run store. Large artifacts live on disk under runs/<run_id>/;
-- these tables hold their paths.
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    repo_path TEXT NOT NULL,
    commit_sha TEXT,
    mode TEXT NOT NULL,                -- live | replay
    status TEXT NOT NULL,              -- running | done | failed | budget_stopped
    stage TEXT,
    workdir TEXT NOT NULL,
    budget_usd REAL NOT NULL,
    spent_usd REAL NOT NULL DEFAULT 0,
    baseline_json TEXT,
    config_json TEXT,
    error TEXT
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id),
    tool TEXT NOT NULL,
    tool_version TEXT,
    phase TEXT NOT NULL,               -- initial | rescan
    group_id TEXT,
    exit_code INTEGER,
    sarif_path TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS finding_groups (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id),
    category TEXT NOT NULL,
    primary_finding_id TEXT,
    member_count INTEGER NOT NULL DEFAULT 1,
    state TEXT NOT NULL,               -- new | triaged | analysed | proven | not_proven | fixed | unfixed | suppressed | out_of_scope | undetermined
    state_reason TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id),
    scan_id INTEGER REFERENCES scans(id),
    group_id TEXT REFERENCES finding_groups(id),
    fingerprint TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    cwe TEXT,
    category TEXT NOT NULL,
    severity TEXT,
    file TEXT NOT NULL,
    start_line INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    message TEXT,
    snippet TEXT,
    in_scope INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS verdicts (
    id INTEGER PRIMARY KEY,
    group_id TEXT NOT NULL REFERENCES finding_groups(id),
    stage TEXT NOT NULL,               -- triage | analysis
    model TEXT,
    verdict TEXT NOT NULL,
    confidence REAL,
    summary TEXT,
    reasoning TEXT,
    fp_reason TEXT,
    taint_path_json TEXT,
    evidence_ok INTEGER NOT NULL,
    evidence_problems_json TEXT,
    llm_call_id INTEGER,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY,
    verdict_id INTEGER NOT NULL REFERENCES verdicts(id),
    role TEXT NOT NULL,
    file TEXT NOT NULL,
    start_line INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    excerpt TEXT NOT NULL,
    why TEXT,
    verified INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS proof_tests (
    id INTEGER PRIMARY KEY,
    group_id TEXT NOT NULL REFERENCES finding_groups(id),
    phase TEXT NOT NULL,               -- before_fix | after_fix
    attempt INTEGER NOT NULL,
    test_path TEXT,
    test_class TEXT,
    test_method TEXT,
    source_path TEXT,
    outcome TEXT NOT NULL,             -- rejected | compile_error | failed_right_reason | failed_other | passed | not_run | timeout
    detail TEXT,
    log_path TEXT,
    llm_call_id INTEGER,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS patches (
    id INTEGER PRIMARY KEY,
    group_id TEXT NOT NULL REFERENCES finding_groups(id),
    attempt INTEGER NOT NULL,
    diff_path TEXT,
    files_json TEXT,
    policy_ok INTEGER NOT NULL,
    proof_outcome TEXT,
    suite_outcome TEXT,
    rescan_outcome TEXT,
    accepted INTEGER NOT NULL,
    failure_summary TEXT,
    llm_call_id INTEGER,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS suppressions (
    id INTEGER PRIMARY KEY,
    group_id TEXT NOT NULL REFERENCES finding_groups(id),
    verdict_id INTEGER REFERENCES verdicts(id),
    rule_id TEXT NOT NULL,
    file TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    justification TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS llm_calls (
    id INTEGER PRIMARY KEY,
    run_id TEXT,
    group_id TEXT,
    stage TEXT NOT NULL,
    role TEXT NOT NULL,
    model TEXT NOT NULL,
    base_url TEXT,
    thinking INTEGER,
    prompt_tokens INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,
    reasoning_tokens INTEGER NOT NULL DEFAULT 0,
    cost_usd REAL NOT NULL DEFAULT 0,
    cached INTEGER NOT NULL DEFAULT 0,
    latency_ms INTEGER,
    request_hash TEXT,
    response_path TEXT,
    error TEXT,
    fallback_from TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runner_jobs (
    id INTEGER PRIMARY KEY,
    run_id TEXT,
    group_id TEXT,
    runner TEXT NOT NULL,
    purpose TEXT NOT NULL,
    argv_json TEXT NOT NULL,
    network INTEGER NOT NULL,
    timeout_s INTEGER,
    exit_code INTEGER,
    timed_out INTEGER NOT NULL DEFAULT 0,
    duration_ms INTEGER,
    log_path TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_groups_run ON finding_groups(run_id);
CREATE INDEX IF NOT EXISTS idx_llm_calls_run ON llm_calls(run_id);
