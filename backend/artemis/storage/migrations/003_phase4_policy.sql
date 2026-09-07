-- Phase 4/5: policy rules, grants, approvals, audit log, tool results.
--
-- docs/security.md §3 (rules/grants), §7 (audit_log); docs/tools.md §2
-- (result_id retrievable via GET /v1/results/{id}).  Raw SQL, forward-only,
-- numbered (ADR-013).  Nothing here weakens the code-owned hard-deny baseline:
-- these tables can only express decisions at or below it, which the policy
-- engine enforces on every evaluation and the startup self-test re-checks.

CREATE TABLE policy_rules (
    id          TEXT PRIMARY KEY,
    tool_name   TEXT NOT NULL,
    category    TEXT,
    decision    TEXT NOT NULL CHECK (decision IN ('ALLOW', 'ASK', 'DENY')),
    scope_json  TEXT,
    source      TEXT NOT NULL CHECK (source IN ('builtin', 'user', 'mode')),
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    note        TEXT
);

CREATE UNIQUE INDEX idx_policy_rules_tool ON policy_rules(tool_name);

CREATE TABLE policy_grants (
    id                 TEXT PRIMARY KEY,
    tool_name          TEXT NOT NULL,
    scope_json         TEXT NOT NULL,
    granted_at         TEXT NOT NULL,
    expires_at         TEXT,
    max_uses           INTEGER,
    uses               INTEGER NOT NULL DEFAULT 0,
    origin_approval_id TEXT,
    revoked_at         TEXT,
    session_id         TEXT,
    last_used_at       TEXT
);

CREATE INDEX idx_policy_grants_tool ON policy_grants(tool_name);

-- Approval ids are server-issued single-use nonces (docs/api.md §6).  The row
-- records the exact tool identity and argument hash the approval was issued
-- for, so a replayed or re-pointed response is rejected.
CREATE TABLE approvals (
    id            TEXT PRIMARY KEY,
    run_id        TEXT NOT NULL,
    session_id    TEXT NOT NULL,
    call_id       TEXT,
    task_id       TEXT,
    tool_name     TEXT NOT NULL,
    args_hash     TEXT NOT NULL,
    risk          TEXT NOT NULL,
    action_text   TEXT NOT NULL,
    targets_json  TEXT NOT NULL DEFAULT '[]',
    item_count    INTEGER NOT NULL DEFAULT 0,
    total_bytes   INTEGER,
    reversible    INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    resolved_at   TEXT,
    outcome       TEXT CHECK (outcome IN ('allowed', 'denied', 'timeout')),
    scope         TEXT,
    consumed_at   TEXT
);

CREATE INDEX idx_approvals_run ON approvals(run_id);

CREATE TABLE audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              TEXT NOT NULL,
    run_id          TEXT,
    task_id         TEXT,
    actor           TEXT NOT NULL CHECK (actor IN ('user', 'model', 'system')),
    tool_name       TEXT,
    event           TEXT NOT NULL,
    args_digest     TEXT,
    resolved_target TEXT,
    decision        TEXT,
    rule_id         TEXT,
    reason          TEXT,
    taint           INTEGER NOT NULL DEFAULT 0,
    approval_id     TEXT,
    outcome         TEXT,
    duration_ms     INTEGER,
    error_code      TEXT
);

CREATE INDEX idx_audit_ts ON audit_log(ts);
CREATE INDEX idx_audit_tool ON audit_log(tool_name);
CREATE INDEX idx_audit_decision ON audit_log(decision);

-- Full tool results live here; only a bounded ``context_view`` enters the
-- prompt (docs/agent.md §4 anti-bloat #1).
CREATE TABLE tool_results (
    id           TEXT PRIMARY KEY,
    run_id       TEXT NOT NULL,
    session_id   TEXT NOT NULL,
    call_id      TEXT,
    tool_name    TEXT NOT NULL,
    status       TEXT NOT NULL,
    summary      TEXT NOT NULL,
    data_json    TEXT,
    context_view TEXT,
    trust        TEXT NOT NULL DEFAULT 'SYSTEM',
    duration_ms  INTEGER NOT NULL DEFAULT 0,
    error_code   TEXT,
    truncated    INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT NOT NULL
);

CREATE INDEX idx_tool_results_run ON tool_results(run_id);

-- Undo manifests for reversible mutations (move-back / recycle-bin restore).
CREATE TABLE undo_manifests (
    id         TEXT PRIMARY KEY,
    run_id     TEXT NOT NULL,
    tool_name  TEXT NOT NULL,
    kind       TEXT NOT NULL,
    items_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    applied_at TEXT
);
