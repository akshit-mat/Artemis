-- Add runs table and message metadata for Phase 2

-- Messages enhancements
ALTER TABLE messages ADD COLUMN trust TEXT DEFAULT 'USER';
ALTER TABLE messages ADD COLUMN token_estimate INTEGER;
ALTER TABLE messages ADD COLUMN run_id TEXT;
ALTER TABLE messages ADD COLUMN superseded_by TEXT;

-- Runs table
CREATE TABLE runs (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    model_id TEXT NOT NULL,
    steps_used INTEGER DEFAULT 0,
    tainted BOOLEAN DEFAULT 0,
    cancel_reason TEXT,
    error_code TEXT,
    input_tokens INTEGER DEFAULT 0,
    output_tokens INTEGER DEFAULT 0,
    reasoning_blob_ref TEXT,
    FOREIGN KEY(session_id) REFERENCES sessions(id)
);

-- Index for retrieving runs by session
CREATE INDEX idx_runs_session ON runs(session_id);

-- Index for messages by session
CREATE INDEX idx_messages_session ON messages(session_id);
