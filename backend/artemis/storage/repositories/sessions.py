"""Session repository.

Provides idempotent session creation so the agent conversation path works
against an empty production database (``foreign_keys=ON`` requires the
session row to exist before any run or message that references it).

Phase 1 uses a single hardcoded session ID (``"s_test"``).  This module
exists so the orchestrator can guarantee the row is present without relying
on a migration seed or test fixtures.
"""

from __future__ import annotations

from datetime import datetime, timezone

from ..database import Database


class SessionRepository:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def ensure_session(self, session_id: str, title: str | None = None) -> None:
        """Ensure a session row exists; a no-op if it already does.

        Uses ``INSERT OR IGNORE`` so concurrent calls are safe and the method
        is idempotent — calling it twice with the same *session_id* is fine.
        This preserves the ``FOREIGN KEY`` constraint without weakening it:
        the row genuinely exists before any run that references it is inserted.
        """
        now = datetime.now(timezone.utc).isoformat()
        await self.db.execute_write(
            "INSERT OR IGNORE INTO sessions (id, title, created_at) VALUES (?, ?, ?)",
            (session_id, title, now),
        )

    async def get_sessions(self) -> list[dict]:
        """Fetch all sessions ordered by creation date descending."""
        rows = await self.db.query(
            "SELECT id, title, created_at FROM sessions ORDER BY created_at DESC"
        )
        return [{"id": row[0], "title": row[1] or row[0], "created_at": row[2]} for row in rows]

    async def get_session(self, session_id: str) -> dict | None:
        """Fetch a specific session by ID."""
        rows = await self.db.query(
            "SELECT id, title, created_at FROM sessions WHERE id = ?",
            (session_id,)
        )
        if not rows:
            return None
        row = rows[0]
        return {"id": row[0], "title": row[1] or row[0], "created_at": row[2]}
