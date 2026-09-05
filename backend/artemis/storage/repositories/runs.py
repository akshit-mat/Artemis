from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import sqlite3

from ..database import Database

class RunRepository:
    def __init__(self, db: Database):
        self.db = db

    async def create_run(self, id: str, session_id: str, model_id: str) -> None:
        """Create a new run in QUEUED state."""
        now = datetime.now(timezone.utc).isoformat()
        sql = """
            INSERT INTO runs (id, session_id, status, started_at, model_id, steps_used, tainted, input_tokens, output_tokens)
            VALUES (?, ?, 'QUEUED', ?, ?, 0, 0, 0, 0)
        """
        await self.db.execute_write(sql, (id, session_id, now, model_id))

    async def update_run_status(self,
                                id: str,
                                status: str,
                                error_code: Optional[str] = None,
                                cancel_reason: Optional[str] = None,
                                steps_used: Optional[int] = None,
                                input_tokens: Optional[int] = None,
                                output_tokens: Optional[int] = None,
                                tainted: Optional[bool] = None,
                                reasoning_blob_ref: Optional[str] = None) -> None:
        """Update a run's status and metadata. Ensures valid state transitions."""
        # Note: Valid transitions:
        # QUEUED -> RUNNING, CANCELLED
        # RUNNING -> DONE, CANCELLED, FAILED, INTERRUPTED

        now = datetime.now(timezone.utc).isoformat()

        # Build dynamic update
        updates = ["status = ?"]
        params: List[Any] = [status]

        if status in ("DONE", "CANCELLED", "FAILED", "INTERRUPTED"):
            updates.append("ended_at = ?")
            params.append(now)

        if error_code is not None:
            updates.append("error_code = ?")
            params.append(error_code)

        if cancel_reason is not None:
            updates.append("cancel_reason = ?")
            params.append(cancel_reason)

        if steps_used is not None:
            updates.append("steps_used = ?")
            params.append(steps_used)

        if input_tokens is not None:
            updates.append("input_tokens = ?")
            params.append(input_tokens)

        if output_tokens is not None:
            updates.append("output_tokens = ?")
            params.append(output_tokens)

        if tainted is not None:
            updates.append("tainted = ?")
            params.append(1 if tainted else 0)

        if reasoning_blob_ref is not None:
            updates.append("reasoning_blob_ref = ?")
            params.append(reasoning_blob_ref)

        params.append(id)

        # Ensure we don't overwrite a terminal state with another terminal state or DONE
        sql = f"""
            UPDATE runs
            SET {', '.join(updates)}
            WHERE id = ? AND status NOT IN ('DONE', 'CANCELLED', 'FAILED', 'INTERRUPTED')
        """
        await self.db.execute_write(sql, tuple(params))

    async def get_run(self, id: str) -> Optional[sqlite3.Row]:
        """Get a run by ID."""
        sql = "SELECT * FROM runs WHERE id = ?"
        rows = await self.db.query(sql, (id,))
        return rows[0] if rows else None

    async def get_active_run_for_session(self, session_id: str) -> Optional[sqlite3.Row]:
        """Get the currently active run for a session."""
        sql = """
            SELECT * FROM runs
            WHERE session_id = ? AND status IN ('QUEUED', 'RUNNING')
            ORDER BY started_at DESC LIMIT 1
        """
        rows = await self.db.query(sql, (session_id,))
        return rows[0] if rows else None
