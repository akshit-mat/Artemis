from typing import Any, Dict, List, Optional
from datetime import datetime, timezone
import sqlite3

from ..database import Database

class MessageRepository:
    def __init__(self, db: Database):
        self.db = db

    async def append_message(self,
                             id: str,
                             session_id: str,
                             role: str,
                             content: str,
                             trust: str = "USER",
                             token_estimate: Optional[int] = None,
                             run_id: Optional[str] = None) -> None:
        """Append a message to a session."""
        now = datetime.now(timezone.utc).isoformat()
        sql = """
            INSERT INTO messages (id, session_id, role, content, created_at, trust, token_estimate, run_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """
        await self.db.execute_write(sql, (id, session_id, role, content, now, trust, token_estimate, run_id))

    async def get_messages_for_session(self, session_id: str, limit: int = 100) -> List[sqlite3.Row]:
        """Get messages for a session, ordered by created_at ascending."""
        sql = """
            SELECT * FROM messages
            WHERE session_id = ? AND superseded_by IS NULL
            ORDER BY created_at ASC
            LIMIT ?
        """
        return await self.db.query(sql, (session_id, limit))
