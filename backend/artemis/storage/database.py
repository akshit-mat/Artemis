import sqlite3
import asyncio
from pathlib import Path
from contextlib import contextmanager

from ..config.settings import DB_PATH
from ..obs.logging import log

# Global single-writer lock as specified in Phase 0
writer_lock = asyncio.Lock()

def get_db_connection(path: Path = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    
    # Phase 0 specified pragmas
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    
    return conn

@contextmanager
def get_read_conn():
    conn = get_db_connection()
    try:
        yield conn
    finally:
        conn.close()

async def execute_write(query: str, params: tuple = ()):
    async with writer_lock:
        return await asyncio.to_thread(_execute_write_sync, query, params)

def _execute_write_sync(query: str, params: tuple):
    conn = get_db_connection()
    try:
        with conn:
            cursor = conn.execute(query, params)
            return cursor.fetchall()
    except Exception as e:
        log.error("db_write_error", error=str(e), query=query)
        raise
    finally:
        conn.close()
