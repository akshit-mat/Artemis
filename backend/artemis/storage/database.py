"""SQLite connection management.

Contract (``docs/architecture.md`` §6, ``docs/roadmap.md`` Phase 1·SQLite):

* WAL, ``synchronous=NORMAL``, ``foreign_keys=ON``, ``busy_timeout`` per config;
* one dedicated writer connection owned by a dedicated writer thread. All writes
  go through :func:`Database.execute_write`, never direct ``sqlite3.connect`` by
  other modules;
* a bounded pool of read-only connections for queries;
* repositories are the only modules allowed to build SQL (``storage/repositories``).
"""

from __future__ import annotations

import asyncio
import queue
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator, Sequence

from ..config.schema import DbConfig
from ..obs.logging import get_logger

log = get_logger("storage.db")


class DatabaseError(RuntimeError):
    """SQLite failure surfaced to callers as a stable, loggable error."""


class Database:
    """Owns the SQLite file and its connection discipline.

    ``open()`` is idempotent; ``close()``/``shutdown()`` are safe to call more
    than once.  A :class:`Database` is not safe to reopen after close.
    """

    def __init__(self, path: Path, config: DbConfig) -> None:
        self._path = path
        self._config = config
        
        self._writer_thread: threading.Thread | None = None
        self._writer_queue: queue.Queue[Any] = queue.Queue()
        
        self._read_pool: queue.Queue[sqlite3.Connection] = queue.Queue()
        self._closed = False

    # -- lifecycle -----------------------------------------------------------

    def open(self) -> None:
        if self._writer_thread is not None:
            return  # already open

        path = self._path
        path.parent.mkdir(parents=True, exist_ok=True)
        
        # Warm-up probe: fail loudly here (startup) rather than on first use.
        probe = sqlite3.connect(path)
        try:
            probe.execute(f"PRAGMA busy_timeout={self._config.busy_timeout_ms}")
            probe.execute("PRAGMA journal_mode=WAL")
            probe.execute("PRAGMA foreign_keys=ON")
        except sqlite3.Error as exc:
            raise DatabaseError(f"cannot open database: {exc}") from exc
        finally:
            probe.close()
            
        self._closed = False
        self._writer_thread = threading.Thread(target=self._writer_loop, name="Artemis-DBWriter")
        self._writer_thread.daemon = True
        self._writer_thread.start()

    def shutdown(self) -> None:
        """Close every connection.  No-op if already closed."""
        self._closed = True
        
        if self._writer_thread is not None:
            self._writer_queue.put(None)  # shutdown signal
            self._writer_thread.join()
            self._writer_thread = None

        while True:
            try:
                conn = self._read_pool.get_nowait()
            except queue.Empty:
                break
            try:
                conn.close()
            except sqlite3.Error:  # pragma: no cover - defensive
                pass

    # -- writer thread -------------------------------------------------------

    def _writer_loop(self) -> None:
        """The dedicated writer thread."""
        try:
            conn = sqlite3.connect(
                self._path,
                timeout=float(self._config.busy_timeout_ms) / 1000.0,
                check_same_thread=True  # Strictly bound to this thread
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(f"PRAGMA synchronous={self._config.synchronous}")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute(f"PRAGMA busy_timeout={self._config.busy_timeout_ms}")
        except sqlite3.Error as exc:
            log.error("db_writer_startup_error", error=str(exc))
            return

        while True:
            msg = self._writer_queue.get()
            if msg is None:
                self._writer_queue.task_done()
                break

            loop, fut, func = msg
            try:
                result = func(conn)
                if loop and fut:
                    loop.call_soon_threadsafe(fut.set_result, result)
            except BaseException as exc:
                if loop and fut:
                    loop.call_soon_threadsafe(fut.set_exception, exc)
                else:
                    log.error("db_writer_error", error=str(exc))
            finally:
                self._writer_queue.task_done()

        try:
            conn.close()
        except sqlite3.Error:
            pass

    # -- connections ---------------------------------------------------------

    def _connect_read(self, path: Path) -> sqlite3.Connection:
        conn = sqlite3.connect(
            path, 
            timeout=float(self._config.busy_timeout_ms) / 1000.0,
            check_same_thread=False
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(f"PRAGMA synchronous={self._config.synchronous}")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute(f"PRAGMA busy_timeout={self._config.busy_timeout_ms}")
        return conn

    @contextmanager
    def read_conn(self) -> Iterator[sqlite3.Connection]:
        """Checked-out read connection from the pool, returned on scope exit."""
        conn = self._acquire_read()
        try:
            yield conn
        finally:
            self._read_pool.put(conn)

    def _acquire_read(self) -> sqlite3.Connection:
        if self._closed:
            raise DatabaseError("database is closed")
        try:
            return self._read_pool.get_nowait()
        except queue.Empty:
            pass
        if self._read_pool.qsize() < self._config.read_pool_size:
            return self._connect_read(self._path)
        return self._read_pool.get(timeout=float(self._config.busy_timeout_ms) / 1000.0)

    # -- write path -----------------------------------------------------------

    async def execute_write(self, sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
        if self._closed or self._writer_thread is None:
            raise DatabaseError("database not open")

        loop = asyncio.get_running_loop()
        fut = loop.create_future()

        def _do_write(conn: sqlite3.Connection) -> list[sqlite3.Row]:
            try:
                with conn:
                    cursor = conn.execute(sql, params)
                    return list(cursor.fetchall())
            except sqlite3.Error as exc:
                log.error("db_write_error", error=str(exc))
                raise DatabaseError(str(exc)) from exc

        self._writer_queue.put((loop, fut, _do_write))
        return await fut

    def execute_write_sync(self, sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
        """Synchronous write for migrations and setup scripts."""
        if self._closed or self._writer_thread is None:
            raise DatabaseError("database not open")

        ev = threading.Event()
        result_box = []
        err_box = []

        def _do_write(conn: sqlite3.Connection) -> None:
            try:
                with conn:
                    cursor = conn.execute(sql, params)
                    result_box.append(list(cursor.fetchall()))
            except BaseException as exc:
                if isinstance(exc, sqlite3.Error):
                    log.error("db_write_error", error=str(exc))
                    err_box.append(DatabaseError(str(exc)))
                else:
                    err_box.append(exc)
            finally:
                ev.set()

        self._writer_queue.put((None, None, _do_write))
        ev.wait()

        if err_box:
            raise err_box[0]
        return result_box[0]

    def execute_script_sync(self, script: str) -> None:
        """Execute a full SQL script synchronously within a single transaction."""
        if self._closed or self._writer_thread is None:
            raise DatabaseError("database not open")

        ev = threading.Event()
        err_box = []

        def _do_write(conn: sqlite3.Connection) -> None:
            try:
                # executescript automatically commits any active transaction.
                # By explicitly starting one inside the script and committing manually,
                # we wrap the entire script in one transaction.
                conn.executescript("BEGIN TRANSACTION;\n" + script)
                conn.commit()
            except BaseException as exc:
                conn.rollback()
                if isinstance(exc, sqlite3.Error):
                    log.error("db_script_error", error=str(exc))
                    err_box.append(DatabaseError(str(exc)))
                else:
                    err_box.append(exc)
            finally:
                ev.set()

        self._writer_queue.put((None, None, _do_write))
        ev.wait()

        if err_box:
            raise err_box[0]

    def execute_transaction_sync(self, statements: list[tuple[str, Sequence[Any]]]) -> None:
        """Execute multiple statements synchronously within a single transaction."""
        if self._closed or self._writer_thread is None:
            raise DatabaseError("database not open")

        ev = threading.Event()
        err_box = []

        def _do_write(conn: sqlite3.Connection) -> None:
            try:
                with conn:
                    for sql, params in statements:
                        conn.execute(sql, params)
            except BaseException as exc:
                if isinstance(exc, sqlite3.Error):
                    log.error("db_transaction_error", error=str(exc))
                    err_box.append(DatabaseError(str(exc)))
                else:
                    err_box.append(exc)
            finally:
                ev.set()

        self._writer_queue.put((None, None, _do_write))
        ev.wait()

        if err_box:
            raise err_box[0]

    # -- read path -------------------------------------------------------------

    async def query(self, sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
        """Read query on the pool, off the event loop."""
        return await asyncio.to_thread(self.query_sync, sql, params)

    def query_sync(self, sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
        if self._closed:
            raise DatabaseError("database is closed")
        with self.read_conn() as conn:
            try:
                cursor = conn.execute(sql, params)
                return list(cursor.fetchall())
            except sqlite3.Error as exc:
                log.error("db_read_error", error=str(exc))
                raise DatabaseError(str(exc)) from exc

    # -- maintenance -----------------------------------------------------------

    def integrity_check(self) -> str:
        if self._closed:
            raise DatabaseError("database is closed")
        with self.read_conn() as conn:
            row = conn.execute("PRAGMA quick_check").fetchone()
        return str(row[0]) if row else "corrupt"
