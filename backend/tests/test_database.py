import pytest
import sqlite3
import asyncio
import threading
from artemis.storage.database import Database, DatabaseError
from artemis.config.schema import DbConfig
from pathlib import Path
from artemis.storage.migrations import init_db

@pytest.fixture
def db(tmp_path):
    db_path = tmp_path / "test.db"
    config = DbConfig(
        busy_timeout_ms=1000,
        read_pool_size=2,
        synchronous="NORMAL"
    )
    database = Database(db_path, config)
    database.open()
    init_db(database)
    yield database
    database.shutdown()

def test_db_lifecycle(tmp_path):
    db_path = tmp_path / "test2.db"
    config = DbConfig(read_pool_size=2)
    database = Database(db_path, config)
    
    # Repeated startup
    database.open()
    database.open() # Idempotent
    assert database.integrity_check() == "ok"
    
    # Repeated shutdown
    database.shutdown()
    database.shutdown() # Idempotent
    
    with pytest.raises(DatabaseError):
        database.query_sync("SELECT 1")

def test_db_concurrent_access(db):
    async def run_concurrent():
        # Test async write
        await db.execute_write("CREATE TABLE IF NOT EXISTS test_table (id INTEGER PRIMARY KEY, val TEXT)")
        
        async def write_task(val):
            await db.execute_write("INSERT INTO test_table (val) VALUES (?)", (val,))
            
        async def read_task():
            rows = await db.query("SELECT * FROM test_table")
            return len(rows)

        # Concurrently write
        await asyncio.gather(*(write_task(f"val{i}") for i in range(10)))
        
        count = await read_task()
        assert count == 10

    asyncio.run(run_concurrent())

def test_db_writer_thread_ownership(db):
    # Let's write a custom script that proves execution fails/rollbacks on error
    with pytest.raises(DatabaseError):
        db.execute_script_sync("BEGIN TRANSACTION; INSERT INTO schema_version (version) VALUES (9999); SYNTAX ERROR!; COMMIT;")
    
    # Ensure rollback happened
    rows = db.query_sync("SELECT * FROM schema_version WHERE version = 9999")
    assert len(rows) == 0

    # Ensure valid script works
    db.execute_script_sync("INSERT INTO schema_version (version) VALUES (9999);")
    rows = db.query_sync("SELECT * FROM schema_version WHERE version = 9999")
    assert len(rows) == 1
