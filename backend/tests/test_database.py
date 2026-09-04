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

def test_migration_idempotency(db):
    """Running init_db again on a fully migrated DB should be safe and idempotent."""
    current_version = db.query_sync("SELECT MAX(version) as v FROM schema_version")[0]['v']

    # Run again
    init_db(db)

    # Version should not change and no errors should be thrown
    new_version = db.query_sync("SELECT MAX(version) as v FROM schema_version")[0]['v']
    assert new_version == current_version

def test_migration_forward_only(db, tmp_path, monkeypatch):
    """Migrations should never apply if they are older than the current schema_version."""
    import artemis.storage.migrations as mig

    current_version = db.query_sync("SELECT MAX(version) as v FROM schema_version")[0]['v']

    # Create a fake older migration in a temporary directory
    fake_mig_dir = tmp_path / "fake_migrations"
    fake_mig_dir.mkdir()

    # This migration is older (version 0), so it should be skipped
    older_sql = fake_mig_dir / "0000_old.sql"
    older_sql.write_text("CREATE TABLE should_not_exist (id INTEGER);")

    # This migration is newer, so it should run
    newer_version = current_version + 1
    newer_sql = fake_mig_dir / f"{newer_version:04d}_new.sql"
    newer_sql.write_text("CREATE TABLE should_exist (id INTEGER);")

    monkeypatch.setattr(mig, "MIGRATIONS_DIR", fake_mig_dir)

    # Run migrator
    mig.init_db(db)

    # The new table should exist, but the old one should NOT
    assert db.query_sync("SELECT name FROM sqlite_master WHERE name='should_exist'")
    assert not db.query_sync("SELECT name FROM sqlite_master WHERE name='should_not_exist'")

    # The version should be updated
    assert db.query_sync("SELECT MAX(version) as v FROM schema_version")[0]['v'] == newer_version

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
