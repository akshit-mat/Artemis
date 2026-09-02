import os
import sqlite3
from pathlib import Path
from .database import get_db_connection
from ..obs.logging import log

MIGRATIONS_DIR = Path(__file__).parent / "migrations"

def init_db():
    conn = get_db_connection()
    try:
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY
                )
            """)
        
        cursor = conn.execute("SELECT MAX(version) as v FROM schema_version")
        row = cursor.fetchone()
        current_version = row['v'] if row and row['v'] is not None else 0
        
        log.info("migration_start", current_version=current_version)
        
        if not MIGRATIONS_DIR.exists():
            MIGRATIONS_DIR.mkdir(parents=True)
            
        migrations = sorted([f for f in os.listdir(MIGRATIONS_DIR) if f.endswith('.sql')])
        
        for migration_file in migrations:
            # Extract version from filename like 001_initial.sql
            try:
                version = int(migration_file.split('_')[0])
            except ValueError:
                continue
                
            if version > current_version:
                log.info("applying_migration", version=version, file=migration_file)
                with open(MIGRATIONS_DIR / migration_file, 'r', encoding='utf-8') as f:
                    sql = f.read()
                
                with conn:
                    conn.executescript(sql)
                    conn.execute("INSERT INTO schema_version (version) VALUES (?)", (version,))
                    
        log.info("migration_complete")
    finally:
        conn.close()
