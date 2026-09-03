import os
from pathlib import Path
from .database import Database
from ..obs.logging import get_logger

log = get_logger("migrations")
MIGRATIONS_DIR = Path(__file__).parent / "migrations"

def init_db(db: Database):
    try:
        # Schema version table
        db.execute_write_sync("""
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY
            )
        """)
        
        # Get current version
        rows = db.query_sync("SELECT MAX(version) as v FROM schema_version")
        current_version = rows[0]['v'] if rows and rows[0]['v'] is not None else 0
        
        log.info("migration_start", current_version=current_version)
        
        if not MIGRATIONS_DIR.exists():
            MIGRATIONS_DIR.mkdir(parents=True)
            
        migrations = sorted([f for f in os.listdir(MIGRATIONS_DIR) if f.endswith('.sql')])
        
        for migration_file in migrations:
            try:
                version = int(migration_file.split('_')[0])
            except ValueError:
                continue
                
            if version > current_version:
                log.info("applying_migration", version=version, file=migration_file)
                with open(MIGRATIONS_DIR / migration_file, 'r', encoding='utf-8') as f:
                    sql = f.read()
                
                script_with_version = f"{sql}\nINSERT INTO schema_version (version) VALUES ({version});"
                db.execute_script_sync(script_with_version)
                    
        log.info("migration_complete")
    except Exception as e:
        log.error("migration_failed", error=str(e))
        raise
