from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
import os
from pathlib import Path

# Base configuration directory
LOCAL_APP_DATA = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local")))
ARTEMIS_DIR = LOCAL_APP_DATA / "ARTEMIS"
DB_PATH = ARTEMIS_DIR / "artemis.db"
LOG_DIR = ARTEMIS_DIR / "logs"

class Settings(BaseSettings):
    port: int = Field(default=0, description="Port to bind to. 0 means ephemeral.")
    host: str = Field(default="127.0.0.1", description="Host to bind to.")
    auth_token: str = Field(default="", description="Authentication token required for all requests.")
    
    model_config = SettingsConfigDict(
        env_prefix="ARTEMIS_",
        env_file=str(ARTEMIS_DIR / "artemis.env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()

# Ensure directories exist
ARTEMIS_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)
