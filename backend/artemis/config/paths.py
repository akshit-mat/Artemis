"""Filesystem locations for ARTEMIS state.

All ARTEMIS state lives under a single data directory so that privacy controls,
backup and purge have one place to operate on.  Production resolves to
``%LOCALAPPDATA%\\ARTEMIS``; tests override via ``ARTEMIS_DATA_DIR``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

DATA_DIR_ENV = "ARTEMIS_DATA_DIR"


def _default_local_app_data() -> Path:
    raw = os.environ.get("LOCALAPPDATA")
    if raw:
        return Path(raw)
    # Non-Windows (CI containers, developer machines) fall back to a stable
    # per-user location rather than the current working directory.
    return Path.home() / ".local" / "share"


@dataclass(frozen=True, slots=True)
class Paths:
    """Resolved, absolute paths.  Immutable once constructed."""

    data_dir: Path
    db_path: Path
    log_dir: Path
    config_file: Path
    blob_dir: Path

    @classmethod
    def resolve(cls, data_dir: Path | str | None = None) -> "Paths":
        if data_dir is not None:
            base = Path(data_dir)
        elif os.environ.get(DATA_DIR_ENV):
            base = Path(os.environ[DATA_DIR_ENV])
        else:
            base = _default_local_app_data() / "ARTEMIS"
        base = base.expanduser().resolve()
        return cls(
            data_dir=base,
            db_path=base / "artemis.db",
            log_dir=base / "logs",
            config_file=base / "artemis.toml",
            blob_dir=base / "blobs",
        )

    def ensure(self) -> None:
        """Create the directories ARTEMIS writes to.  Never creates files."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.blob_dir.mkdir(parents=True, exist_ok=True)
