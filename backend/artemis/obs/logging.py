"""Structured JSON logging with structural redaction.

Rules from ``docs/architecture.md`` §8:

* JSON lines, one per event, to ``stderr`` **and** a rotating file.
* ``stdout`` is reserved for the single-line startup handshake and must never
  carry log output — writing logs there would corrupt the supervisor protocol.
* Redaction is structural: sensitive keys are replaced with a non-reversible
  digest, not matched by regex over a rendered string.
* Payloads are not logged by default; unbounded strings are truncated.
"""

from __future__ import annotations

import logging
import logging.handlers
import os
import sys
import time
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Final, Iterator, MutableMapping

import structlog

from ..config.schema import LoggingConfig

#: Keys whose values are never emitted.  Matched case-insensitively against the
#: whole key, and also as a substring for the obvious secret words.
SENSITIVE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "token",
        "auth_token",
        "authorization",
        "bearer",
        "password",
        "passwd",
        "secret",
        "credential",
        "credentials",
        "api_key",
        "apikey",
        "cookie",
        "set-cookie",
        "session_key",
        "private_key",
    }
)

#: Substrings that force redaction regardless of the surrounding key name.
SENSITIVE_SUBSTRINGS: Final[tuple[str, ...]] = ("token", "secret", "password", "credential")

#: Any string field longer than this is truncated.  Prevents a hostile or buggy
#: caller from writing an unbounded payload into the log.
MAX_FIELD_CHARS: Final[int] = 512

#: Keys that legitimately carry a short non-secret identifier derived from a
#: secret and must therefore survive redaction.
REDACTION_ALLOWLIST: Final[frozenset[str]] = frozenset({"token_fingerprint"})

_run_id: ContextVar[str | None] = ContextVar("artemis_run_id", default=None)
_session_id: ContextVar[str | None] = ContextVar("artemis_session_id", default=None)
_conn_id: ContextVar[str | None] = ContextVar("artemis_conn_id", default=None)

_configured = False


def _digest(value: object) -> str:
    raw = value if isinstance(value, (str, bytes)) else repr(value)
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "replace")
    return f"«redacted:{sha256(raw).hexdigest()[:8]}»"


def _is_sensitive(key: str) -> bool:
    lowered = key.lower()
    if lowered in REDACTION_ALLOWLIST:
        return False
    if lowered in SENSITIVE_KEYS:
        return True
    return any(part in lowered for part in SENSITIVE_SUBSTRINGS)


def _scrub(value: Any, depth: int = 0) -> Any:
    if depth > 4:
        return "«depth-limited»"
    if isinstance(value, str):
        if len(value) > MAX_FIELD_CHARS:
            return value[:MAX_FIELD_CHARS] + f"…[truncated {len(value) - MAX_FIELD_CHARS} chars]"
        return value
    if isinstance(value, dict):
        return {
            str(k): (_digest(v) if _is_sensitive(str(k)) else _scrub(v, depth + 1))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        trimmed = list(value)[:32]
        return [_scrub(item, depth + 1) for item in trimmed]
    if isinstance(value, (bytes, bytearray, memoryview)):
        return f"«bytes:{len(value)}»"
    return value


def redact_processor(
    _logger: object, _method: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    """Replace sensitive values and truncate oversized ones."""
    for key in list(event_dict.keys()):
        if _is_sensitive(str(key)):
            event_dict[key] = _digest(event_dict[key])
        else:
            event_dict[key] = _scrub(event_dict[key])
    return event_dict


def correlation_processor(
    _logger: object, _method: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    """Attach ambient correlation ids when the caller did not supply them."""
    for name, var in (("run_id", _run_id), ("session_id", _session_id), ("conn_id", _conn_id)):
        if name not in event_dict:
            value = var.get()
            if value is not None:
                event_dict[name] = value
    return event_dict


def bind_correlation(
    *, run_id: str | None = None, session_id: str | None = None, conn_id: str | None = None
) -> None:
    """Set ambient correlation ids for the current task/context."""
    if run_id is not None:
        _run_id.set(run_id)
    if session_id is not None:
        _session_id.set(session_id)
    if conn_id is not None:
        _conn_id.set(conn_id)


def clear_correlation() -> None:
    _run_id.set(None)
    _session_id.set(None)
    _conn_id.set(None)


def log_file_path(log_dir: Path, now: datetime | None = None) -> Path:
    """``artemis-YYYYMMDD.jsonl`` — ``%m`` is the month, not ``%M``."""
    stamp = (now or datetime.now(timezone.utc)).strftime("%Y%m%d")
    return log_dir / f"artemis-{stamp}.jsonl"


def purge_old_logs(log_dir: Path, retention_days: int, now: datetime | None = None) -> list[Path]:
    """Delete log files whose mtime is older than the retention window."""
    if not log_dir.exists():
        return []
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=retention_days)
    removed: list[Path] = []
    for entry in _log_files(log_dir):
        try:
            mtime = datetime.fromtimestamp(entry.stat().st_mtime, timezone.utc)
        except OSError:
            continue
        if mtime < cutoff:
            try:
                entry.unlink()
                removed.append(entry)
            except OSError:
                continue
    return removed


def _log_files(log_dir: Path) -> Iterator[Path]:
    for entry in log_dir.iterdir():
        if entry.is_file() and entry.name.startswith("artemis-") and ".jsonl" in entry.name:
            yield entry


def configure_logging(
    log_dir: Path | None,
    config: LoggingConfig,
    *,
    component: str = "core",
    force: bool = False,
) -> None:
    """Install the JSON logging pipeline.  Idempotent unless ``force``."""
    global _configured
    if _configured and not force:
        return

    shared = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        correlation_processor,
        redact_processor,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer(sort_keys=True),
    ]

    structlog.configure(
        processors=shared,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=not force,
    )

    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
        try:
            handler.close()
        except Exception:  # pragma: no cover - best effort
            pass

    formatter = logging.Formatter("%(message)s")

    # stderr, never stdout: stdout carries the supervisor handshake.
    stream = logging.StreamHandler(sys.stderr)
    stream.setFormatter(formatter)
    root.addHandler(stream)

    if log_dir is not None:
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
            purge_old_logs(log_dir, config.retention_days)
            file_handler = logging.handlers.RotatingFileHandler(
                log_file_path(log_dir),
                maxBytes=config.max_file_bytes,
                backupCount=config.max_backups,
                encoding="utf-8",
                delay=True,
            )
            file_handler.setFormatter(formatter)
            root.addHandler(file_handler)
        except OSError as exc:  # pragma: no cover - disk failure path
            print(
                f'{{"level":"error","event":"log_file_unavailable","error":"{exc}"}}',
                file=sys.stderr,
                flush=True,
            )

    root.setLevel(getattr(logging, config.level))
    # Uvicorn writes its own access/error records; route them through us and
    # keep them quiet so they cannot interleave with the handshake.
    for noisy in ("uvicorn", "uvicorn.error", "uvicorn.access", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    structlog.contextvars.bind_contextvars(component=component, pid=os.getpid())
    _configured = True


def get_logger(component: str | None = None) -> structlog.stdlib.BoundLogger:
    logger = structlog.get_logger("artemis")
    if component:
        return logger.bind(component=component)
    return logger


class Timer:
    """Measure a span in milliseconds for the ``duration_ms`` log field."""

    __slots__ = ("_start",)

    def __enter__(self) -> "Timer":
        self._start = time.perf_counter()
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    @property
    def duration_ms(self) -> int:
        return int((time.perf_counter() - self._start) * 1000)
