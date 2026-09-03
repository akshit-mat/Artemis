"""Typed configuration schema and layered loader.

Layering (``docs/architecture.md`` §7), later wins:

1. code defaults (this module)
2. ``%LOCALAPPDATA%\\ARTEMIS\\artemis.toml``
3. environment (``ARTEMIS_*``)
4. runtime settings in the ``settings`` table (read by callers, not here)

Invalid configuration raises :class:`ConfigError` and the process exits.  There
is no silent fallback to defaults: a typo in a security-relevant key must be
visible.  The security baseline (``config/baseline.py``) is applied *after*
every layer, so no layer can weaken it.
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from . import baseline
from .paths import Paths

ENV_PREFIX: Final[str] = "ARTEMIS_"

#: Env vars consumed by the process but not part of the config document.
#: ``ARTEMIS_AUTH_TOKEN`` is deliberately excluded from the config model so the
#: token can never be serialised by ``GET /v1/config``.
RESERVED_ENV: Final[frozenset[str]] = frozenset(
    {
        "ARTEMIS_AUTH_TOKEN",
        "ARTEMIS_DATA_DIR",
        "ARTEMIS_PORT",
        "ARTEMIS_HOST",
        "ARTEMIS_DEV_MODE",
    }
)


class ConfigError(RuntimeError):
    """Fatal configuration problem.  Always terminates startup."""


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class HttpConfig(_Model):
    max_body_bytes: int = Field(default=baseline.MAX_HTTP_BODY_BYTES, ge=1024)


class WsConfig(_Model):
    max_text_bytes: int = Field(default=baseline.MAX_WS_TEXT_BYTES, ge=1024)
    max_binary_bytes: int = Field(default=baseline.MAX_WS_BINARY_BYTES, ge=1024)
    max_connections: int = Field(default=8, ge=1)
    heartbeat_interval_s: float = Field(default=20.0, gt=0.5, le=300.0)
    heartbeat_misses: int = Field(default=2, ge=1, le=10)
    send_timeout_s: float = Field(default=5.0, gt=0.1, le=60.0)


class EventsConfig(_Model):
    replay_buffer_size: int = Field(default=500, ge=1)
    outbound_queue_max: int = Field(default=1000, ge=8)


class DbConfig(_Model):
    busy_timeout_ms: int = Field(default=5000, ge=100, le=60_000)
    read_pool_size: int = Field(default=4, ge=1)
    synchronous: Literal["OFF", "NORMAL", "FULL"] = "NORMAL"


class LoggingConfig(_Model):
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    retention_days: int = Field(default=14, ge=1)
    max_file_bytes: int = Field(default=16 * 1024 * 1024, ge=64 * 1024)
    max_backups: int = Field(default=5, ge=0, le=50)
    log_payloads: bool = False
    """Never log message payloads by default (``docs/architecture.md`` §8)."""


class AppConfig(_Model):
    """Root configuration document."""

    http: HttpConfig = HttpConfig()
    ws: WsConfig = WsConfig()
    events: EventsConfig = EventsConfig()
    db: DbConfig = DbConfig()
    logging: LoggingConfig = LoggingConfig()


# --------------------------------------------------------------------------
# Flatten / unflatten helpers
# --------------------------------------------------------------------------


def _flatten(data: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in data.items():
        dotted = f"{prefix}{key}"
        if isinstance(value, dict):
            out.update(_flatten(value, f"{dotted}."))
        else:
            out[dotted] = value
    return out


def _unflatten(flat: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for dotted, value in flat.items():
        parts = dotted.split(".")
        cursor = out
        for part in parts[:-1]:
            existing = cursor.get(part)
            if not isinstance(existing, dict):
                existing = {}
                cursor[part] = existing
            cursor = existing
        cursor[parts[-1]] = value
    return out


def _coerce_scalar(raw: str) -> Any:
    """Coerce an environment string into a TOML-ish scalar.

    Pydantic performs the real validation; this only distinguishes the obvious
    literal shapes so ``ARTEMIS_WS__MAX_CONNECTIONS=4`` yields an int.
    """
    lowered = raw.strip().lower()
    if lowered in ("true", "false"):
        return lowered == "true"
    try:
        return int(raw)
    except ValueError:
        pass
    try:
        return float(raw)
    except ValueError:
        pass
    return raw


def _env_overrides(environ: dict[str, str]) -> dict[str, Any]:
    """``ARTEMIS_WS__MAX_TEXT_BYTES`` -> ``ws.max_text_bytes``."""
    flat: dict[str, Any] = {}
    for name, raw in environ.items():
        if not name.startswith(ENV_PREFIX) or name in RESERVED_ENV:
            continue
        body = name[len(ENV_PREFIX) :]
        if not body:
            continue
        dotted = body.replace("__", ".").lower()
        flat[dotted] = _coerce_scalar(raw)
    return flat


def _reject_baseline_keys(flat: dict[str, Any], source: str) -> None:
    for key in flat:
        head = key.split(".", 1)[0]
        if key in baseline.BASELINE_OWNED_KEYS or head in baseline.BASELINE_OWNED_KEYS:
            raise ConfigError(
                f"{source}: key '{key}' is owned by the security baseline and "
                f"cannot be set by configuration (docs/security.md R-BASELINE)."
            )


def _load_toml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: invalid TOML: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"{path}: cannot be read: {exc}") from exc


def load_config(
    paths: Paths,
    environ: dict[str, str] | None = None,
    toml_text: str | None = None,
) -> tuple[AppConfig, list[tuple[str, int, int]]]:
    """Resolve the layered configuration.

    Returns the validated config plus the list of baseline clamps applied, so
    the caller can log each reduction. Raises :class:`ConfigError` on any
    invalid input.
    """
    environ = dict(os.environ if environ is None else environ)

    if toml_text is not None:
        try:
            file_layer = tomllib.loads(toml_text)
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"invalid TOML: {exc}") from exc
    else:
        file_layer = _load_toml(paths.config_file)

    flat_file = _flatten(file_layer)
    _reject_baseline_keys(flat_file, str(paths.config_file))

    flat_env = _env_overrides(environ)
    _reject_baseline_keys(flat_env, "environment")

    merged: dict[str, Any] = {**flat_file, **flat_env}
    clamps = baseline.clamp_to_baseline(merged)

    try:
        config = AppConfig.model_validate(_unflatten(merged))
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(p) for p in err['loc'])}: {err['msg']}" for err in exc.errors()
        )
        raise ConfigError(f"invalid configuration: {details}") from exc

    return config, clamps


def public_dict(config: AppConfig) -> dict[str, Any]:
    """Config as returned by ``GET /v1/config``.

    The auth token is not part of :class:`AppConfig` at all, so there is no
    field to accidentally serialise.
    """
    return config.model_dump(mode="json")
