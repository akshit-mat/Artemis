"""Hard security baseline.

Phase 0 invariant (``docs/security.md`` R-BASELINE, ADR-016): the security floor
lives in code and cannot be raised by any later configuration layer.  TOML, the
environment, the database and the UI may only *tighten* limits.

Two mechanisms enforce that:

* :data:`BASELINE_OWNED_KEYS` — dotted config keys that configuration may not
  set at all.  Attempting to set one is a fatal startup error, not a silent
  ignore, so a misconfiguration is loud.
* :func:`clamp_to_baseline` — numeric limits are clamped to the baseline
  maximum.  Configuration lowering a limit is honoured; raising it is refused.

This module must not import any other ARTEMIS module.  It has no dependencies
so that it cannot be subverted by import-order tricks.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Final, Mapping

# --------------------------------------------------------------------------
# Immutable transport facts
# --------------------------------------------------------------------------

#: The only addresses the backend may ever bind to.  ``docs/architecture.md`` §3.
ALLOWED_BIND_HOSTS: Final[frozenset[str]] = frozenset({"127.0.0.1", "::1"})

#: Origin allowlist for release builds (``docs/api.md`` §1).
PRODUCTION_ORIGINS: Final[frozenset[str]] = frozenset({"http://tauri.localhost"})

#: Additional origin permitted *only* in development builds (Vite dev server).
DEVELOPMENT_ORIGINS: Final[frozenset[str]] = frozenset({"http://localhost:1420"})

#: Subprotocol the WebSocket handshake negotiates.  The bearer subprotocol is
#: never echoed back, because that would place the token in a response header.
WS_SUBPROTOCOL: Final[str] = "artemis.v1"

#: Prefix carrying the bearer token in the WebSocket subprotocol list.
WS_BEARER_PREFIX: Final[str] = "bearer."

#: Wire envelope version.
PROTOCOL_VERSION: Final[int] = 1

#: Minimum accepted auth-token length in hex characters (256 bits).
MIN_TOKEN_HEX_CHARS: Final[int] = 64

#: Requests to these paths do not require a bearer token.  Deliberately tiny
#: and closed: it is a literal, not a prefix match.
UNAUTHENTICATED_PATHS: Final[frozenset[str]] = frozenset({"/health"})

#: Paths that do not require an ``Origin`` header.  ``/health`` is a liveness
#: probe used by the Rust supervisor, which is not a browser.
ORIGIN_EXEMPT_PATHS: Final[frozenset[str]] = frozenset({"/health"})

# --------------------------------------------------------------------------
# Numeric ceilings (configuration may lower these, never raise them)
# --------------------------------------------------------------------------

MAX_HTTP_BODY_BYTES: Final[int] = 1 * 1024 * 1024  # docs/api.md §1
MAX_WS_TEXT_BYTES: Final[int] = 256 * 1024  # docs/api.md §1
MAX_WS_BINARY_BYTES: Final[int] = 64 * 1024  # docs/api.md §1
MAX_REPLAY_BUFFER: Final[int] = 5_000  # bounded replay storage
MAX_OUTBOUND_QUEUE: Final[int] = 10_000  # bounded per-connection queue
MAX_WS_CONNECTIONS: Final[int] = 64  # bounded subscriber set
MAX_LOG_FILE_BYTES: Final[int] = 64 * 1024 * 1024
MAX_LOG_RETENTION_DAYS: Final[int] = 365
MAX_READ_POOL_SIZE: Final[int] = 16

#: dotted config key -> baseline ceiling.  Values are integers only.
_CEILINGS: Final[Mapping[str, int]] = MappingProxyType(
    {
        "http.max_body_bytes": MAX_HTTP_BODY_BYTES,
        "ws.max_text_bytes": MAX_WS_TEXT_BYTES,
        "ws.max_binary_bytes": MAX_WS_BINARY_BYTES,
        "ws.max_connections": MAX_WS_CONNECTIONS,
        "events.replay_buffer_size": MAX_REPLAY_BUFFER,
        "events.outbound_queue_max": MAX_OUTBOUND_QUEUE,
        "logging.max_file_bytes": MAX_LOG_FILE_BYTES,
        "logging.retention_days": MAX_LOG_RETENTION_DAYS,
        "db.read_pool_size": MAX_READ_POOL_SIZE,
    }
)

#: Configuration may not express these at all; they are decided by code.
BASELINE_OWNED_KEYS: Final[frozenset[str]] = frozenset(
    {
        "security",  # whole section is code-owned
        "security.allowed_origins",
        "security.require_auth",
        "security.ws_subprotocol",
        "http.require_origin",
        "policy",  # future phases: the policy baseline is code-owned
        "auth_token",  # secrets never come from a config file
        "token",
    }
)


def ceilings() -> Mapping[str, int]:
    """Read-only view of the numeric ceilings (used by tests and docs)."""
    return _CEILINGS


def clamp_to_baseline(flat: dict[str, object]) -> list[tuple[str, int, int]]:
    """Clamp a *flattened* config mapping in place.

    Returns the list of ``(key, requested, clamped)`` triples that were reduced,
    so the caller can log them loudly.
    """
    reductions: list[tuple[str, int, int]] = []
    for key, ceiling in _CEILINGS.items():
        if key not in flat:
            continue
        value = flat[key]
        if isinstance(value, bool) or not isinstance(value, int):
            continue  # schema validation reports the type error
        if value > ceiling:
            reductions.append((key, value, ceiling))
            flat[key] = ceiling
    return reductions


def allowed_origins(dev_mode: bool) -> frozenset[str]:
    """Origin allowlist.  ``dev_mode`` may only *add* the Vite dev origin."""
    if dev_mode:
        return PRODUCTION_ORIGINS | DEVELOPMENT_ORIGINS
    return PRODUCTION_ORIGINS


def is_loopback_host(host: str) -> bool:
    return host in ALLOWED_BIND_HOSTS
