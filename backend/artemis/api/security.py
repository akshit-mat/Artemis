"""Transport security primitives.

Single source of truth for the three checks every request must pass
(``docs/api.md`` §1, ``docs/security.md`` §2 R-AUTH):

1. loopback bind (enforced at socket creation, see ``artemis/main.py``)
2. bearer token, constant-time compared
3. exact ``Host`` and allowlisted ``Origin``

Nothing here reads global state: a :class:`TransportPolicy` is constructed once
from the actually-bound address and injected.  That keeps the production code
free of test special-cases such as accepting ``Host: testserver``.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from enum import Enum
from typing import Final

from ..config import baseline

_HEX_RE: Final[re.Pattern[str]] = re.compile(r"\A[0-9a-fA-F]+\Z")
_BEARER_RE: Final[re.Pattern[str]] = re.compile(r"\ABearer ([A-Za-z0-9._\-+/=]+)\Z")

#: Hard cap on how many subprotocols we will examine, so a hostile handshake
#: cannot make us do unbounded work.
MAX_SUBPROTOCOLS: Final[int] = 8


class TokenError(RuntimeError):
    """The per-launch auth token is missing or unusable."""


class AuthToken:
    """A per-launch bearer token.

    Structurally unloggable: ``__repr__``/``__str__`` are redacted and the raw
    value is stored in a private slot with no accessor.  This encodes Phase 0
    invariants 9 and 10 (never persisted, never logged) in the type rather than
    relying on reviewer discipline.
    """

    __slots__ = ("_value", "_fingerprint")

    def __init__(self, value: str) -> None:
        if not value:
            raise TokenError("auth token is empty")
        if len(value) < baseline.MIN_TOKEN_HEX_CHARS:
            raise TokenError(
                f"auth token must be at least {baseline.MIN_TOKEN_HEX_CHARS} hex "
                f"characters (256 bits); got {len(value)}"
            )
        if not _HEX_RE.match(value):
            raise TokenError("auth token must be hexadecimal")
        self._value = value
        self._fingerprint = hashlib.sha256(value.encode("ascii")).hexdigest()[:8]

    @classmethod
    def from_environ(cls, environ: dict[str, str], *, consume: bool = True) -> "AuthToken":
        """Read the token from the environment and remove it from the mapping.

        Consuming the variable means the value cannot later be inherited by a
        child process or dumped by an environment introspection endpoint.
        """
        raw = environ.get("ARTEMIS_AUTH_TOKEN")
        if raw is None:
            raise TokenError(
                "ARTEMIS_AUTH_TOKEN is not set. The backend must be launched by "
                "the ARTEMIS shell, which mints a fresh token per launch."
            )
        token = cls(raw.strip())
        if consume:
            environ.pop("ARTEMIS_AUTH_TOKEN", None)
        return token

    @property
    def fingerprint(self) -> str:
        """Short, non-reversible identifier safe to put in logs."""
        return self._fingerprint

    def verify(self, presented: str | None) -> bool:
        if not presented:
            return False
        return hmac.compare_digest(self._value, presented)

    def verify_bearer(self, header: str | None) -> bool:
        """Validate an ``Authorization: Bearer <token>`` header."""
        if not header:
            return False
        match = _BEARER_RE.match(header)
        if match is None:
            # Malformed header shape (wrong scheme, extra whitespace, no value).
            # Still burn a comparison so shape errors and value errors take a
            # similar amount of time.
            hmac.compare_digest(self._value, "")
            return False
        return self.verify(match.group(1))

    def verify_subprotocols(self, offered: list[str] | tuple[str, ...] | None) -> bool:
        """Validate the WebSocket subprotocol list.

        Requires ``artemis.v1`` and exactly one ``bearer.<token>`` entry whose
        token matches.  The bearer entry is never echoed back to the client.
        """
        if not offered:
            return False
        if len(offered) > MAX_SUBPROTOCOLS:
            return False
        items = [item.strip() for item in offered]
        if baseline.WS_SUBPROTOCOL not in items:
            return False
        bearers = [i for i in items if i.startswith(baseline.WS_BEARER_PREFIX)]
        if len(bearers) != 1:
            return False
        return self.verify(bearers[0][len(baseline.WS_BEARER_PREFIX) :])

    # -- redaction ---------------------------------------------------------
    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"<AuthToken fp={self._fingerprint} redacted>"

    __str__ = __repr__

    def __format__(self, _spec: str) -> str:  # pragma: no cover - trivial
        return self.__repr__()

    def __reduce__(self):  # pragma: no cover - defensive
        raise TypeError("AuthToken is not serialisable")


class OriginVerdict(str, Enum):
    OK = "ok"
    MISSING = "missing"
    REJECTED = "rejected"


@dataclass(frozen=True, slots=True)
class TransportPolicy:
    """Immutable per-launch transport rules."""

    expected_hosts: frozenset[str]
    allowed_origins: frozenset[str]
    dev_mode: bool

    @classmethod
    def for_binding(cls, host: str, port: int, *, dev_mode: bool) -> "TransportPolicy":
        if not baseline.is_loopback_host(host):
            raise ValueError(
                f"refusing to serve on non-loopback host {host!r} "
                f"(docs/architecture.md §3)"
            )
        if host == "::1":
            authority = f"[::1]:{port}"
        else:
            authority = f"{host}:{port}"
        return cls(
            expected_hosts=frozenset({authority}),
            allowed_origins=baseline.allowed_origins(dev_mode),
            dev_mode=dev_mode,
        )

    @classmethod
    def for_testing(cls, hosts: frozenset[str], *, dev_mode: bool = False) -> "TransportPolicy":
        """Explicit test constructor.

        Tests must state which ``Host`` values they use.  Production code never
        contains a test hostname, so a test helper cannot loosen production.
        """
        return cls(
            expected_hosts=hosts,
            allowed_origins=baseline.allowed_origins(dev_mode),
            dev_mode=dev_mode,
        )

    def check_host(self, host: str | None) -> bool:
        if not host:
            return False
        candidate = host.strip().lower()
        if candidate != host.strip():
            # Host headers are case-insensitive; compare the folded form only.
            pass
        return candidate in {h.lower() for h in self.expected_hosts}

    def check_origin(self, origin: str | None) -> OriginVerdict:
        if origin is None or origin == "":
            return OriginVerdict.MISSING
        if origin.strip() in self.allowed_origins:
            return OriginVerdict.OK
        return OriginVerdict.REJECTED

    def requires_auth(self, path: str) -> bool:
        return path not in baseline.UNAUTHENTICATED_PATHS

    def requires_origin(self, path: str) -> bool:
        return path not in baseline.ORIGIN_EXEMPT_PATHS
