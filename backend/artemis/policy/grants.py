"""Policy grants — scoped, expiring, revocable authority.

``docs/security.md`` §3 "Grants".  A grant is *structural*: it names concrete
paths, operations and caps, never a free-text label.  Matching is therefore
decidable in code and testable, and a ``Downloads`` grant provably cannot cover
``Documents``, a parent, a shared-prefix sibling, or a junction target (because
the paths being matched are already canonical).

Grants can only be consumed through :meth:`GrantScope.covers`; there is no
"trust the label" path.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Optional, Sequence

from .paths import CanonicalPath, comparison_key, is_contained, segments_of


class GrantScopeError(ValueError):
    """A scope document that cannot be interpreted.  Treated as no grant."""


@dataclass(frozen=True, slots=True)
class GrantScope:
    """Structural scope of a grant.

    ``{"paths": [...], "recursive": true, "ops": ["move","delete"],
       "max_items": 50}``
    """

    paths: tuple[str, ...] = ()
    recursive: bool = True
    ops: frozenset[str] = frozenset()
    max_items: Optional[int] = None
    _segments: tuple[tuple[str, ...], ...] = field(default=(), repr=False, compare=False)

    @classmethod
    def parse(cls, document: str | dict[str, Any] | None) -> "GrantScope":
        if document is None or document == "":
            return cls()
        if isinstance(document, str):
            try:
                data = json.loads(document)
            except json.JSONDecodeError as exc:
                raise GrantScopeError(f"invalid scope JSON: {exc}") from exc
        else:
            data = document
        if not isinstance(data, dict):
            raise GrantScopeError("scope must be a JSON object")

        raw_paths = data.get("paths") or []
        if not isinstance(raw_paths, list) or any(not isinstance(p, str) for p in raw_paths):
            raise GrantScopeError("scope.paths must be a list of strings")
        paths = tuple(p.rstrip("\\") for p in raw_paths if p)

        raw_ops = data.get("ops") or []
        if not isinstance(raw_ops, list) or any(not isinstance(o, str) for o in raw_ops):
            raise GrantScopeError("scope.ops must be a list of strings")

        max_items = data.get("max_items")
        if max_items is not None and (not isinstance(max_items, int) or max_items < 0):
            raise GrantScopeError("scope.max_items must be a non-negative integer")

        return cls(
            paths=paths,
            recursive=bool(data.get("recursive", True)),
            ops=frozenset(o.lower() for o in raw_ops),
            max_items=max_items,
            _segments=tuple(segments_of(p) for p in paths),
        )

    def to_json(self) -> str:
        payload: dict[str, Any] = {"recursive": self.recursive}
        if self.paths:
            payload["paths"] = list(self.paths)
        if self.ops:
            payload["ops"] = sorted(self.ops)
        if self.max_items is not None:
            payload["max_items"] = self.max_items
        return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))

    # -- matching -----------------------------------------------------------

    def covers_op(self, op: str) -> bool:
        return not self.ops or op.lower() in self.ops

    def covers_path(self, candidate: CanonicalPath | str) -> bool:
        """Segment-wise structural containment of a single canonical path."""
        if not self.paths:
            return False
        path = candidate.path if isinstance(candidate, CanonicalPath) else candidate
        segments = (
            candidate.segments if isinstance(candidate, CanonicalPath) else segments_of(path)
        )
        for scope_path, scope_segments in zip(self.paths, self._segments or tuple(
            segments_of(p) for p in self.paths
        )):
            if self.recursive:
                if is_contained(segments, scope_segments):
                    return True
            elif comparison_key(path) == comparison_key(scope_path):
                return True
        return False

    def covers(
        self,
        *,
        op: str,
        paths: Sequence[CanonicalPath] = (),
        item_count: int = 1,
    ) -> bool:
        """A grant covers a call only if it covers **every** aspect of it."""
        if not self.covers_op(op):
            return False
        if self.max_items is not None and item_count > self.max_items:
            return False
        if paths:
            return all(self.covers_path(p) for p in paths)
        # A pathless grant covers a pathless tool only.
        return not self.paths


@dataclass(frozen=True, slots=True)
class Grant:
    """A persisted grant row."""

    id: str
    tool_name: str
    scope: GrantScope
    granted_at: datetime
    expires_at: Optional[datetime]
    max_uses: Optional[int]
    uses: int
    origin_approval_id: Optional[str]
    revoked_at: Optional[datetime]
    session_id: Optional[str]

    def is_active(self, now: datetime, *, session_id: str | None = None) -> bool:
        if self.revoked_at is not None:
            return False
        if self.expires_at is not None and self.expires_at <= now:
            return False
        if self.max_uses is not None and self.uses >= self.max_uses:
            return False
        if self.session_id is not None and self.session_id != session_id:
            return False
        return True


def parse_ts(value: Any) -> Optional[datetime]:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    parsed = datetime.fromisoformat(str(value))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def grant_from_row(row: Any) -> Grant:
    """Build a :class:`Grant` from a SQLite row, tolerating a bad scope doc."""
    data = dict(row)
    try:
        scope = GrantScope.parse(data.get("scope_json"))
    except GrantScopeError:
        # An uninterpretable scope must never widen authority: treat it as an
        # empty scope, which covers nothing.
        scope = GrantScope()
    return Grant(
        id=str(data["id"]),
        tool_name=str(data["tool_name"]),
        scope=scope,
        granted_at=parse_ts(data.get("granted_at")) or datetime.now(timezone.utc),
        expires_at=parse_ts(data.get("expires_at")),
        max_uses=data.get("max_uses"),
        uses=int(data.get("uses") or 0),
        origin_approval_id=data.get("origin_approval_id"),
        revoked_at=parse_ts(data.get("revoked_at")),
        session_id=data.get("session_id"),
    )


def first_matching(
    grants: Iterable[Grant],
    *,
    tool_name: str,
    op: str,
    paths: Sequence[CanonicalPath],
    item_count: int,
    now: datetime,
    session_id: str | None,
) -> Optional[Grant]:
    for grant in grants:
        if grant.tool_name != tool_name:
            continue
        if not grant.is_active(now, session_id=session_id):
            continue
        if grant.scope.covers(op=op, paths=paths, item_count=item_count):
            return grant
    return None
