"""Filesystem scope management (``docs/security.md`` §5 Defaults, roadmap Phase 5).

Owns the mutable list of ``allow_roots`` and the :class:`PathPolicy` built from
it.  Additions are validated here — the UI is never authoritative:

* ``C:\\`` (or any drive root) is refused;
* a root inside a baseline-protected location is refused;
* a root that does not exist is refused;
* the caller must pass ``confirm_risk=True``, which is how the settings UI's
  explicit risk confirmation is enforced on the *backend* side.

Roots are persisted in the existing ``settings`` table (no new storage engine).
"""

from __future__ import annotations

import json
from typing import Any, Iterable, Optional

from ..obs.logging import get_logger
from ..storage.database import Database
from .paths import PathPolicy, PathRejected, default_allow_roots, segments_of

log = get_logger("policy.fsconfig")

SETTINGS_KEY = "filesystem.allow_roots"


class RootRejected(ValueError):
    """An allow_root the backend refuses to accept."""


class FilesystemScope:
    """The single source of truth for the filesystem scope."""

    def __init__(
        self,
        *,
        allow_roots: Iterable[str] | None = None,
        allow_unc: bool = False,
        max_read_bytes: int = 512 * 1024,
        max_batch_items: int = 200,
        db: Database | None = None,
    ) -> None:
        self.allow_unc = allow_unc
        self.max_read_bytes = max_read_bytes
        self.max_batch_items = max_batch_items
        self.db = db
        roots = list(allow_roots or []) or default_allow_roots()
        self._roots: list[str] = []
        self._policy = PathPolicy([], allow_unc=allow_unc)
        self._set_roots(roots, tolerate_invalid=True)

    # -- state ---------------------------------------------------------------

    @property
    def policy(self) -> PathPolicy:
        return self._policy

    @property
    def allow_roots(self) -> tuple[str, ...]:
        return tuple(self._roots)

    def _set_roots(self, roots: list[str], *, tolerate_invalid: bool = False) -> None:
        accepted: list[str] = []
        for root in roots:
            try:
                normalized = self._validate_root(root)
            except RootRejected as exc:
                if not tolerate_invalid:
                    raise
                log.warning("allow_root_ignored", root=str(root), reason=str(exc))
                continue
            if normalized.casefold() not in {item.casefold() for item in accepted}:
                accepted.append(normalized)
        if not accepted:
            accepted = [
                root
                for root in default_allow_roots()
                if self._safe_validate(root) is not None
            ]
        self._roots = accepted
        self._policy = PathPolicy(accepted, allow_unc=self.allow_unc)
        self._rebind()

    def _rebind(self) -> None:
        from ..tools.builtin import bind_filesystem_scope

        bind_filesystem_scope(
            allow_roots=list(self._roots),
            allow_unc=self.allow_unc,
            max_read_bytes=self.max_read_bytes,
        )

    def _safe_validate(self, root: str) -> Optional[str]:
        try:
            return self._validate_root(root)
        except RootRejected:
            return None

    def _validate_root(self, root: str) -> str:
        candidate = str(root).strip().strip('"')
        if not candidate:
            raise RootRejected("The folder is empty.")
        try:
            normalized = PathPolicy._normalize_root(candidate)  # noqa: SLF001 - same package
        except ValueError as exc:
            raise RootRejected(str(exc)) from exc
        segments = segments_of(normalized)
        if len(segments) <= 1:
            raise RootRejected("A drive root such as C:\\ cannot be an allowed folder.")
        probe = PathPolicy([normalized], allow_unc=self.allow_unc)
        denial = probe.denial_reason(normalized, segments)
        if denial is not None:
            raise RootRejected(f"That folder is protected: {denial}")
        try:
            resolved = probe.canonicalize(normalized, must_exist=True)
        except PathRejected as exc:
            raise RootRejected(exc.reason) from exc
        if not resolved.is_dir:
            raise RootRejected("That path is not a folder.")
        return resolved.path

    # -- mutation ------------------------------------------------------------

    async def load(self) -> None:
        if self.db is None:
            return
        rows = await self.db.query("SELECT value FROM settings WHERE key = ?", (SETTINGS_KEY,))
        if not rows:
            return
        try:
            stored = json.loads(rows[0]["value"])
        except (json.JSONDecodeError, TypeError):
            log.warning("allow_roots_unreadable")
            return
        if isinstance(stored, list) and stored:
            self._set_roots([str(item) for item in stored], tolerate_invalid=True)

    async def _persist(self) -> None:
        if self.db is None:
            return
        await self.db.execute_write(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (SETTINGS_KEY, json.dumps(list(self._roots), ensure_ascii=False)),
        )

    async def add_root(self, root: str, *, confirm_risk: bool) -> str:
        """Add an allowed folder.  Requires the explicit risk confirmation."""
        if not confirm_risk:
            raise RootRejected(
                "Adding a folder requires explicit confirmation of the risk."
            )
        normalized = self._validate_root(root)
        if normalized.casefold() in {item.casefold() for item in self._roots}:
            return normalized
        self._set_roots([*self._roots, normalized])
        await self._persist()
        return normalized

    async def remove_root(self, root: str) -> bool:
        target = str(root).strip().rstrip("\\").casefold()
        remaining = [item for item in self._roots if item.casefold() != target]
        if len(remaining) == len(self._roots):
            return False
        self._roots = remaining
        self._policy = PathPolicy(remaining, allow_unc=self.allow_unc) if remaining else PathPolicy(
            [], allow_unc=self.allow_unc
        )
        self._rebind()
        await self._persist()
        return True

    def describe(self) -> dict[str, Any]:
        return {
            "allow_roots": list(self._roots),
            "allow_unc": self.allow_unc,
            "max_read_bytes": self.max_read_bytes,
            "max_batch_items": self.max_batch_items,
            "delete_mode": "recycle_bin",
            "permanent_delete_available": False,
        }


__all__ = ["FilesystemScope", "RootRejected", "SETTINGS_KEY"]
