"""Persistence for policy rules and grants (``docs/security.md`` §3, ADR-016).

Raw SQL through the existing repository discipline; no ORM.  The store is the
only module that writes ``policy_rules`` / ``policy_grants``, and every mutation
is audited by the caller.

Loosening past the baseline is refused here as well as in the engine: a rule row
that requests more authority than :func:`policy.baseline.baseline_ceiling`
permits is rejected at write time, so the table cannot even hold such a row.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional, Sequence

from ..storage.database import Database
from ..tools.contract import Decision, RiskLevel
from . import baseline
from .grants import Grant, GrantScope, grant_from_row


class RuleRejected(ValueError):
    """A rule that would exceed the hard-deny baseline."""


class PolicyStore:
    def __init__(self, db: Database) -> None:
        self.db = db

    # -- rules ---------------------------------------------------------------

    async def load_rules(self) -> dict[str, str]:
        rows = await self.db.query("SELECT tool_name, decision FROM policy_rules")
        return {str(row["tool_name"]): str(row["decision"]) for row in rows}

    async def list_rules(self) -> list[dict[str, Any]]:
        rows = await self.db.query(
            "SELECT * FROM policy_rules ORDER BY tool_name ASC"
        )
        return [dict(row) for row in rows]

    async def set_rule(
        self,
        tool_name: str,
        decision: Decision | str,
        *,
        risk: RiskLevel,
        destructive: bool = False,
        source: str = "user",
        category: str | None = None,
        note: str | None = None,
    ) -> dict[str, Any]:
        wanted = decision if isinstance(decision, Decision) else Decision(str(decision))
        ceiling, rule_id, reason = baseline.baseline_ceiling(
            tool_name=tool_name, risk=risk, destructive=destructive
        )
        if wanted.rank > ceiling.rank:
            raise RuleRejected(
                f"{tool_name}: {wanted.value} exceeds the baseline ceiling "
                f"{ceiling.value} ({rule_id}: {reason})"
            )
        now = datetime.now(timezone.utc).isoformat()
        existing = await self.db.query(
            "SELECT id FROM policy_rules WHERE tool_name = ?", (tool_name,)
        )
        if existing:
            await self.db.execute_write(
                "UPDATE policy_rules SET decision = ?, updated_at = ?, source = ?, "
                "note = ?, category = ? WHERE tool_name = ?",
                (wanted.value, now, source, note, category, tool_name),
            )
            rule_row_id = str(existing[0]["id"])
        else:
            rule_row_id = f"pr_{uuid.uuid4().hex[:12]}"
            await self.db.execute_write(
                "INSERT INTO policy_rules (id, tool_name, category, decision, "
                "scope_json, source, created_at, updated_at, note) "
                "VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?)",
                (rule_row_id, tool_name, category, wanted.value, source, now, now, note),
            )
        return {"id": rule_row_id, "tool_name": tool_name, "decision": wanted.value}

    async def delete_rule(self, tool_name: str) -> None:
        await self.db.execute_write(
            "DELETE FROM policy_rules WHERE tool_name = ?", (tool_name,)
        )

    # -- grants --------------------------------------------------------------

    async def load_grants(self) -> list[Grant]:
        rows = await self.db.query(
            "SELECT * FROM policy_grants WHERE revoked_at IS NULL ORDER BY granted_at DESC"
        )
        return [grant_from_row(row) for row in rows]

    async def list_grants(self) -> list[dict[str, Any]]:
        rows = await self.db.query(
            "SELECT * FROM policy_grants ORDER BY granted_at DESC"
        )
        return [dict(row) for row in rows]

    async def create_grant(
        self,
        *,
        tool_name: str,
        scope: GrantScope,
        risk: RiskLevel,
        destructive: bool = False,
        ttl_s: float | None = None,
        session_id: str | None = None,
        max_uses: int | None = None,
        origin_approval_id: str | None = None,
    ) -> Grant:
        """Create a grant.  Refused for tools the baseline never allows.

        A ``DESTRUCTIVE`` tool has an ``ASK`` baseline ceiling, so a grant could
        never raise it to ``ALLOW``; creating one would be misleading in the
        Permissions panel.  We refuse instead (``docs/security.md`` §3:
        "Always is unavailable for DESTRUCTIVE tools").
        """
        ceiling, rule_id, reason = baseline.baseline_ceiling(
            tool_name=tool_name, risk=risk, destructive=destructive
        )
        if ceiling is not Decision.ALLOW:
            raise RuleRejected(
                f"{tool_name}: the baseline ceiling is {ceiling.value} "
                f"({rule_id}: {reason}); a grant cannot raise it"
            )
        now = datetime.now(timezone.utc)
        grant_id = f"pg_{uuid.uuid4().hex[:12]}"
        expires_at = (now + timedelta(seconds=ttl_s)).isoformat() if ttl_s else None
        await self.db.execute_write(
            "INSERT INTO policy_grants (id, tool_name, scope_json, granted_at, "
            "expires_at, max_uses, uses, origin_approval_id, revoked_at, session_id) "
            "VALUES (?, ?, ?, ?, ?, ?, 0, ?, NULL, ?)",
            (
                grant_id,
                tool_name,
                scope.to_json(),
                now.isoformat(),
                expires_at,
                max_uses,
                origin_approval_id,
                session_id,
            ),
        )
        return Grant(
            id=grant_id,
            tool_name=tool_name,
            scope=scope,
            granted_at=now,
            expires_at=datetime.fromisoformat(expires_at) if expires_at else None,
            max_uses=max_uses,
            uses=0,
            origin_approval_id=origin_approval_id,
            revoked_at=None,
            session_id=session_id,
        )

    async def record_grant_use(self, grant_id: str) -> None:
        await self.db.execute_write(
            "UPDATE policy_grants SET uses = uses + 1, last_used_at = ? WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(), grant_id),
        )

    async def revoke_grant(self, grant_id: str) -> bool:
        rows = await self.db.query(
            "SELECT id FROM policy_grants WHERE id = ? AND revoked_at IS NULL",
            (grant_id,),
        )
        if not rows:
            return False
        await self.db.execute_write(
            "UPDATE policy_grants SET revoked_at = ? WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(), grant_id),
        )
        return True


__all__ = ["PolicyStore", "RuleRejected"]
