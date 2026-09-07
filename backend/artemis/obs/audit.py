"""Structured audit log (``docs/security.md`` §7).

Separate from application logs, append-only, user-visible, never transmitted.

Two properties matter and are enforced here:

* **Audit records never grant authority.**  Nothing reads this table to make a
  decision; the policy engine's inputs are rules, grants, taint and the
  baseline.
* **An unauditable privileged action is not performed.**  :meth:`AuditWriter.record`
  raises :class:`AuditFailure` when the write fails, and the tool runtime
  aborts side-effecting calls on that failure.  Read-only ``ALLOW`` calls
  proceed with a degraded-audit warning so a full disk does not brick the app.

``args_digest`` is a hash plus a redacted summary: paths are shown, file
*contents* never are.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Any, Iterable, Optional, Sequence

from ..storage.database import Database, DatabaseError
from .logging import get_logger

log = get_logger("obs.audit")

#: Lifecycle events recorded for every privileged call.
EVENT_PROPOSAL = "tool.proposal"
EVENT_DECISION = "tool.decision"
EVENT_AUTHORIZED = "tool.authorized"
EVENT_APPROVAL_REQUESTED = "approval.requested"
EVENT_APPROVAL_RESOLVED = "approval.resolved"
EVENT_DENIED = "tool.denied"
EVENT_EXECUTION = "tool.execution"
EVENT_COMPLETED = "tool.completed"
EVENT_FAILED = "tool.failed"
EVENT_CANCELLED = "tool.cancelled"
EVENT_TAINT_DOWNGRADE = "policy.taint_downgrade"
EVENT_FS_MUTATION = "fs.mutation"
EVENT_GRANT_CREATED = "policy.grant_created"
EVENT_GRANT_REVOKED = "policy.grant_revoked"
EVENT_RULE_CHANGED = "policy.rule_changed"
EVENT_BASELINE_DENIAL = "policy.baseline_denial"
EVENT_CONFIG_CHANGED = "policy.config_changed"

#: Argument names whose values are summarised rather than recorded verbatim.
_BULKY_ARGS: frozenset[str] = frozenset({"content", "text", "body", "data", "bytes"})

MAX_DIGEST_CHARS: int = 1024


class AuditFailure(RuntimeError):
    """The audit record could not be written.  Side effects must not proceed."""


def args_digest(canonical_json: str, *, redact: Iterable[str] = ()) -> str:
    """Hash plus a redacted summary.  File contents are never included."""
    digest = sha256(canonical_json.encode("utf-8")).hexdigest()[:32]
    try:
        parsed = json.loads(canonical_json)
    except json.JSONDecodeError:  # pragma: no cover - canonical json is valid
        return f"sha256:{digest}"
    if isinstance(parsed, dict):
        redact_set = set(_BULKY_ARGS) | {r.lower() for r in redact}
        summary: dict[str, Any] = {}
        for key, value in parsed.items():
            if key.lower() in redact_set:
                length = len(value) if isinstance(value, (str, bytes, list)) else 0
                summary[key] = f"«{type(value).__name__}:{length}»"
            elif isinstance(value, str) and len(value) > 200:
                summary[key] = value[:200] + "…"
            else:
                summary[key] = value
        rendered = json.dumps(summary, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    else:  # pragma: no cover - non-object canonical args are rejected earlier
        rendered = canonical_json
    if len(rendered) > MAX_DIGEST_CHARS:
        rendered = rendered[:MAX_DIGEST_CHARS] + "…"
    return f"sha256:{digest} {rendered}"


@dataclass(slots=True)
class AuditRecord:
    event: str
    actor: str = "system"
    run_id: Optional[str] = None
    task_id: Optional[str] = None
    tool_name: Optional[str] = None
    args_digest: Optional[str] = None
    resolved_target: Optional[str] = None
    decision: Optional[str] = None
    rule_id: Optional[str] = None
    reason: Optional[str] = None
    taint: bool = False
    approval_id: Optional[str] = None
    outcome: Optional[str] = None
    duration_ms: Optional[int] = None
    error_code: Optional[str] = None


_INSERT = """
    INSERT INTO audit_log (
        ts, run_id, task_id, actor, tool_name, event, args_digest,
        resolved_target, decision, rule_id, reason, taint, approval_id,
        outcome, duration_ms, error_code
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


class AuditWriter:
    """Append-only writer over the existing single-writer SQLite path."""

    def __init__(self, db: Database, *, retention_days: int = 90) -> None:
        self.db = db
        self.retention_days = retention_days
        self.degraded = False

    async def record(self, record: AuditRecord, *, required: bool = True) -> None:
        """Write one record.

        *required* is ``True`` for side-effecting calls: a failure raises
        :class:`AuditFailure` so the caller aborts the operation.
        """
        params = (
            datetime.now(timezone.utc).isoformat(),
            record.run_id,
            record.task_id,
            record.actor,
            record.tool_name,
            record.event,
            record.args_digest,
            record.resolved_target,
            record.decision,
            record.rule_id,
            record.reason,
            1 if record.taint else 0,
            record.approval_id,
            record.outcome,
            record.duration_ms,
            record.error_code,
        )
        try:
            await self.db.execute_write(_INSERT, params)
            self.degraded = False
        except (DatabaseError, Exception) as exc:  # noqa: BLE001 - fail closed
            log.error("audit_write_failed", event=record.event, error=str(exc))
            if required:
                raise AuditFailure(str(exc)) from exc
            self.degraded = True

    async def query(
        self,
        *,
        from_ts: str | None = None,
        to_ts: str | None = None,
        decision: str | None = None,
        tool: str | None = None,
        limit: int = 100,
        cursor: int | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if from_ts:
            clauses.append("ts >= ?")
            params.append(from_ts)
        if to_ts:
            clauses.append("ts <= ?")
            params.append(to_ts)
        if decision:
            clauses.append("decision = ?")
            params.append(decision)
        if tool:
            clauses.append("tool_name = ?")
            params.append(tool)
        if cursor is not None:
            clauses.append("id < ?")
            params.append(cursor)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(max(1, min(int(limit), 500)))
        rows = await self.db.query(
            f"SELECT * FROM audit_log {where} ORDER BY id DESC LIMIT ?", tuple(params)
        )
        return [dict(row) for row in rows]

    async def purge(self, *, now: datetime | None = None) -> int:
        cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=self.retention_days)
        rows = await self.db.execute_write(
            "DELETE FROM audit_log WHERE ts < ?", (cutoff.isoformat(),)
        )
        return len(rows)


__all__ = [
    "AuditFailure",
    "AuditRecord",
    "AuditWriter",
    "EVENT_APPROVAL_REQUESTED",
    "EVENT_APPROVAL_RESOLVED",
    "EVENT_AUTHORIZED",
    "EVENT_BASELINE_DENIAL",
    "EVENT_CANCELLED",
    "EVENT_COMPLETED",
    "EVENT_CONFIG_CHANGED",
    "EVENT_DECISION",
    "EVENT_DENIED",
    "EVENT_EXECUTION",
    "EVENT_FAILED",
    "EVENT_FS_MUTATION",
    "EVENT_GRANT_CREATED",
    "EVENT_GRANT_REVOKED",
    "EVENT_PROPOSAL",
    "EVENT_RULE_CHANGED",
    "EVENT_TAINT_DOWNGRADE",
    "args_digest",
]
