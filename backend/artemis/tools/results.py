"""Tool result storage — full results out of the prompt.

``docs/agent.md`` §4 anti-bloat #1: the full result goes here and the context
receives only a bounded ``context_view`` plus a ``result_id``.  ``read_more``
(``docs/tools.md`` §6 Meta) and ``GET /v1/results/{result_id}`` both read from
this table.

``read_more`` inherits the source result's trust, so paging through a file's
contents cannot launder untrusted bytes into a trusted channel.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional

from ..obs.logging import get_logger
from ..storage.database import Database
from .contract import ToolContext, ToolResult, ToolSpec

log = get_logger("tools.results")

#: Characters returned by a single ``read_more`` page.
READ_MORE_PAGE_CHARS: int = 2000


class ResultStore:
    def __init__(self, db: Database) -> None:
        self.db = db

    async def save(
        self, result: ToolResult, *, spec: ToolSpec, ctx: ToolContext, call_id: str | None = None
    ) -> str:
        payload = None
        if result.data is not None:
            try:
                payload = json.dumps(result.data, ensure_ascii=False, default=str)
            except (TypeError, ValueError):  # pragma: no cover - defensive
                payload = None
        await self.db.execute_write(
            "INSERT OR REPLACE INTO tool_results (id, run_id, session_id, call_id, "
            "tool_name, status, summary, data_json, context_view, trust, duration_ms, "
            "error_code, truncated, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                result.result_id,
                ctx.run_id,
                ctx.session_id,
                call_id,
                spec.name,
                result.status,
                result.summary,
                payload,
                result.context_view,
                result.trust,
                result.duration_ms,
                result.error_code,
                1 if result.truncated else 0,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        return result.result_id

    async def get(self, result_id: str) -> Optional[dict[str, Any]]:
        rows = await self.db.query("SELECT * FROM tool_results WHERE id = ?", (result_id,))
        if not rows:
            return None
        row = dict(rows[0])
        if row.get("data_json"):
            try:
                row["data"] = json.loads(row["data_json"])
            except json.JSONDecodeError:  # pragma: no cover - defensive
                row["data"] = None
        else:
            row["data"] = None
        row.pop("data_json", None)
        return row

    async def page(
        self, result_id: str, *, offset: int = 0, limit: int = READ_MORE_PAGE_CHARS
    ) -> Optional[dict[str, Any]]:
        """Return one page of a stored result's renderable body."""
        record = await self.get(result_id)
        if record is None:
            return None
        body = _renderable(record)
        offset = max(0, int(offset))
        limit = max(1, min(int(limit), 20_000))
        chunk = body[offset : offset + limit]
        return {
            "result_id": result_id,
            "tool_name": record["tool_name"],
            "trust": record["trust"],
            "offset": offset,
            "limit": limit,
            "total_chars": len(body),
            "has_more": offset + limit < len(body),
            "text": chunk,
        }


def _renderable(record: dict[str, Any]) -> str:
    data = record.get("data")
    if isinstance(data, dict):
        for key in ("text", "body", "content"):
            value = data.get(key)
            if isinstance(value, str):
                return value
        try:
            return json.dumps(data, ensure_ascii=False, indent=2, default=str)
        except (TypeError, ValueError):  # pragma: no cover - defensive
            pass
    return record.get("context_view") or record.get("summary") or ""


__all__ = ["READ_MORE_PAGE_CHARS", "ResultStore"]
