"""Meta tools (``docs/tools.md`` §6 "Meta").

``read_more`` pages a stored tool result.  It **inherits the source result's
trust**: paging through a file's contents must not launder untrusted bytes into a
trusted channel, so a page of an ``UNTRUSTED`` result is itself ``UNTRUSTED`` and
keeps the run tainted.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from ..contract import (
    Decision,
    ExecTier,
    RiskLevel,
    ToolCategory,
    ToolContext,
    ToolResult,
    ToolSpec,
)

#: Set by ``artemis.tools.builtin.bind_result_store`` at startup.
_result_store: Any = None


def bind_result_store(store: Any) -> None:
    global _result_store  # noqa: PLW0603 - single explicit binding point
    _result_store = store


class ReadMoreArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    result_id: str = Field(min_length=3, max_length=64, description="Id from an earlier result.")
    offset: int = Field(default=0, ge=0, le=50_000_000, description="Character offset.")
    limit: int = Field(default=2000, ge=1, le=20_000, description="Characters to return.")


class ReadMoreResult(BaseModel):
    result_id: str
    offset: int
    limit: int
    total_chars: int
    has_more: bool
    text: str
    trust: str


async def _read_more(args: ReadMoreArgs, ctx: ToolContext) -> ToolResult:
    if _result_store is None:
        return ToolResult(
            status="unavailable",
            summary="Result storage is not available.",
            error_code="RESULT_STORE_UNAVAILABLE",
        )
    page = await _result_store.page(args.result_id, offset=args.offset, limit=args.limit)
    if page is None:
        return ToolResult(
            status="error",
            summary="That result id is not known.",
            error_code="RESULT_NOT_FOUND",
        )
    trust = "UNTRUSTED" if page.get("trust") == "UNTRUSTED" else "SYSTEM"
    body = page["text"]
    if trust == "UNTRUSTED":
        from ...policy.taint import wrap_untrusted

        view = wrap_untrusted(body, source=f"result:{args.result_id}")
    else:
        view = body
    return ToolResult(
        status="ok",
        summary=(
            f"Characters {page['offset']}–{page['offset'] + len(body)} of "
            f"{page['total_chars']} from {page['tool_name']}."
        ),
        data={**page, "trust": trust},
        context_view=view,
        trust=trust,
        truncated=bool(page["has_more"]),
    )


READ_MORE = ToolSpec(
    name="read_more",
    summary="Read the next part of a previous tool result that was truncated.",
    args_model=ReadMoreArgs,
    returns_model=ReadMoreResult,
    category=ToolCategory.META,
    risk=RiskLevel.READ_ONLY,
    side_effects=False,
    reversible=True,
    produces_untrusted_content=False,
    tier=ExecTier.INLINE,
    timeout_s=5.0,
    default_decision=Decision.ALLOW,
    execute=_read_more,
)

META_TOOLS: tuple[ToolSpec, ...] = (READ_MORE,)

__all__ = ["META_TOOLS", "READ_MORE", "bind_result_store"]
