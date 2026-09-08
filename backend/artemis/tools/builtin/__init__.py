"""Explicit builtin tool registration (``docs/tools.md`` §3).

There is no filesystem auto-discovery: the list below *is* the model's entire
action space.  Adding a capability means adding a line here and a reviewed
``ToolSpec`` — which is exactly the audit point ADR-003 is designed to create.
"""

from __future__ import annotations

from typing import Any

from ..registry import REGISTRY, ToolRegistry
from .files import FILE_TOOLS, bind_scope, current_scope
from .meta import META_TOOLS, bind_result_store
from .system import SYSTEM_TOOLS

BUILTIN_TOOLS = (*SYSTEM_TOOLS, *META_TOOLS, *FILE_TOOLS)


def register_builtin_tools(registry: ToolRegistry | None = None) -> ToolRegistry:
    """Register every builtin tool.  Idempotent per registry instance."""
    target = registry or REGISTRY
    existing = set(target.names())
    for spec in BUILTIN_TOOLS:
        if spec.name in existing:
            continue
        target.register(spec)
    return target


def bind_filesystem_scope(
    *, allow_roots: list[str], allow_unc: bool, max_read_bytes: int
) -> None:
    bind_scope(allow_roots=allow_roots, allow_unc=allow_unc, max_read_bytes=max_read_bytes)


__all__ = [
    "BUILTIN_TOOLS",
    "bind_filesystem_scope",
    "bind_result_store",
    "current_scope",
    "register_builtin_tools",
]
