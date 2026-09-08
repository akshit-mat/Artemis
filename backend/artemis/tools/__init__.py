"""Tool package.

Registration is explicit (``docs/tools.md`` §3): import
``artemis.tools.builtin.register_builtin_tools`` and call it once at startup.
"""

from .contract import (
    ActionPreview,
    CancelToken,
    Decision,
    ExecTier,
    RiskLevel,
    ToolCategory,
    ToolContext,
    ToolResult,
    ToolSpec,
    canonical_args_json,
    canonical_hash,
)
from .registry import REGISTRY, ToolNotFound, ToolRegistry

__all__ = [
    "ActionPreview",
    "CancelToken",
    "Decision",
    "ExecTier",
    "REGISTRY",
    "RiskLevel",
    "ToolCategory",
    "ToolContext",
    "ToolNotFound",
    "ToolRegistry",
    "ToolResult",
    "ToolSpec",
    "canonical_args_json",
    "canonical_hash",
]
