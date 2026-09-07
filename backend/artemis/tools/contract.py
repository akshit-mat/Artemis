"""Tool contract — the declarative description of every model-accessible action.

``docs/tools.md`` §2 is the specification for this module.  Nothing here decides
*whether* an action is permitted; that is ``policy/engine.py``.  This module
owns the shape of a tool, the shape of its result, and the canonical argument
representation that :class:`~artemis.policy.engine.Authorization` binds to.

Invariants enforced here:

* every model-accessible action is an explicitly registered :class:`ToolSpec`
  (``docs/decisions.md`` ADR-003 — there is no ``run_command``);
* ``canonical_args_json`` / ``canonical_hash`` are the single definition of
  "the exact arguments", used identically at authorization time and at
  execution time (``docs/security.md`` §6 "TOCTOU on approval");
* tools never raise to the agent: the runtime converts exceptions into a
  :class:`ToolResult` with a stable ``error_code`` (``docs/tools.md`` §2).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Literal, Optional

from pydantic import BaseModel, ConfigDict

# --------------------------------------------------------------------------
# Enumerations
# --------------------------------------------------------------------------


class Decision(str, Enum):
    """Policy outcome.  Ordered as a lattice: ``DENY < ASK < ALLOW``."""

    DENY = "DENY"
    ASK = "ASK"
    ALLOW = "ALLOW"

    @property
    def rank(self) -> int:
        return _DECISION_RANK[self]


_DECISION_RANK: dict[Decision, int] = {
    Decision.DENY: 0,
    Decision.ASK: 1,
    Decision.ALLOW: 2,
}


def decision_min(*decisions: Decision) -> Decision:
    """``min`` over the decision lattice (``docs/security.md`` §3).

    Used everywhere a decision is combined.  There is deliberately no ``max``
    helper in this codebase: nothing may move a decision *up* the lattice.
    """
    if not decisions:
        raise ValueError("decision_min requires at least one decision")
    return min(decisions, key=lambda d: d.rank)


class RiskLevel(str, Enum):
    """``docs/tools.md`` §2.  Drives default policy, UI colour, taint lock."""

    READ_ONLY = "READ_ONLY"
    LOW = "LOW"
    MODERATE = "MODERATE"
    DESTRUCTIVE = "DESTRUCTIVE"
    FORBIDDEN = "FORBIDDEN"


class ToolCategory(str, Enum):
    SYSTEM = "system"
    APPS = "apps"
    FILES = "files"
    MEDIA = "media"
    WINDOWS = "windows"
    WEB = "web"
    MEMORY = "memory"
    VISION = "vision"
    META = "meta"


class ExecTier(str, Enum):
    """``docs/tools.md`` §4 / ADR-008."""

    INLINE = "INLINE"
    THREAD = "THREAD"
    SUBPROCESS = "SUBPROCESS"


class Trust(str, Enum):
    SYSTEM = "SYSTEM"
    USER = "USER"
    UNTRUSTED = "UNTRUSTED"


#: Maximum tool timeout permitted by the contract (``docs/tools.md`` §2).
MAX_TIMEOUT_S: float = 60.0

#: ``context_view`` budget in tokens (``docs/agent.md`` §4 anti-bloat #1).
CONTEXT_VIEW_TOKEN_CAP: int = 600

#: ``summary`` character budget (``docs/tools.md`` §2 result shape).
SUMMARY_CHAR_CAP: int = 200


# --------------------------------------------------------------------------
# Canonical argument representation
# --------------------------------------------------------------------------


def _canonicalize(value: Any) -> Any:
    """Recursively produce a JSON-safe, order-stable representation."""
    if isinstance(value, BaseModel):
        return _canonicalize(value.model_dump(mode="json"))
    if isinstance(value, dict):
        return {str(k): _canonicalize(value[k]) for k in sorted(value, key=str)}
    if isinstance(value, (list, tuple)):
        return [_canonicalize(item) for item in value]
    if isinstance(value, Enum):
        return _canonicalize(value.value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def canonical_args(args: Any) -> dict[str, Any]:
    """Canonical dict form of validated tool arguments."""
    canonical = _canonicalize(args)
    if not isinstance(canonical, dict):
        raise TypeError("tool arguments must canonicalize to an object")
    return canonical


def canonical_args_json(args: Any) -> str:
    """Deterministic serialization of validated arguments.

    Sorted keys, no insignificant whitespace, non-ASCII preserved.  This exact
    byte string is what :func:`canonical_hash` digests, so the hash is stable
    across processes (including the subprocess tier) and across restarts.
    """
    return json.dumps(
        canonical_args(args),
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )


def canonical_hash(args: Any) -> str:
    """``sha256(canonical_args)`` — the binding used by ``Authorization``."""
    return hashlib.sha256(canonical_args_json(args).encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# Result / preview / context types
# --------------------------------------------------------------------------


class UndoHandle(BaseModel):
    """Describes how a completed side effect can be reversed."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["recycle_bin", "move_manifest"]
    token: str
    description: str


class ToolResult(BaseModel):
    """``docs/tools.md`` §2 result shape.  Tools never raise to the agent."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["ok", "error", "timeout", "denied", "unavailable", "cancelled"]
    summary: str
    data: Optional[dict[str, Any]] = None
    context_view: str = ""
    result_id: str = ""
    trust: Literal["SYSTEM", "UNTRUSTED"] = "SYSTEM"
    duration_ms: int = 0
    error_code: Optional[str] = None
    undo: Optional[UndoHandle] = None
    truncated: bool = False


class ActionPreview(BaseModel):
    """Backend-generated, resolved description of a pending operation.

    ``docs/api.md`` §4: ``action_text`` is generated by the backend from
    validated arguments.  Model prose never occupies this field.
    """

    model_config = ConfigDict(extra="forbid")

    action_text: str
    targets: list[str] = []
    item_count: int = 0
    total_bytes: Optional[int] = None
    reversible: bool = False
    detail: Optional[str] = None
    destructive: bool = False


@dataclass(slots=True)
class ResolvedContext:
    """What the policy layer resolved for a call, handed to ``preview``.

    ``paths`` are the canonical paths produced by ``policy/paths.py``; tools and
    previews use these, never the model-supplied strings (``docs/tools.md`` §8).
    """

    run_id: str
    session_id: str
    tainted: bool = False
    paths: dict[str, Any] = field(default_factory=dict)


class CancelToken:
    """Cooperative cancellation signal handed to tools.

    The ``SUBPROCESS`` tier additionally performs a hard process-tree kill; this
    token is the cooperative half and the mechanism by which INLINE/THREAD tools
    observe cancellation (``docs/agent.md`` §2 Cancellation).
    """

    __slots__ = ("_cancelled", "_callbacks")

    def __init__(self) -> None:
        self._cancelled = False
        self._callbacks: list[Callable[[], None]] = []

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    def cancel(self) -> None:
        if self._cancelled:
            return
        self._cancelled = True
        for callback in list(self._callbacks):
            try:
                callback()
            except Exception:  # pragma: no cover - defensive; hooks must not throw
                pass

    def on_cancel(self, callback: Callable[[], None]) -> None:
        """Register a hook fired on cancellation (used for tree-kill)."""
        self._callbacks.append(callback)
        if self._cancelled:
            callback()

    def raise_if_cancelled(self) -> None:
        if self._cancelled:
            raise ToolCancelled()


class ToolCancelled(Exception):
    """Raised inside a tool body when its cancel token fires."""


@dataclass(slots=True)
class ToolContext:
    """``docs/tools.md`` §2.

    Deliberately does **not** carry the database, the model, or the policy
    engine: tools are leaves, not orchestrators.
    """

    run_id: str
    session_id: str
    cancel_token: CancelToken
    authorization: Any  # policy.engine.Authorization — avoids an import cycle
    taint: bool = False
    resolved: Optional[ResolvedContext] = None
    progress: Callable[[Optional[float], Optional[str]], None] = lambda _p, _n: None
    logger: Any = None


# --------------------------------------------------------------------------
# ToolSpec
# --------------------------------------------------------------------------


class ToolSpecError(ValueError):
    """A ToolSpec whose declared fields are incoherent.  Fatal at import."""


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """Declarative tool definition (``docs/tools.md`` §2).

    Adding a tool requires no change to the agent, the policy engine or the UI.
    """

    name: str
    summary: str
    args_model: type[BaseModel]
    returns_model: type[BaseModel]
    category: ToolCategory
    risk: RiskLevel
    side_effects: bool
    reversible: bool
    produces_untrusted_content: bool
    tier: ExecTier
    timeout_s: float
    default_decision: Decision
    execute: Callable[[BaseModel, ToolContext], Awaitable[ToolResult]]
    requires_paths: bool = False
    preview: Optional[Callable[[BaseModel, ResolvedContext], ActionPreview]] = None
    requires: frozenset[str] = frozenset()
    enabled: bool = True
    #: Path-shaped argument names, in the order a preview should show them.
    path_args: tuple[str, ...] = ()
    #: True when the tool destroys data even though the effect is recoverable.
    destructive: bool = False

    # -- coherence ----------------------------------------------------------

    def validate_coherence(self) -> None:
        """Registry meta-test rules (``docs/tools.md`` §10).

        Called by the registry on every registration, so an incoherent tool
        cannot reach a running system.
        """
        if not self.name or not self.name.replace("_", "").isalnum():
            raise ToolSpecError(f"{self.name!r}: name must be snake_case alphanumeric")
        if self.name != self.name.lower():
            raise ToolSpecError(f"{self.name!r}: name must be lower-case")
        if not self.summary or len(self.summary) > 200:
            raise ToolSpecError(f"{self.name}: summary must be 1..200 chars")
        if not (0 < self.timeout_s <= MAX_TIMEOUT_S):
            raise ToolSpecError(f"{self.name}: timeout_s must be in (0, {MAX_TIMEOUT_S}]")
        if self.risk is RiskLevel.FORBIDDEN:
            raise ToolSpecError(f"{self.name}: FORBIDDEN capabilities are never implemented")
        if self.risk is RiskLevel.DESTRUCTIVE and self.default_decision is Decision.ALLOW:
            raise ToolSpecError(f"{self.name}: DESTRUCTIVE tools may not default to ALLOW")
        if self.risk is RiskLevel.READ_ONLY and self.side_effects:
            raise ToolSpecError(f"{self.name}: READ_ONLY tools cannot declare side effects")
        if self.risk in (RiskLevel.MODERATE, RiskLevel.DESTRUCTIVE) and not self.side_effects:
            raise ToolSpecError(f"{self.name}: {self.risk.value} implies side_effects=True")
        if self.destructive and self.risk is not RiskLevel.DESTRUCTIVE:
            raise ToolSpecError(f"{self.name}: destructive flag requires risk=DESTRUCTIVE")
        if self.risk is RiskLevel.DESTRUCTIVE and not self.destructive:
            raise ToolSpecError(f"{self.name}: DESTRUCTIVE risk requires destructive=True")
        if self.requires_paths and not self.path_args:
            raise ToolSpecError(f"{self.name}: requires_paths=True needs path_args")
        if self.path_args and not self.requires_paths:
            raise ToolSpecError(f"{self.name}: path_args requires requires_paths=True")
        for arg in self.path_args:
            if arg not in self.args_model.model_fields:
                raise ToolSpecError(f"{self.name}: path arg {arg!r} absent from args model")
        if self.side_effects and self.risk is RiskLevel.READ_ONLY:  # pragma: no cover
            raise ToolSpecError(f"{self.name}: contradictory risk/side_effects")

    # -- schema -------------------------------------------------------------

    def json_schema(self) -> dict[str, Any]:
        return self.args_model.model_json_schema()

    def compact_schema(self) -> dict[str, Any]:
        """Compact schema rendering used by the context assembler.

        Descriptions are truncated to one line and unused JSON-Schema keywords
        are dropped: the full schema of ~15 tools does not fit the Tier-1 budget
        (``docs/agent.md`` §4 anti-bloat #2).
        """
        schema = self.json_schema()
        props: dict[str, Any] = {}
        for field_name, spec in (schema.get("properties") or {}).items():
            entry: dict[str, Any] = {}
            if "type" in spec:
                entry["type"] = spec["type"]
            elif "anyOf" in spec:
                types = [s.get("type") for s in spec["anyOf"] if s.get("type")]
                entry["type"] = "|".join(t for t in types if t and t != "null") or "string"
            if "enum" in spec:
                entry["enum"] = spec["enum"]
            description = spec.get("description")
            if description:
                entry["description"] = description.strip().splitlines()[0][:120]
            props[field_name] = entry
        return {
            "name": self.name,
            "description": self.summary,
            "parameters": {
                "type": "object",
                "properties": props,
                "required": list(schema.get("required") or []),
            },
        }

    def provider_schema(self) -> dict[str, Any]:
        """Ollama/OpenAI-shaped function schema for native tool calling."""
        return {"type": "function", "function": self.compact_schema()}

    def validate_args(self, raw: dict[str, Any]) -> BaseModel:
        """Validate model-proposed arguments.  Raises ``ValidationError``."""
        return self.args_model.model_validate(raw)
