"""Tool-call extraction with the documented fallback chain (``docs/agent.md`` §3).

Order, and the ``path`` recorded for metrics:

1. ``native`` — provider-emitted ``tool_call`` chunks.
2. ``constrained`` — a re-request with ``format=<json-schema>`` when a tool call
   is structurally expected (the caller drives this; this module parses the
   resulting JSON object).
3. ``text`` — balanced-brace JSON scan for ``{"tool": ..., "arguments": {...}}``,
   tolerant of fenced code blocks.
4. failure → the caller's repair loop.

**Extraction never implies authorization.**  Everything produced here is an
untrusted *proposal* that must still pass the registry, the schema and the
policy engine.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Iterable

_FENCE_RE = re.compile(r"```[a-zA-Z0-9_+-]*\s*(.*?)```", re.DOTALL)

#: Keys a small local model plausibly uses for the tool name / arguments.
_NAME_KEYS = ("tool", "name", "tool_name", "function")
_ARG_KEYS = ("arguments", "args", "parameters", "params", "input")

MAX_CANDIDATES = 8


@dataclass(slots=True)
class ExtractedCall:
    name: str
    arguments: dict[str, Any]
    path: str


@dataclass(slots=True)
class ExtractionMetrics:
    """Which extraction path succeeded — a model-drift signal (risk R15)."""

    paths: Counter = field(default_factory=Counter)
    failures: int = 0

    def record(self, path: str) -> None:
        self.paths[path] += 1

    def record_failure(self) -> None:
        self.failures += 1

    def snapshot(self) -> dict[str, int]:
        data = {f"path_{key}": value for key, value in self.paths.items()}
        data["failures"] = self.failures
        return data


metrics = ExtractionMetrics()


def _balanced_objects(text: str) -> list[str]:
    """Return top-level ``{...}`` substrings, respecting strings and escapes."""
    found: list[str] = []
    depth = 0
    start = -1
    in_string = False
    escape = False
    for index, char in enumerate(text):
        if in_string:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
            continue
        if char == "{":
            if depth == 0:
                start = index
            depth += 1
        elif char == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start >= 0:
                    found.append(text[start : index + 1])
                    start = -1
                    if len(found) >= MAX_CANDIDATES:
                        break
    return found


def _coerce_call(payload: Any, *, path: str) -> ExtractedCall | None:
    if not isinstance(payload, dict):
        return None
    # OpenAI-shaped nesting: {"function": {"name": ..., "arguments": ...}}
    nested = payload.get("function")
    if isinstance(nested, dict) and any(key in nested for key in _NAME_KEYS + _ARG_KEYS):
        payload = nested

    name: Any = None
    for key in _NAME_KEYS:
        candidate = payload.get(key)
        if isinstance(candidate, str) and candidate.strip():
            name = candidate.strip()
            break
    if not name:
        return None

    arguments: Any = None
    for key in _ARG_KEYS:
        if key in payload:
            arguments = payload[key]
            break
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments)
        except json.JSONDecodeError:
            return None
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, dict):
        return None
    return ExtractedCall(name=name, arguments=arguments, path=path)


def extract_from_text(text: str, *, path: str = "text") -> list[ExtractedCall]:
    """Balanced-brace scan.  Returns every plausible call, in order."""
    if not text or "{" not in text:
        return []
    candidates: list[str] = []
    for fenced in _FENCE_RE.findall(text):
        candidates.extend(_balanced_objects(fenced))
    candidates.extend(_balanced_objects(text))

    calls: list[ExtractedCall] = []
    seen: set[str] = set()
    for raw in candidates:
        if raw in seen:
            continue
        seen.add(raw)
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            continue
        # A wrapper such as {"tool_calls": [ ... ]}.
        if isinstance(payload, dict) and isinstance(payload.get("tool_calls"), list):
            for item in payload["tool_calls"][:MAX_CANDIDATES]:
                call = _coerce_call(item, path=path)
                if call is not None:
                    calls.append(call)
            continue
        call = _coerce_call(payload, path=path)
        if call is not None:
            calls.append(call)
    return calls


def extract_native(tool_calls: Iterable[Any]) -> list[ExtractedCall]:
    """Normalise provider-emitted ``ToolCall`` objects."""
    calls: list[ExtractedCall] = []
    for item in tool_calls:
        name = getattr(item, "name", None)
        arguments = getattr(item, "arguments", None)
        if not name:
            continue
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except json.JSONDecodeError:
                arguments = None
        if not isinstance(arguments, dict):
            arguments = {}
        calls.append(ExtractedCall(name=str(name), arguments=arguments, path="native"))
    return calls


def looks_like_tool_intent(text: str) -> bool:
    """Heuristic for "a tool call was structurally expected but unparsed".

    Only used to decide whether to spend a constrained-decoding retry.  It never
    turns prose into a call — the only thing that can produce a call is a parsed,
    schema-valid JSON object naming a registered tool.
    """
    if not text:
        return False
    lowered = text.lower()
    if '"tool"' in lowered or '"arguments"' in lowered or "tool_call" in lowered:
        return True
    return bool(re.search(r"\{\s*\"?[a-z_]+\"?\s*:", lowered))


def tool_call_json_schema(tool_names: list[str]) -> dict[str, Any]:
    """Schema used for the constrained-decoding retry."""
    return {
        "type": "object",
        "properties": {
            "tool": {"type": "string", "enum": tool_names},
            "arguments": {"type": "object"},
        },
        "required": ["tool", "arguments"],
    }


__all__ = [
    "ExtractedCall",
    "ExtractionMetrics",
    "extract_from_text",
    "extract_native",
    "looks_like_tool_intent",
    "metrics",
    "tool_call_json_schema",
]
