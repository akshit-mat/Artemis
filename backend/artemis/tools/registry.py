"""Tool registry — explicit registration, no filesystem discovery.

``docs/tools.md`` §3.  Plugin scanning is an attack surface and a debugging
hazard, so the registry is populated by an explicit list in
``tools/builtin/__init__.py``.

Responsibilities: name uniqueness, JSON-Schema generation, capability gating,
enabled/disabled state, and the compact schema rendering used by the context
assembler.  **Tool visibility is not tool permission**: a tool whose effective
decision is ``DENY`` is omitted from the schema list entirely, which saves
context and removes the temptation.
"""

from __future__ import annotations

import shutil
import sys
from typing import Callable, Iterable, Iterator, Mapping, Optional

from ..obs.logging import get_logger
from .contract import Decision, ToolSpec

log = get_logger("tools.registry")


class ToolNotFound(KeyError):
    """The model proposed a tool that does not exist.  Fails safe as a denial."""


def detect_capabilities() -> frozenset[str]:
    """Capabilities available on this machine.

    Declared via ``ToolSpec.requires``; a missing capability makes the tool
    report ``unavailable`` rather than failing in a confusing way.
    """
    caps: set[str] = {"cpu"}
    if sys.platform == "win32":
        caps.add("windows")
    if shutil.which("nvidia-smi"):
        caps.add("gpu")
    try:
        import psutil  # noqa: PLC0415 - probe only

        caps.add("psutil")
        if getattr(psutil, "sensors_battery", None) and psutil.sensors_battery() is not None:
            caps.add("battery")
    except Exception:  # pragma: no cover - psutil is a declared dependency
        pass
    return frozenset(caps)


class ToolRegistry:
    """Single in-process registry."""

    def __init__(self, capabilities: Iterable[str] | None = None) -> None:
        self._specs: dict[str, ToolSpec] = {}
        self._capabilities = (
            frozenset(capabilities) if capabilities is not None else detect_capabilities()
        )

    # -- registration --------------------------------------------------------

    def register(self, *specs: ToolSpec) -> None:
        for spec in specs:
            spec.validate_coherence()
            if spec.name in self._specs:
                raise ValueError(f"duplicate tool name: {spec.name}")
            self._specs[spec.name] = spec
            log.debug("tool_registered", tool=spec.name, risk=spec.risk.value, tier=spec.tier.value)

    def clear(self) -> None:
        self._specs.clear()

    # -- lookup --------------------------------------------------------------

    def __contains__(self, name: object) -> bool:
        return name in self._specs

    def __iter__(self) -> Iterator[ToolSpec]:
        return iter(self._specs.values())

    def __len__(self) -> int:
        return len(self._specs)

    def get(self, name: str) -> ToolSpec:
        try:
            return self._specs[name]
        except KeyError as exc:
            raise ToolNotFound(name) from exc

    def try_get(self, name: str) -> Optional[ToolSpec]:
        return self._specs.get(name)

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._specs))

    def all(self) -> tuple[ToolSpec, ...]:
        return tuple(self._specs[name] for name in sorted(self._specs))

    # -- capability gating ----------------------------------------------------

    @property
    def capabilities(self) -> frozenset[str]:
        return self._capabilities

    def missing_capabilities(self, spec: ToolSpec) -> frozenset[str]:
        return frozenset(spec.requires) - self._capabilities

    def is_available(self, spec: ToolSpec) -> bool:
        return spec.enabled and not self.missing_capabilities(spec)

    # -- schema rendering ----------------------------------------------------

    def visible(
        self, decider: Callable[[ToolSpec], Decision] | Mapping[str, Decision] | None = None
    ) -> tuple[ToolSpec, ...]:
        """Tools exposed to the model.

        ``DENY`` tools are omitted.  Tools denied only *by taint* remain listed
        because they are legitimate in untainted turns; the denial is explained
        at call time (``docs/tools.md`` §3).
        """
        result: list[ToolSpec] = []
        for spec in self.all():
            if not spec.enabled:
                continue
            if self.missing_capabilities(spec):
                continue
            if decider is None:
                result.append(spec)
                continue
            decision = (
                decider.get(spec.name, Decision.ASK)
                if isinstance(decider, Mapping)
                else decider(spec)
            )
            if decision is Decision.DENY:
                continue
            result.append(spec)
        return tuple(result)

    def provider_schemas(
        self, decider: Callable[[ToolSpec], Decision] | Mapping[str, Decision] | None = None
    ) -> list[dict[str, object]]:
        return [spec.provider_schema() for spec in self.visible(decider)]

    def compact_catalog(
        self, decider: Callable[[ToolSpec], Decision] | Mapping[str, Decision] | None = None
    ) -> list[dict[str, object]]:
        return [spec.compact_schema() for spec in self.visible(decider)]

    def render_prompt_catalog(
        self, decider: Callable[[ToolSpec], Decision] | Mapping[str, Decision] | None = None
    ) -> str:
        """One compact line per tool for the Tier-1 context slot."""
        lines: list[str] = []
        for spec in self.visible(decider):
            schema = spec.compact_schema()
            params = schema["parameters"]["properties"]  # type: ignore[index]
            required = set(schema["parameters"]["required"])  # type: ignore[index]
            rendered = ", ".join(
                f"{name}{'' if name in required else '?'}:{meta.get('type', 'string')}"
                for name, meta in params.items()  # type: ignore[union-attr]
            )
            lines.append(f"- {spec.name}({rendered}) — {spec.summary}")
        return "\n".join(lines)


#: Process-wide registry.  Populated by ``tools.builtin.register_builtin_tools``.
REGISTRY = ToolRegistry()


__all__ = ["REGISTRY", "ToolNotFound", "ToolRegistry", "detect_capabilities"]
