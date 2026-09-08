"""Agent orchestrator — the controlled multi-step loop (``docs/agent.md`` §2).

The FSM is explicit and hand-written (ADR-004):

    ASSEMBLE → INFER → PARSE → (RESPOND | VALIDATE | REPAIR)
    VALIDATE → AUTHORIZE → (EXECUTE | AWAIT_APPROVAL | DENIED) → ASSEMBLE

Every guard in ``docs/agent.md`` §2 is enforced here, in code, and none of them
is negotiable by the model.  Authority lives in :class:`ToolMediator`; this class
never touches the tool runtime directly.

Phase 2/3 behaviour is preserved exactly: with no mediator (or with tools
disabled) the loop is a single ASSEMBLE → INFER → RESPOND round, which is what
the existing regression tests assert.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

import anyio

from ..api.events import bus
from ..models.base import GenOptions
from ..models.registry import ModelRegistry
from ..obs.logging import get_logger
from ..policy.taint import STANDING_INSTRUCTION, taint_tracker
from ..storage.repositories.messages import MessageRepository
from ..storage.repositories.runs import RunRepository
from ..storage.repositories.sessions import SessionRepository
from ..tools.contract import CancelToken, Decision, canonical_hash
from . import toolcalls
from .context import ContextAssembler, estimate_tokens
from .manager import run_manager
from .policy import should_use_reasoning
from .state import state_computer

log = get_logger("agent.loop")


@dataclass(slots=True)
class AgentGuards:
    """``docs/agent.md`` §2 guard table.  Defaults are the documented defaults."""

    max_steps: int = 6
    turn_wall_clock_s: float = 120.0
    first_token_timeout_s: float = 20.0
    max_repair_attempts: int = 2
    max_side_effect_calls_per_turn: int = 5
    max_parallel_tool_calls: int = 1
    repeated_call_limit: int = 3
    tools_enabled: bool = True

    @classmethod
    def from_config(cls, config: Any) -> "AgentGuards":
        section = getattr(config, "agent", None)
        if section is None:
            return cls()
        return cls(
            max_steps=section.max_steps,
            turn_wall_clock_s=section.turn_wall_clock_s,
            first_token_timeout_s=section.first_token_timeout_s,
            max_repair_attempts=section.max_repair_attempts,
            max_side_effect_calls_per_turn=section.max_side_effect_calls_per_turn,
            max_parallel_tool_calls=section.max_parallel_tool_calls,
            repeated_call_limit=section.repeated_call_limit,
            tools_enabled=section.tools_enabled,
        )


@dataclass(slots=True)
class TurnBudget:
    """Mutable per-turn counters."""

    steps_used: int = 0
    repairs: int = 0
    side_effect_calls: int = 0
    call_counts: dict[str, int] = field(default_factory=dict)
    tool_failures: dict[str, int] = field(default_factory=dict)

    def note_call(self, tool: str, args_hash: str) -> int:
        key = f"{tool}:{args_hash}"
        self.call_counts[key] = self.call_counts.get(key, 0) + 1
        return self.call_counts[key]


class AgentOrchestrator:
    def __init__(
        self,
        run_repo: RunRepository,
        message_repo: MessageRepository,
        model_registry: ModelRegistry,
        session_repo: SessionRepository | None = None,
        mediator: Any = None,
        guards: AgentGuards | None = None,
    ):
        self.run_repo = run_repo
        self.message_repo = message_repo
        self.model_registry = model_registry
        self.session_repo = session_repo
        self.mediator = mediator
        self.guards = guards or AgentGuards()

    # -- entry point ---------------------------------------------------------

    async def handle_chat(
        self,
        session_id: str,
        text: str,
        client_msg_id: str = None,
        reasoning: bool | None = None,
    ) -> str:
        """Validate, create the run, persist the user turn.  Returns ``run_id``."""
        run_id = f"r_{uuid.uuid4().hex[:12]}"

        model_config = self.model_registry.get_config("primary")
        if not model_config:
            raise ValueError("No primary model configured")

        if self.session_repo is not None:
            await self.session_repo.ensure_session(session_id)

        await self.run_repo.create_run(run_id, session_id, model_config.id)

        user_msg_id = client_msg_id or f"m_{uuid.uuid4().hex[:12]}"
        await self.message_repo.append_message(
            id=user_msg_id,
            session_id=session_id,
            role="user",
            content=text,
            trust="USER",
            token_estimate=estimate_tokens(text),
            run_id=run_id,
        )
        # A new user turn starts an untainted run (``docs/security.md`` §4).
        taint_tracker.clear(run_id)
        return run_id

    # -- the loop ------------------------------------------------------------

    async def run_conversation(
        self, run_id: str, session_id: str, reasoning: bool | None = None
    ) -> None:
        await self.run_repo.update_run_status(run_id, "RUNNING")
        state_computer.set_state(run_id, "THINKING", intensity=1.0, run_id=run_id)
        bus.publish("agent.state", state_computer.compute(), session_id, run_id)

        model_config = self.model_registry.get_config("primary")
        provider = self.model_registry.get_provider("primary")

        cancel_scope = anyio.CancelScope()
        cancel_token = CancelToken()
        run_manager.register(run_id, cancel_scope, cancel_token)

        budget = TurnBudget()
        usage_in = 0
        usage_out = 0
        error_code: str | None = None
        final_content = ""
        finish_reason = "stop"
        incomplete = False
        terminal_error: tuple[str, str] | None = None
        tool_transcript: list[dict[str, str]] = []

        try:
            with anyio.fail_after(self.guards.turn_wall_clock_s):
                raw_messages = await self.message_repo.get_messages_for_session(session_id)
                last_user_text = next(
                    (m["content"] for m in reversed(raw_messages) if m["role"] == "user"), ""
                )
                options: GenOptions = {}
                if reasoning is not None:
                    options["reasoning"] = reasoning
                else:
                    options["reasoning"] = should_use_reasoning(last_user_text)

                while True:
                    if budget.steps_used >= self.guards.max_steps:
                        terminal_error = (
                            "MAX_STEPS",
                            "I stopped after the maximum number of steps for one turn.",
                        )
                        incomplete = True
                        break

                    budget.steps_used += 1
                    tool_schemas = self._tool_schemas(session_id, run_id)
                    assembly = self._assemble(
                        raw_messages,
                        model_config,
                        tool_transcript=tool_transcript,
                        has_tools=bool(tool_schemas),
                        tainted=taint_tracker.is_tainted(run_id),
                    )

                    step = await self._infer(
                        provider=provider,
                        messages=assembly.messages,
                        tools=tool_schemas,
                        options=options,
                        cancel_scope=cancel_scope,
                        session_id=session_id,
                        run_id=run_id,
                    )
                    usage_in += step.input_tokens
                    usage_out += step.output_tokens
                    if step.finish_reason:
                        finish_reason = step.finish_reason
                    if step.error_code:
                        error_code = step.error_code
                        raise RuntimeError(step.error_message or step.error_code)

                    calls = step.calls
                    if not calls and tool_schemas and not step.content.strip():
                        # Nothing usable: either repair or end honestly.
                        if budget.repairs < self.guards.max_repair_attempts:
                            budget.repairs += 1
                            tool_transcript.append(
                                {
                                    "role": "system_note",
                                    "content": (
                                        "Your previous reply was empty. Reply with plain "
                                        "text, or a single JSON object "
                                        '{"tool": "<name>", "arguments": {...}}.'
                                    ),
                                }
                            )
                            continue
                        terminal_error = (
                            "TOOL_CALL_UNPARSEABLE",
                            "I could not produce a usable reply for that request.",
                        )
                        break

                    # Unparseable-but-intended tool call → repair.
                    if step.needs_repair:
                        if budget.repairs < self.guards.max_repair_attempts:
                            budget.repairs += 1
                            tool_transcript.append(
                                {
                                    "role": "system_note",
                                    "content": step.repair_note
                                    or "The tool call was not valid JSON. Try again.",
                                }
                            )
                            continue
                        terminal_error = (
                            "TOOL_CALL_UNPARSEABLE",
                            "I could not read that tool call, so I stopped.",
                        )
                        break

                    if not calls:
                        final_content = step.content
                        break

                    # max_parallel_tool_calls (Phase 4 = 1): extras are serialised.
                    stop_turn = False
                    for call in calls[: max(1, self.guards.max_parallel_tool_calls)]:
                        outcome = await self._run_tool(
                            call=call,
                            run_id=run_id,
                            session_id=session_id,
                            user_turn_text=last_user_text,
                            model_rationale=step.content.strip(),
                            budget=budget,
                            cancel_token=cancel_token,
                        )
                        if outcome is None:
                            terminal_error = (
                                "REPEATED_TOOL_CALL",
                                "I stopped because I was about to repeat the same action.",
                            )
                            stop_turn = True
                            break
                        tool_transcript.append(
                            {
                                "role": "tool",
                                "content": self._render_tool_message(call.name, outcome),
                            }
                        )
                        if outcome.side_effect and outcome.result.status == "ok":
                            budget.side_effect_calls += 1
                        if outcome.result.status in ("error", "denied", "timeout", "unavailable"):
                            failures = budget.tool_failures.get(call.name, 0) + 1
                            budget.tool_failures[call.name] = failures
                            if failures >= 2:
                                terminal_error = (
                                    "TOOL_ERROR",
                                    f"'{call.name}' failed twice, so I stopped.",
                                )
                                stop_turn = True
                                break
                        if outcome.result.status == "cancelled":
                            raise _Cancelled()
                    if stop_turn:
                        break

                    state_computer.set_state(
                        run_id, "THINKING", intensity=1.0, run_id=run_id
                    )
                    bus.publish("agent.state", state_computer.compute(), session_id, run_id)

            await self._finalize(
                run_id=run_id,
                session_id=session_id,
                content=final_content,
                finish_reason=finish_reason,
                steps_used=budget.steps_used,
                usage_in=usage_in,
                usage_out=usage_out,
                incomplete=incomplete,
                terminal_error=terminal_error,
            )

        except _Cancelled:
            await self._cancel_run(run_id, session_id)
        except TimeoutError:
            log.error("run_wall_clock_timeout", run_id=run_id)
            cancel_token.cancel()
            await self._fail_run(
                run_id, session_id, "MODEL_TIMEOUT", "Agent turn wall clock timeout"
            )
        except RuntimeError as e:
            log.error("run_provider_error", run_id=run_id, error=str(e))
            code = error_code or "INTERNAL"
            if code == "CANCELLED":
                await self._cancel_run(run_id, session_id)
            else:
                await self._fail_run(run_id, session_id, code, str(e))
        except Exception as e:  # noqa: BLE001 - never leave the UI spinning
            log.error("run_internal_error", run_id=run_id, error=str(e), exc_info=True)
            await self._fail_run(run_id, session_id, "INTERNAL", "Internal agent error")
        finally:
            run_manager.unregister(run_id)
            if cancel_scope.cancel_called and error_code != "CANCELLED":
                cancel_token.cancel()
                await self._cancel_run(run_id, session_id)

    # -- steps ---------------------------------------------------------------

    def _tool_schemas(self, session_id: str, run_id: str) -> list[dict[str, Any]] | None:
        if self.mediator is None or not self.guards.tools_enabled:
            return None
        try:
            decisions = self.mediator.effective_decisions(
                session_id=session_id, tainted=taint_tracker.is_tainted(run_id)
            )
            schemas = self.mediator.registry.provider_schemas(decisions)
        except Exception as exc:  # noqa: BLE001 - a schema failure must not kill the turn
            log.error("tool_schema_failed", error=str(exc))
            return None
        return schemas or None

    def _assemble(
        self,
        raw_messages: list[Any],
        model_config: Any,
        *,
        tool_transcript: list[dict[str, str]],
        has_tools: bool,
        tainted: bool,
    ):
        assembler = ContextAssembler(num_ctx=model_config.num_ctx)
        catalog = ""
        if has_tools and self.mediator is not None:
            catalog = self.mediator.registry.render_prompt_catalog(
                self.mediator.effective_decisions(session_id="s", tainted=tainted)
            )
        assembly = assembler.assemble(
            raw_messages,
            tool_catalog=catalog,
            tool_results=tool_transcript,
            standing_instruction=STANDING_INSTRUCTION if tainted else "",
        )
        return assembly

    async def _infer(
        self,
        *,
        provider: Any,
        messages: list[Any],
        tools: list[dict[str, Any]] | None,
        options: GenOptions,
        cancel_scope: anyio.CancelScope,
        session_id: str,
        run_id: str,
    ) -> "_StepResult":
        """One inference round, with the documented single connection retry."""
        attempt = 0
        while True:
            attempt += 1
            step = await self._stream_once(
                provider=provider,
                messages=messages,
                tools=tools,
                options=options,
                cancel_scope=cancel_scope,
                session_id=session_id,
                run_id=run_id,
            )
            if (
                step.error_code == "MODEL_UNAVAILABLE"
                and attempt == 1
                and not cancel_scope.cancel_called
            ):
                log.warning("provider_retry", run_id=run_id, error_code=step.error_code)
                await anyio.sleep(0.25)  # docs/agent.md §2 Retries
                continue
            return step

    async def _stream_once(
        self,
        *,
        provider: Any,
        messages: list[Any],
        tools: list[dict[str, Any]] | None,
        options: GenOptions,
        cancel_scope: anyio.CancelScope,
        session_id: str,
        run_id: str,
    ) -> "_StepResult":
        step = _StepResult()
        token_count = 0
        last_rate_time = time.monotonic()
        native_calls: list[Any] = []

        stream_iter = provider.stream(messages, tools, options, cancel_scope)
        async for chunk in stream_iter:
            if chunk.kind == "content":
                if chunk.text:
                    if not step.content:
                        state_computer.set_state(
                            run_id, "RESPONDING", intensity=1.0, run_id=run_id
                        )
                        bus.publish("agent.state", state_computer.compute(), session_id, run_id)
                    step.content += chunk.text
                    token_count += estimate_tokens(chunk.text)
                    now = time.monotonic()
                    dt = now - last_rate_time
                    if dt >= 0.5:
                        rate = token_count / dt
                        intensity = min(1.5, max(0.2, rate / 40.0))
                        state_computer.set_state(
                            run_id, "RESPONDING", intensity=intensity, run_id=run_id
                        )
                        bus.publish("agent.state", state_computer.compute(), session_id, run_id)
                        token_count = 0
                        last_rate_time = now
                    bus.publish(
                        "agent.delta",
                        {"channel": "content", "text": chunk.text},
                        session_id,
                        run_id,
                    )
            elif chunk.kind == "reasoning":
                if chunk.text:
                    step.reasoning += chunk.text
                    bus.publish(
                        "agent.delta",
                        {"channel": "reasoning", "text": chunk.text},
                        session_id,
                        run_id,
                    )
            elif chunk.kind == "tool_call":
                if chunk.tool_call is not None:
                    native_calls.append(chunk.tool_call)
            elif chunk.kind == "usage":
                if chunk.usage:
                    step.input_tokens = chunk.usage.input_tokens
                    step.output_tokens = chunk.usage.output_tokens
            elif chunk.kind == "error":
                step.error_code = chunk.error.code
                step.error_message = chunk.error.message
                return step
            elif chunk.kind == "done":
                step.finish_reason = chunk.finish_reason

        if native_calls:
            step.calls = toolcalls.extract_native(native_calls)
            for call in step.calls:
                toolcalls.metrics.record(call.path)
            return step

        if tools:
            extracted = toolcalls.extract_from_text(step.content)
            if extracted:
                step.calls = extracted
                for call in extracted:
                    toolcalls.metrics.record(call.path)
                # Prose that accompanied a tool call is rationale, not an answer.
                return step
            if toolcalls.looks_like_tool_intent(step.content):
                toolcalls.metrics.record_failure()
                step.needs_repair = True
                step.repair_note = (
                    "Your reply looked like a tool call but was not valid JSON. "
                    'Reply with exactly one JSON object: {"tool": "<name>", '
                    '"arguments": {...}} — or answer in plain text.'
                )
        return step

    async def _run_tool(
        self,
        *,
        call: toolcalls.ExtractedCall,
        run_id: str,
        session_id: str,
        user_turn_text: str,
        model_rationale: str,
        budget: TurnBudget,
        cancel_token: CancelToken,
    ):
        args_hash = canonical_hash(call.arguments)
        count = budget.note_call(call.name, args_hash)
        if count > self.guards.repeated_call_limit:
            log.warning("repeated_tool_call_guard", run_id=run_id, tool=call.name)
            return None

        spec = self.mediator.registry.try_get(call.name)
        side_effecting = bool(spec and spec.side_effects)
        state = "EXECUTING" if side_effecting else "SEARCHING"
        state_computer.set_state(
            run_id, state, intensity=0.8, run_id=run_id, detail=f"{call.name}…"
        )
        bus.publish("agent.state", state_computer.compute(), session_id, run_id)

        approval_state_key = f"approval_{run_id}"
        try:
            outcome = await self.mediator.handle_proposal(
                tool_name=call.name,
                raw_args=call.arguments,
                run_id=run_id,
                session_id=session_id,
                user_turn_text=user_turn_text,
                model_rationale=model_rationale,
                side_effect_budget_exceeded=(
                    budget.side_effect_calls >= self.guards.max_side_effect_calls_per_turn
                ),
                cancel_token=cancel_token,
            )
        finally:
            state_computer.clear_state(approval_state_key)
        return outcome

    @staticmethod
    def _render_tool_message(tool_name: str, outcome: Any) -> str:
        result = outcome.result
        header = f"[tool:{tool_name} status={result.status}]"
        body = result.context_view or result.summary
        if result.status != "ok":
            body = result.summary
            if result.error_code:
                body = f"{body} (code={result.error_code})"
        if result.truncated and result.result_id:
            body = f"{body}\n(result_id={result.result_id}; use read_more to continue)"
        return f"{header}\n{body}"

    # -- termination ---------------------------------------------------------

    async def _finalize(
        self,
        *,
        run_id: str,
        session_id: str,
        content: str,
        finish_reason: str,
        steps_used: int,
        usage_in: int,
        usage_out: int,
        incomplete: bool,
        terminal_error: tuple[str, str] | None,
    ) -> None:
        if content:
            msg_id = f"m_{uuid.uuid4().hex[:12]}"
            await self.message_repo.append_message(
                id=msg_id,
                session_id=session_id,
                role="assistant",
                content=content,
                trust="SYSTEM",
                token_estimate=estimate_tokens(content),
                run_id=run_id,
            )
            bus.publish(
                "agent.message",
                {
                    "message_id": msg_id,
                    "role": "assistant",
                    "content": content,
                    "finish_reason": finish_reason,
                    "steps_used": steps_used,
                    "tokens": {"in": usage_in, "out": usage_out} if usage_in or usage_out else {},
                    "incomplete": incomplete,
                },
                session_id,
                run_id,
            )

        if terminal_error is not None:
            code, message = terminal_error
            await self.run_repo.update_run_status(
                run_id,
                "DONE" if content else "FAILED",
                steps_used=steps_used,
                input_tokens=usage_in,
                output_tokens=usage_out,
                error_code=code,
                tainted=taint_tracker.is_tainted(run_id),
            )
            bus.publish(
                "agent.error",
                {
                    "code": code,
                    "message": message,
                    "recoverable": True,
                    "correlation_id": run_id,
                },
                session_id,
                run_id,
            )
            state_computer.clear_state(run_id)
            bus.publish("agent.state", state_computer.compute(), session_id, run_id)
            return

        await self.run_repo.update_run_status(
            run_id,
            "DONE",
            steps_used=steps_used,
            input_tokens=usage_in,
            output_tokens=usage_out,
            tainted=taint_tracker.is_tainted(run_id),
            reasoning_blob_ref=None,
        )
        state_computer.clear_state(run_id)
        bus.publish("agent.state", state_computer.compute(), session_id, run_id)

    async def _fail_run(self, run_id: str, session_id: str, code: str, message: str) -> None:
        await self.run_repo.update_run_status(run_id, "FAILED", error_code=code)
        bus.publish(
            "agent.error",
            {
                "code": code,
                "message": message,
                "recoverable": False,
                "correlation_id": run_id,
            },
            session_id,
            run_id,
        )
        state_computer.set_state(
            f"error_{run_id}", "ERROR", intensity=1.0, run_id=run_id, detail=message
        )
        state_computer.clear_state(run_id)
        bus.publish("agent.state", state_computer.compute(), session_id, run_id)

    async def _cancel_run(self, run_id: str, session_id: str) -> None:
        await self.run_repo.update_run_status(
            run_id, "CANCELLED", cancel_reason="User requested"
        )
        bus.publish(
            "agent.error",
            {
                "code": "CANCELLED",
                "message": "Run cancelled by user",
                "recoverable": False,
                "correlation_id": run_id,
            },
            session_id,
            run_id,
        )
        state_computer.clear_state(run_id)
        bus.publish("agent.state", state_computer.compute(), session_id, run_id)


class _Cancelled(Exception):
    """Internal signal: a tool reported cancellation."""


@dataclass(slots=True)
class _StepResult:
    content: str = ""
    reasoning: str = ""
    calls: list[toolcalls.ExtractedCall] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0
    finish_reason: str | None = None
    error_code: str | None = None
    error_message: str | None = None
    needs_repair: bool = False
    repair_note: str | None = None


__all__ = ["AgentGuards", "AgentOrchestrator", "TurnBudget"]
