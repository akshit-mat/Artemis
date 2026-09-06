import uuid
import anyio
from datetime import datetime, timezone

from .context import ContextAssembler, estimate_tokens
from .manager import run_manager
from ..storage.repositories.runs import RunRepository
from ..storage.repositories.messages import MessageRepository
from ..storage.repositories.sessions import SessionRepository
from ..models.registry import ModelRegistry
from ..api.events import bus
from ..models.base import GenOptions
from .policy import should_use_reasoning
from .state import state_computer

from ..obs.logging import get_logger

log = get_logger("agent.loop")

class AgentOrchestrator:
    def __init__(self,
                 run_repo: RunRepository,
                 message_repo: MessageRepository,
                 model_registry: ModelRegistry,
                 session_repo: SessionRepository | None = None):
        self.run_repo = run_repo
        self.message_repo = message_repo
        self.model_registry = model_registry
        self.session_repo = session_repo

    async def handle_chat(self, session_id: str, text: str, client_msg_id: str = None, reasoning: bool | None = None) -> str:
        """
        Entry point for chat.send.
        1. Validates & creates run
        2. Persists user message
        3. Spawns the stream in the background
        """
        # A single chat.send must create exactly one run
        # If client_msg_id matches an existing run processing, we could return it (idempotency),
        # but for now we just create a new run_id
        run_id = f"r_{uuid.uuid4().hex[:12]}"

        # Determine model
        model_config = self.model_registry.get_config("primary")
        if not model_config:
            raise ValueError("No primary model configured")

        # 1. Ensure session row exists (INSERT OR IGNORE) so the FK constraint
        #    on runs.session_id is satisfied even on a fresh production database.
        if self.session_repo is not None:
            await self.session_repo.ensure_session(session_id)

        # 2. Create run
        await self.run_repo.create_run(run_id, session_id, model_config.id)

        # 3. Persist user message
        user_msg_id = client_msg_id or f"m_{uuid.uuid4().hex[:12]}"
        await self.message_repo.append_message(
            id=user_msg_id,
            session_id=session_id,
            role="user",
            content=text,
            trust="USER",
            token_estimate=estimate_tokens(text),
            run_id=run_id
        )

        # We don't block the caller (WebSocket). The task runs in the background.
        # But we want to ensure anyio can run it independently. We assume the caller
        # (the FastAPI route or lifespan task group) will execute `run_conversation`
        return run_id

    async def run_conversation(self, run_id: str, session_id: str, reasoning: bool | None = None) -> None:
        """
        The background task that actually executes the conversation.
        assemble -> stream -> persist
        """
        # Mark as RUNNING
        await self.run_repo.update_run_status(run_id, "RUNNING")
        state_computer.set_state(run_id, "THINKING", intensity=1.0, run_id=run_id)
        bus.publish("agent.state", state_computer.compute(), session_id, run_id)

        model_config = self.model_registry.get_config("primary")
        provider = self.model_registry.get_provider("primary")

        # Setup cancellation scope for this run
        cancel_scope = anyio.CancelScope()
        run_manager.register(run_id, cancel_scope)

        try:
            # ASSEMBLE
            raw_messages = await self.message_repo.get_messages_for_session(session_id)
            # Ensure context assembler matches the model's num_ctx
            assembler = ContextAssembler(num_ctx=model_config.num_ctx)
            assembly = assembler.assemble(raw_messages)

            # INFER (Stream)
            content_buffer = ""
            reasoning_buffer = ""
            usage = None
            finish_reason = None
            error_code = None

            options: GenOptions = {} # defaults handled by provider
            if reasoning is not None:
                options["reasoning"] = reasoning
            else:
                # Apply policy on the last user message
                last_user_msg = next((m["content"] for m in reversed(raw_messages) if m["role"] == 'user'), "")
                options["reasoning"] = should_use_reasoning(last_user_msg)

            import time
            token_count = 0
            last_rate_time = time.monotonic()

            # Bounded time per turn (120s)
            with anyio.fail_after(120.0):
                stream_iter = provider.stream(assembly.messages, None, options, cancel_scope)
                async for chunk in stream_iter:
                    if chunk.kind == "content":
                        if chunk.text:
                            if not content_buffer:
                                state_computer.set_state(run_id, "RESPONDING", intensity=1.0, run_id=run_id)
                                bus.publish("agent.state", state_computer.compute(), session_id, run_id)
                            content_buffer += chunk.text

                            token_count += estimate_tokens(chunk.text)
                            now = time.monotonic()
                            dt = now - last_rate_time
                            if dt >= 0.5:
                                rate = token_count / dt
                                # Normalise intensity: 40 tokens/sec = 1.0
                                intensity = min(1.5, max(0.2, rate / 40.0))
                                state_computer.set_state(run_id, "RESPONDING", intensity=intensity, run_id=run_id)
                                bus.publish("agent.state", state_computer.compute(), session_id, run_id)
                                token_count = 0
                                last_rate_time = now

                            bus.publish("agent.delta", {"channel": "content", "text": chunk.text}, session_id, run_id)
                    elif chunk.kind == "reasoning":
                        if chunk.text:
                            reasoning_buffer += chunk.text
                            bus.publish("agent.delta", {"channel": "reasoning", "text": chunk.text}, session_id, run_id)
                    elif chunk.kind == "usage":
                        usage = chunk.usage
                    elif chunk.kind == "error":
                        error_code = chunk.error.code
                        raise RuntimeError(f"Provider error: {chunk.error.message}")
                    elif chunk.kind == "done":
                        finish_reason = chunk.finish_reason

            # DONE - PERSIST
            # A run produces at most one persisted assistant message
            if content_buffer:
                msg_id = f"m_{uuid.uuid4().hex[:12]}"
                await self.message_repo.append_message(
                    id=msg_id,
                    session_id=session_id,
                    role="assistant",
                    content=content_buffer, # reasoning is NOT included here
                    trust="SYSTEM",
                    token_estimate=estimate_tokens(content_buffer),
                    run_id=run_id
                )

                tokens_dict = {}
                if usage:
                    tokens_dict["in"] = usage.input_tokens
                    tokens_dict["out"] = usage.output_tokens

                bus.publish("agent.message", {
                    "message_id": msg_id,
                    "role": "assistant",
                    "content": content_buffer,
                    "finish_reason": finish_reason or "stop",
                    "steps_used": 1,
                    "tokens": tokens_dict,
                    "incomplete": False
                }, session_id, run_id)

            # Clean completion
            await self.run_repo.update_run_status(
                run_id,
                "DONE",
                steps_used=1,
                input_tokens=usage.input_tokens if usage else 0,
                output_tokens=usage.output_tokens if usage else 0,
                reasoning_blob_ref=None # Not persisting blobs in this phase
            )
            state_computer.clear_state(run_id)
            bus.publish("agent.state", state_computer.compute(), session_id, run_id)

        except TimeoutError:
            # Wall clock timeout
            log.error("run_wall_clock_timeout", run_id=run_id)
            await self._fail_run(run_id, session_id, "MODEL_TIMEOUT", "Agent turn wall clock timeout")
        except RuntimeError as e:
            # Provider errors
            log.error("run_provider_error", run_id=run_id, error=str(e))
            # error_code is captured during the loop, default to INTERNAL if missed
            code = error_code or "INTERNAL"
            if code == "CANCELLED":
                # Provider emitted CANCELLED chunk because cancel_token was triggered
                await self._cancel_run(run_id, session_id)
            else:
                await self._fail_run(run_id, session_id, code, str(e))
        except Exception as e:
            # Other uncaught errors
            log.error("run_internal_error", run_id=run_id, error=str(e), exc_info=True)
            await self._fail_run(run_id, session_id, "INTERNAL", "Internal agent error")
        finally:
            run_manager.unregister(run_id)
            # Ensure we check if cancelled from the outside during the try block
            if cancel_scope.cancel_called and error_code != "CANCELLED":
                await self._cancel_run(run_id, session_id)

    async def _fail_run(self, run_id: str, session_id: str, code: str, message: str) -> None:
        """Helper to fail a run and emit the error event."""
        await self.run_repo.update_run_status(run_id, "FAILED", error_code=code)
        bus.publish("agent.error", {
            "code": code,
            "message": message,
            "recoverable": False,
            "correlation_id": run_id
        }, session_id, run_id)
        state_computer.set_state(f"error_{run_id}", "ERROR", intensity=1.0, run_id=run_id, detail=message)
        state_computer.clear_state(run_id)
        bus.publish("agent.state", state_computer.compute(), session_id, run_id)

    async def _cancel_run(self, run_id: str, session_id: str) -> None:
        """Helper to cleanly transition a run to CANCELLED state."""
        await self.run_repo.update_run_status(run_id, "CANCELLED", cancel_reason="User requested")
        bus.publish("agent.error", {
            "code": "CANCELLED",
            "message": "Run cancelled by user",
            "recoverable": False,
            "correlation_id": run_id
        }, session_id, run_id)
        state_computer.clear_state(run_id)
        bus.publish("agent.state", state_computer.compute(), session_id, run_id)
