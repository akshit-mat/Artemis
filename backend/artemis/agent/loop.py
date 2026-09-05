import logging
import uuid
import anyio
from datetime import datetime, timezone

from .context import ContextAssembler, estimate_tokens
from .manager import run_manager
from ..storage.repositories.runs import RunRepository
from ..storage.repositories.messages import MessageRepository
from ..models.registry import ModelRegistry
from ..api.events import bus
from ..models.base import GenOptions

log = logging.getLogger("agent.loop")

class AgentOrchestrator:
    def __init__(self,
                 run_repo: RunRepository,
                 message_repo: MessageRepository,
                 model_registry: ModelRegistry):
        self.run_repo = run_repo
        self.message_repo = message_repo
        self.model_registry = model_registry

    async def handle_chat(self, session_id: str, text: str, client_msg_id: str = None) -> str:
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

        # 1. Create run
        await self.run_repo.create_run(run_id, session_id, model_config.id)

        # 2. Persist user message
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

    async def run_conversation(self, run_id: str, session_id: str) -> None:
        """
        The background task that actually executes the conversation.
        assemble -> stream -> persist
        """
        # Mark as RUNNING
        await self.run_repo.update_run_status(run_id, "RUNNING")
        bus.publish("agent.state", {"state": "THINKING", "intensity": 1, "run_id": run_id}, session_id, run_id)

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

            # Bounded time per turn (120s)
            with anyio.fail_after(120.0):
                stream_iter = provider.stream(assembly.messages, None, options, cancel_scope)
                async for chunk in stream_iter:
                    if chunk.kind == "content":
                        if chunk.text:
                            content_buffer += chunk.text
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
            bus.publish("agent.state", {"state": "IDLE", "intensity": 0, "run_id": run_id}, session_id, run_id)

        except TimeoutError:
            # Wall clock timeout
            log.error("run_wall_clock_timeout run_id=%s", run_id)
            await self._fail_run(run_id, session_id, "MODEL_TIMEOUT", "Agent turn wall clock timeout")
        except RuntimeError as e:
            # Provider errors
            log.error("run_provider_error run_id=%s error=%s", run_id, str(e))
            # error_code is captured during the loop, default to INTERNAL if missed
            code = error_code or "INTERNAL"
            if code == "CANCELLED":
                # Provider emitted CANCELLED chunk because cancel_token was triggered
                await self._cancel_run(run_id, session_id)
            else:
                await self._fail_run(run_id, session_id, code, str(e))
        except Exception as e:
            # Other uncaught errors
            log.error("run_internal_error run_id=%s error=%s", run_id, str(e), exc_info=True)
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
        bus.publish("agent.state", {"state": "IDLE", "intensity": 0, "run_id": run_id}, session_id, run_id)

    async def _cancel_run(self, run_id: str, session_id: str) -> None:
        """Helper to cleanly transition a run to CANCELLED state."""
        await self.run_repo.update_run_status(run_id, "CANCELLED", cancel_reason="User requested")
        bus.publish("agent.error", {
            "code": "CANCELLED",
            "message": "Run cancelled by user",
            "recoverable": False,
            "correlation_id": run_id
        }, session_id, run_id)
        bus.publish("agent.state", {"state": "IDLE", "intensity": 0, "run_id": run_id}, session_id, run_id)
