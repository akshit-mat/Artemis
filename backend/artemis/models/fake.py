import anyio
from typing import Any, AsyncIterator, Optional

from .base import ModelProvider, Capabilities, Chunk, GenOptions, Message, ProviderHealth, Usage
from artemis.config.schema import ModelConfig


class FakeProvider(ModelProvider):
    """A deterministic, scriptable provider for agent testing."""
    
    def __init__(self, config: Optional[ModelConfig] = None):
        self.config = config
        if config is not None:
            self.name = config.model
        else:
            self.name = "fake-model"
            
        self.capabilities = Capabilities(
            streaming=True,
            tools=True,
            structured_output=True,
            reasoning=True,
            vision=False,
            context_window=8192,
            recommended_num_ctx=8192
        )
        # Tests can inject a sequence of chunks here to script the response
        self.scripted_chunks: list[Chunk] = []
        
        # Tests can inject a custom sleep per chunk to simulate streaming delays
        self.chunk_delay_s: float = 0.0
        # Optional test hook set immediately before a configured delay starts.
        self.delay_started: anyio.Event | None = None

        # Optional: fail health check if set
        self.health_status: ProviderHealth = {"status": "ok", "details": None}
        
    async def stream(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None,
        options: GenOptions,
        cancel_token: anyio.CancelScope
    ) -> AsyncIterator[Chunk]:
        
        chunks = self.scripted_chunks or [
            # Default fallback if unscripted
            Chunk(kind="content", text="Fake response."),
            Chunk(kind="usage", usage=Usage(input_tokens=10, output_tokens=5)),
            Chunk(kind="done", finish_reason="stop"),
        ]

        # The provider owns entering the supplied scope for its stream. Calling
        # ``cancel_token.cancel()`` therefore cancels an in-flight await rather
        # than merely being observed after it completes.
        with cancel_token:
            for chunk in chunks:
                if cancel_token.cancel_called:
                    break
                if self.chunk_delay_s > 0:
                    if self.delay_started is not None:
                        self.delay_started.set()
                    try:
                        await anyio.sleep(self.chunk_delay_s)
                    except anyio.get_cancelled_exc_class():
                        if cancel_token.cancel_called:
                            break
                        raise
                if cancel_token.cancel_called:
                    break
                yield chunk

        if cancel_token.cancel_called:
            from artemis.models.base import ProviderError
            yield Chunk(kind="error", error=ProviderError(code="CANCELLED", message="Cancelled"))

    async def health(self) -> ProviderHealth:
        return self.health_status

    async def count_tokens(self, messages: list[Message]) -> int:
        # Simple deterministic heuristic for tests: 1 token per word
        return sum(len(m["content"].split()) for m in messages)
