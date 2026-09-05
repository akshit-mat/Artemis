import anyio
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, AsyncIterator, Literal, Optional, TYPE_CHECKING, TypedDict

if TYPE_CHECKING:
    from artemis.config.schema import ModelConfig


class Capabilities(TypedDict):
    streaming: bool
    tools: bool            # native tool/function calling
    structured_output: bool # constrained JSON
    reasoning: bool        # emits a separate thinking channel
    vision: bool
    context_window: int
    recommended_num_ctx: int


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class Usage:
    input_tokens: int
    output_tokens: int


@dataclass
class ProviderError:
    code: Literal["MODEL_UNAVAILABLE", "MODEL_NOT_FOUND", "MODEL_TIMEOUT", "INTERNAL", "CANCELLED"]
    message: str


@dataclass
class Chunk:
    kind: Literal["content", "reasoning", "tool_call", "usage", "done", "error"]
    text: Optional[str] = None
    tool_call: Optional[ToolCall] = None
    usage: Optional[Usage] = None
    finish_reason: Optional[str] = None
    error: Optional[ProviderError] = None


class GenOptions(TypedDict, total=False):
    temperature: float
    num_ctx: int
    max_tokens: int
    stop: list[str]
    seed: int


class Message(TypedDict):
    role: Literal["user", "assistant", "system", "tool"]
    content: str


class ProviderHealth(TypedDict):
    status: Literal["ok", "offline", "error"]
    details: Optional[str]


class ModelProvider(ABC):
    name: str
    capabilities: Capabilities
    
    @abstractmethod
    def __init__(self, config: "ModelConfig") -> None: ...

    @abstractmethod
    async def stream(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None,
        options: GenOptions,
        cancel_token: anyio.CancelScope,
    ) -> AsyncIterator[Chunk]:
        """Yield normalized chunks while owning the supplied cancellation scope.

        Callers create and cancel ``cancel_token``; providers enter it around
        their I/O so cancellation interrupts an in-flight await or stream read.
        """
        ...

    @abstractmethod
    async def health(self) -> ProviderHealth: ...

    @abstractmethod
    async def count_tokens(self, messages: list[Message]) -> int: ...
