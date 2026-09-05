"""Model providers and abstractions."""

from .base import ModelProvider, Capabilities, Chunk, GenOptions, Message, ProviderHealth, Usage, ToolCall
from .fake import FakeProvider
from .ollama import OllamaProvider
from .registry import ModelRegistry

# Register available providers
ModelRegistry.register_provider("fake", FakeProvider)
ModelRegistry.register_provider("ollama", OllamaProvider)

__all__ = [
    "ModelProvider",
    "Capabilities",
    "Chunk",
    "GenOptions",
    "Message",
    "ProviderHealth",
    "Usage",
    "ToolCall",
    "FakeProvider",
    "OllamaProvider",
    "ModelRegistry",
]
