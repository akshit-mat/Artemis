import json
import logging
import socket
from typing import Any, AsyncIterator
from urllib.parse import urlparse

import anyio
import httpx

from artemis.config.schema import ModelConfig
from artemis.models.base import (
    Capabilities,
    Chunk,
    GenOptions,
    Message,
    ModelProvider,
    ProviderError,
    ProviderHealth,
    Usage,
)

logger = logging.getLogger(__name__)


def is_loopback(host: str) -> bool:
    # Strict literal string match to prevent DNS rebinding TOCTOU SSRF
    # and URL parser differential attacks.
    return host in ("localhost", "127.0.0.1", "::1", "[::1]")


class StreamSplitter:
    """Parses streamed text and separates <think> blocks into reasoning chunks."""
    def __init__(self):
        self.in_reasoning = False
        self.buffer = ""
        self.open_tag = "<think>"
        self.close_tag = "</think>"

    def process(self, chunk: str) -> list[tuple[str, str]]:
        self.buffer += chunk
        results = []
        
        while self.buffer:
            if not self.in_reasoning:
                idx = self.buffer.find(self.open_tag)
                if idx != -1:
                    if idx > 0:
                        results.append(("content", self.buffer[:idx]))
                    self.in_reasoning = True
                    self.buffer = self.buffer[idx + len(self.open_tag):]
                else:
                    partial_match = False
                    for i in range(1, len(self.open_tag)):
                        suffix = self.buffer[-i:]
                        if self.open_tag.startswith(suffix):
                            if len(self.buffer) > i:
                                results.append(("content", self.buffer[:-i]))
                            self.buffer = suffix
                            partial_match = True
                            break
                    if not partial_match:
                        results.append(("content", self.buffer))
                        self.buffer = ""
                    break
            else:
                idx = self.buffer.find(self.close_tag)
                if idx != -1:
                    if idx > 0:
                        results.append(("reasoning", self.buffer[:idx]))
                    self.in_reasoning = False
                    self.buffer = self.buffer[idx + len(self.close_tag):]
                else:
                    partial_match = False
                    for i in range(1, len(self.close_tag)):
                        suffix = self.buffer[-i:]
                        if self.close_tag.startswith(suffix):
                            if len(self.buffer) > i:
                                results.append(("reasoning", self.buffer[:-i]))
                            self.buffer = suffix
                            partial_match = True
                            break
                    if not partial_match:
                        results.append(("reasoning", self.buffer))
                        self.buffer = ""
                    break
                    
        return results

    def flush(self) -> list[tuple[str, str]]:
        if not self.buffer:
            return []
        kind = "reasoning" if self.in_reasoning else "content"
        res = [(kind, self.buffer)]
        self.buffer = ""
        return res


class OllamaProvider(ModelProvider):
    """Ollama API integration."""
    
    def __init__(self, config: ModelConfig):
        self.config = config
        self.name = config.model
        self.base_url = config.options.get("base_url", "http://127.0.0.1:11434")
        
        parsed = httpx.URL(self.base_url)
        if not parsed.host or not is_loopback(parsed.host):
            raise ValueError(f"Ollama base_url must be loopback. Got {self.base_url}")
            
        self.keep_alive = config.options.get("keep_alive", "5m")
        
        self.capabilities = Capabilities(
            streaming=True,
            tools=config.capabilities.tools,
            structured_output=config.capabilities.structured_output,
            reasoning=config.capabilities.reasoning,
            vision=config.capabilities.vision,
            context_window=config.capabilities.context_window,
            recommended_num_ctx=config.num_ctx
        )
        
    async def stream(
        self,
        messages: list[Message],
        tools: list[dict[str, Any]] | None,
        options: GenOptions,
        cancel_token: anyio.CancelScope
    ) -> AsyncIterator[Chunk]:
        
        url = f"{self.base_url}/api/chat"
        
        payload: dict[str, Any] = {
            "model": self.name,
            "messages": messages,
            "stream": True,
            "keep_alive": self.keep_alive,
            "options": {
                "num_ctx": options.get("num_ctx", self.config.num_ctx),
            }
        }
        
        if "temperature" in options:
            payload["options"]["temperature"] = options["temperature"]
        if "max_tokens" in options:
            payload["options"]["num_predict"] = options["max_tokens"]
        if "stop" in options:
            payload["options"]["stop"] = options["stop"]
        if "seed" in options:
            payload["options"]["seed"] = options["seed"]
            
        if tools:
            payload["tools"] = tools

        splitter = StreamSplitter()
        
        read_timeout = float(self.config.options.get("read_timeout", 30.0))
        first_token_timeout = float(self.config.options.get("first_token_timeout", 20.0))
        
        timeout = httpx.Timeout(read_timeout, connect=2.0)
        
        with cancel_token:
            try:
                async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
                    async with client.stream("POST", url, json=payload) as response:
                        if response.status_code == 404:
                            yield Chunk(kind="error", error=ProviderError(code="MODEL_NOT_FOUND", message="Model not found"))
                            return
                        elif response.status_code != 200:
                            yield Chunk(kind="error", error=ProviderError(code="INTERNAL", message=f"HTTP {response.status_code}"))
                            return

                        iterator = response.aiter_lines().__aiter__()
                        first_line = True
                        
                        while True:
                            try:
                                if first_line:
                                    with anyio.fail_after(first_token_timeout):
                                        line = await iterator.__anext__()
                                    first_line = False
                                else:
                                    line = await iterator.__anext__()
                            except StopAsyncIteration:
                                break
                            except TimeoutError:
                                yield Chunk(kind="error", error=ProviderError(code="MODEL_TIMEOUT", message="First token timeout"))
                                return
                            except httpx.ReadTimeout:
                                yield Chunk(kind="error", error=ProviderError(code="MODEL_TIMEOUT", message="Read timeout"))
                                return
                            except httpx.ReadError as e:
                                if cancel_token.cancel_called:
                                    # Fall through to the CANCELLED check at the bottom
                                    break
                                yield Chunk(kind="error", error=ProviderError(code="INTERNAL", message=str(e)))
                                return
                                
                            if not line:
                                continue
                                
                            try:
                                data = json.loads(line)
                            except json.JSONDecodeError:
                                continue
                                
                            if "error" in data:
                                yield Chunk(kind="error", error=ProviderError(code="INTERNAL", message=data['error']))
                                return
                                
                            msg = data.get("message", {})
                            content = msg.get("content", "")
                            
                            # Parse content through the splitter to separate <think> tags.
                            # ALWAYS intercept <think> tags. If reasoning is disabled, drop them.
                            if content:
                                parsed_chunks = splitter.process(content)
                                for kind, text in parsed_chunks:
                                    if kind == "reasoning":
                                        if self.capabilities["reasoning"]:
                                            yield Chunk(kind="reasoning", text=text)
                                    else:
                                        yield Chunk(kind="content", text=text)
                                
                            # Handle tool calls
                            if "tool_calls" in msg and msg["tool_calls"]:
                                for tc in msg["tool_calls"]:
                                    from artemis.models.base import ToolCall
                                    fn = tc.get("function", {})
                                    yield Chunk(
                                        kind="tool_call",
                                        tool_call=ToolCall(
                                            id=tc.get("id", ""),
                                            name=fn.get("name", ""),
                                            arguments=fn.get("arguments", {})
                                        )
                                    )
                                    
                            if data.get("done"):
                                # Flush any remaining buffered text
                                for kind, text in splitter.flush():
                                    if kind == "reasoning":
                                        if self.capabilities["reasoning"]:
                                            yield Chunk(kind="reasoning", text=text)
                                    else:
                                        yield Chunk(kind="content", text=text)
                                        
                                usage = Usage(
                                    input_tokens=data.get("prompt_eval_count", 0),
                                    output_tokens=data.get("eval_count", 0)
                                )
                                yield Chunk(kind="usage", usage=usage)
                                yield Chunk(kind="done", finish_reason=data.get("done_reason", "stop"))
                                break

            except httpx.ConnectError:
                yield Chunk(kind="error", error=ProviderError(code="MODEL_UNAVAILABLE", message="Connection failed"))
                return
            except httpx.ReadTimeout:
                yield Chunk(kind="error", error=ProviderError(code="MODEL_TIMEOUT", message="Read timeout"))
                return
            except Exception as e:
                # Need to catch Exception inside cancel scope just in case, but let cancel fall through
                if cancel_token.cancel_called:
                    pass
                else:
                    logger.error(f"Unexpected error in Ollama stream: {e}")
                    yield Chunk(kind="error", error=ProviderError(code="INTERNAL", message=str(e)))
                    return

        if cancel_token.cancel_called:
            yield Chunk(kind="error", error=ProviderError(code="CANCELLED", message="Request cancelled"))
                
    async def health(self) -> ProviderHealth:
        url = f"{self.base_url}/api/tags"
        try:
            # Short explicit timeout for health probe
            async with httpx.AsyncClient(timeout=httpx.Timeout(2.0), follow_redirects=False) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    models = [m.get("name") for m in data.get("models", [])]
                    # Check if our specific model is pulled
                    if self.name in models or f"{self.name}:latest" in models:
                        return {"status": "ok", "details": None}
                    else:
                        return {"status": "error", "details": "model_not_pulled"}
                else:
                    return {"status": "error", "details": f"HTTP {resp.status_code}"}
        except httpx.RequestError:
            return {"status": "offline", "details": "connection_failed"}

    async def count_tokens(self, messages: list[Message]) -> int:
        total_chars = sum(len(m["content"]) for m in messages)
        return int(total_chars / 3.6)
