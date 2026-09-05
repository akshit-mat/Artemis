import json as json_mod
import time
import pytest
import anyio
import httpx
from typing import AsyncIterator

from artemis.models.ollama import StreamSplitter, OllamaProvider, is_loopback
from artemis.config.schema import ModelConfig
from artemis.models.base import Chunk, Message, ProviderError

def test_is_loopback():
    assert is_loopback("127.0.0.1") is True
    assert is_loopback("localhost") is True
    assert is_loopback("::1") is True
    assert is_loopback("0.0.0.0") is False
    assert is_loopback("192.168.1.1") is False
    assert is_loopback("8.8.8.8") is False
    assert is_loopback("example.com") is False


def test_stream_splitter_edge_cases():
    splitter = StreamSplitter()
    
    # 1. Normal reasoning
    res = splitter.process("Text <think>thought</think> answer")
    assert res == [
        ("content", "Text "),
        ("reasoning", "thought"),
        ("content", " answer")
    ]
    
    # 2. Opening tag split
    splitter = StreamSplitter()
    res = splitter.process("Let me <thi")
    assert res == [("content", "Let me ")]
    res = splitter.process("nk>think</think>")
    assert res == [("reasoning", "think")]
    
    # 3. Closing tag split
    splitter = StreamSplitter()
    res = splitter.process("<think>reason")
    assert res == [("reasoning", "reason")]
    res = splitter.process("ing</thi")
    assert res == [("reasoning", "ing")]
    res = splitter.process("nk> done")
    assert res == [("content", " done")]
    
    # 4. content -> reasoning -> content
    splitter = StreamSplitter()
    res = splitter.process("A <think>B</think> C")
    assert res == [("content", "A "), ("reasoning", "B"), ("content", " C")]
    
    # 5. Multiple reasoning sections
    splitter = StreamSplitter()
    res = splitter.process("<think>1</think> <think>2</think>")
    assert res == [("reasoning", "1"), ("content", " "), ("reasoning", "2")]
    
    # 6. Incomplete <think> tag at stream termination
    splitter = StreamSplitter()
    res = splitter.process("Start <thi")
    assert res == [("content", "Start ")]
    res = splitter.flush()
    assert res == [("content", "<thi")] # correctly flushes as content
    
    # 7. Incomplete close tag at stream termination
    splitter = StreamSplitter()
    splitter.process("<think>thought</th")
    res = splitter.flush()
    assert res == [("reasoning", "</th")]
    
    # 8. Malformed fragments - text with partial prefixes that never complete
    splitter = StreamSplitter()
    res = splitter.process("Math: 2 < t")
    assert res == [("content", "Math: 2 < t")]
    
    # Text with an actual prefix that gets buffered
    res = splitter.process("Math: 2 <thi")
    assert res == [("content", "Math: 2 ")]
    res = splitter.flush()
    assert res == [("content", "<thi")]


class MockResponse:
    def __init__(self, status_code, chunks=None):
        self.status_code = status_code
        self.chunks = chunks or []
        self.closed = False

    async def aiter_lines(self) -> AsyncIterator[str]:
        for c in self.chunks:
            yield c

class MockAsyncClient:
    def __init__(self, mock_post_stream=None, mock_get=None):
        self.mock_post_stream = mock_post_stream
        self.mock_get = mock_get

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass

    def stream(self, method, url, **kwargs):
        class StreamContext:
            def __init__(self, response):
                self.response = response
            async def __aenter__(self):
                return self.response
            async def __aexit__(self, *args):
                self.response.closed = True
        return StreamContext(self.mock_post_stream(method, url, **kwargs))
        
    async def get(self, url, **kwargs):
        return await self.mock_get(url, **kwargs)


@pytest.mark.anyio
async def test_ollama_provider_stream_success(monkeypatch):
    """Test streaming parsing with a mocked HTTP client."""
    config = ModelConfig(
        id="qwen",
        provider="ollama",
        model="qwen3:8b",
        role="primary",
        capabilities={"reasoning": True}
    )
    provider = OllamaProvider(config)
    
    def mock_post_stream(method, url, json=None, **kwargs):
        lines = [
            json_mod.dumps({"message": {"content": "Hello <thi"}}),
            json_mod.dumps({"message": {"content": "nk>thought</think> world"}}),
            json_mod.dumps({"done": True, "prompt_eval_count": 5, "eval_count": 10, "done_reason": "stop"}),
        ]
        return MockResponse(200, lines)

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: MockAsyncClient(mock_post_stream=mock_post_stream))

    cancel_scope = anyio.CancelScope()
    messages: list[Message] = [{"role": "user", "content": "Hi"}]
    
    chunks = [c async for c in provider.stream(messages, None, {}, cancel_scope)]
    
    kinds = [c.kind for c in chunks]
    assert kinds == ["content", "reasoning", "content", "usage", "done"]
    
    assert chunks[0].text == "Hello "
    assert chunks[1].text == "thought"
    assert chunks[2].text == " world"
    assert chunks[3].usage.input_tokens == 5
    assert chunks[4].finish_reason == "stop"


@pytest.mark.anyio
async def test_ollama_provider_message_thinking_field(monkeypatch):
    """Ollama 0.33+ separates thinking into message.thinking (not inline <think> tags).

    Thinking tokens from message.thinking must be emitted as reasoning chunks
    directly.  message.content carries only the real response (no tags).
    This test verifies that the /think artifact is eliminated: message.content
    is passed through the StreamSplitter as-is without contamination from the
    thinking field.
    """
    config = ModelConfig(
        id="qwen",
        provider="ollama",
        model="qwen3:8b",
        role="primary",
        capabilities={"reasoning": True},
    )
    provider = OllamaProvider(config)

    def mock_post_stream(method, url, json=None, **kwargs):
        # Simulate Ollama 0.33 format: thinking in message.thinking, response in message.content
        lines = [
            json_mod.dumps({"message": {"content": "",   "thinking": "Okay,"}}),
            json_mod.dumps({"message": {"content": "",   "thinking": " let me think."}}),
            json_mod.dumps({"message": {"content": "ARTEMIS ONLINE", "thinking": ""}}),
            json_mod.dumps({"done": True, "prompt_eval_count": 8, "eval_count": 3, "done_reason": "stop"}),
        ]
        return MockResponse(200, lines)

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: MockAsyncClient(mock_post_stream=mock_post_stream))

    cancel_scope = anyio.CancelScope()
    chunks = [c async for c in provider.stream([], None, {}, cancel_scope)]

    kinds = [c.kind for c in chunks]
    # Two reasoning chunks (from thinking field), one content, usage, done
    assert kinds == ["reasoning", "reasoning", "content", "usage", "done"], kinds

    assert chunks[0].text == "Okay,"
    assert chunks[1].text == " let me think."
    assert chunks[2].text == "ARTEMIS ONLINE"
    # No <think> contamination in content
    assert "<think>" not in chunks[2].text
    assert "/think" not in chunks[2].text


@pytest.mark.anyio
async def test_ollama_provider_message_thinking_disabled(monkeypatch):
    """Thinking from message.thinking is silently dropped when reasoning=False."""
    config = ModelConfig(
        id="qwen", provider="ollama", model="qwen3:8b", role="primary",
        capabilities={"reasoning": False},
    )
    provider = OllamaProvider(config)

    def mock_post_stream(method, url, json=None, **kwargs):
        lines = [
            json_mod.dumps({"message": {"content": "",  "thinking": "secret thought"}}),
            json_mod.dumps({"message": {"content": "Hello", "thinking": ""}}),
            json_mod.dumps({"done": True, "done_reason": "stop"}),
        ]
        return MockResponse(200, lines)

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: MockAsyncClient(mock_post_stream=mock_post_stream))

    cancel_scope = anyio.CancelScope()
    chunks = [c async for c in provider.stream([], None, {}, cancel_scope)]

    kinds = [c.kind for c in chunks]
    # thinking dropped, only content + usage + done
    assert kinds == ["content", "usage", "done"], kinds
    assert chunks[0].text == "Hello"



@pytest.mark.anyio
async def test_ollama_provider_reasoning_disabled(monkeypatch):
    """Test that <think> tags are dropped if reasoning capability is False."""
    config = ModelConfig(
        id="qwen", provider="ollama", model="qwen3:8b", role="primary",
        capabilities={"reasoning": False}
    )
    provider = OllamaProvider(config)
    
    def mock_post_stream(method, url, json=None, **kwargs):
        lines = [
            json_mod.dumps({"message": {"content": "A <think>thought</think> B"}}),
            json_mod.dumps({"done": True, "done_reason": "stop"}),
        ]
        return MockResponse(200, lines)

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: MockAsyncClient(mock_post_stream=mock_post_stream))

    cancel_scope = anyio.CancelScope()
    chunks = [c async for c in provider.stream([], None, {}, cancel_scope)]
    
    kinds = [c.kind for c in chunks]
    # reasoning is dropped, so we only get content and done
    assert kinds == ["content", "content", "usage", "done"]
    assert chunks[0].text == "A "
    assert chunks[1].text == " B"


@pytest.mark.anyio
async def test_ollama_provider_capabilities():
    """Test that capabilities strictly mirror configuration."""
    config = ModelConfig(
        id="qwen", provider="ollama", model="qwen3:8b", role="primary",
        capabilities={"tools": False, "vision": True, "reasoning": False, "structured_output": False, "context_window": 8192}
    )
    provider = OllamaProvider(config)
    assert provider.capabilities["streaming"] is True
    assert provider.capabilities["tools"] is False
    assert provider.capabilities["vision"] is True
    assert provider.capabilities["reasoning"] is False
    assert provider.capabilities["structured_output"] is False
    assert provider.capabilities["context_window"] == 8192


def test_ollama_provider_loopback_validation():
    """Test that SSRF to non-loopback addresses is strictly prevented."""
    valid_configs = [
        "http://127.0.0.1:11434",
        "http://localhost:11434",
        "http://[::1]:11434"
    ]
    for url in valid_configs:
        config = ModelConfig(id="t", provider="ollama", model="m", role="primary", options={"base_url": url})
        OllamaProvider(config) # Should not raise
        
    invalid_configs = [
        "http://0.0.0.0:11434",
        "http://192.168.1.1:11434",
        "https://example.com",
        "http://8.8.8.8"
    ]
    for url in invalid_configs:
        config = ModelConfig(id="t", provider="ollama", model="m", role="primary", options={"base_url": url})
        with pytest.raises(ValueError, match="must be loopback"):
            OllamaProvider(config)


@pytest.mark.anyio
async def test_ollama_provider_real_cancellation(monkeypatch):
    """Prove that cancellation interrupts a blocked streaming read and returns in <200ms, and properly invokes stream closure."""
    
    class RealisticMockResponse:
        def __init__(self, status_code):
            self.status_code = status_code
            self.aclose_called = False
            self.read_event = anyio.Event()

        async def aiter_lines(self):
            yield json_mod.dumps({"message": {"content": "first chunk"}})
            # Simulate blocking indefinitely waiting for network I/O
            await self.read_event.wait()

        async def aclose(self):
            self.aclose_called = True

    class MockStreamContext:
        def __init__(self, response):
            self.response = response
        
        async def __aenter__(self):
            return self.response
            
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            await self.response.aclose()

    response = RealisticMockResponse(200)
    
    def mock_post_stream(method, url, **kwargs):
        return MockStreamContext(response)

    class CustomMockAsyncClient:
        def __init__(self, **kwargs):
            pass
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        def stream(self, method, url, **kwargs):
            return mock_post_stream(method, url, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", CustomMockAsyncClient)
    
    config = ModelConfig(id="test", provider="ollama", model="m", role="primary")
    provider = OllamaProvider(config)
    
    cancel_scope = anyio.CancelScope()
    streamed_chunks = []
    
    async def run_stream():
        async for chunk in provider.stream([], None, {}, cancel_scope):
            streamed_chunks.append(chunk)
            if chunk.kind == "content" and chunk.text == "first chunk":
                cancel_scope.cancel()

    start_time = time.perf_counter()
    await run_stream()
    duration = time.perf_counter() - start_time
    
    assert duration < 0.2, f"Latency {duration}s exceeded 200ms limit"
    assert response.aclose_called is True, "HTTP stream aclose() was not executed"
    
    assert len(streamed_chunks) == 2
    assert streamed_chunks[0].text == "first chunk"
    assert streamed_chunks[1].kind == "error"
    assert streamed_chunks[1].error.code == "CANCELLED"


@pytest.mark.anyio
async def test_ollama_provider_timeouts(monkeypatch):
    """Test first-token timeout and read timeout."""
    
    # 1. First token timeout
    class FirstTokenTimeoutResponse(MockResponse):
        async def aiter_lines(self):
            await anyio.sleep(100.0)
            yield ""
            
    def mock_post_stream1(method, url, **kwargs):
        return FirstTokenTimeoutResponse(200)

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: MockAsyncClient(mock_post_stream=mock_post_stream1))
    
    config = ModelConfig(id="test", provider="ollama", model="m", role="primary", options={"first_token_timeout": 0.1})
    provider = OllamaProvider(config)
    
    cancel_scope = anyio.CancelScope()
    chunks = [c async for c in provider.stream([], None, {}, cancel_scope)]
    assert len(chunks) == 1
    assert chunks[0].kind == "error"
    assert chunks[0].error.code == "MODEL_TIMEOUT"
    assert "First token" in chunks[0].error.message


@pytest.mark.anyio
async def test_ollama_provider_health(monkeypatch):
    config = ModelConfig(id="qwen", provider="ollama", model="qwen3:8b", role="primary")
    provider = OllamaProvider(config)
    
    async def mock_get(url, **kwargs):
        class MockHealthResp:
            status_code = 200
            def json(self):
                return {"models": [{"name": "qwen3:8b"}]}
        return MockHealthResp()

    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: MockAsyncClient(mock_get=mock_get))
    
    health = await provider.health()
    assert health["status"] == "ok"
