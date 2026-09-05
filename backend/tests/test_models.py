import time

import anyio
import pytest

from pydantic import ValidationError

from artemis.models import FakeProvider, Chunk, Usage, Message
from artemis.config.paths import Paths
from artemis.config.schema import AppConfig, ConfigError, ModelConfig, load_config
from artemis.models.registry import ModelRegistry


@pytest.mark.anyio
async def test_fake_provider_streaming():
    """Test that FakeProvider yields its scripted chunks."""
    provider = FakeProvider(config=ModelConfig(id="t", provider="fake", model="fake-model", role="primary"))
    
    # Script some chunks
    provider.scripted_chunks = [
        Chunk(kind="content", text="Hello"),
        Chunk(kind="content", text=" World"),
        Chunk(kind="done", finish_reason="stop")
    ]
    
    cancel_scope = anyio.CancelScope()
    messages: list[Message] = [{"role": "user", "content": "Hi"}]
    
    streamed_chunks = []
    async for chunk in provider.stream(messages, None, {}, cancel_scope):
        streamed_chunks.append(chunk)
        
    assert len(streamed_chunks) == 3
    assert streamed_chunks[0].text == "Hello"
    assert streamed_chunks[1].text == " World"
    assert streamed_chunks[2].finish_reason == "stop"


@pytest.mark.anyio
async def test_fake_provider_cancellation():
    """Test that FakeProvider stops streaming if the cancel token is triggered between chunks."""
    provider = FakeProvider(config=ModelConfig(id="t", provider="fake", model="fake-model", role="primary"))
    provider.scripted_chunks = [
        Chunk(kind="content", text="1"),
        Chunk(kind="content", text="2"),
        Chunk(kind="content", text="3"),
        Chunk(kind="done", finish_reason="stop")
    ]
    
    cancel_scope = anyio.CancelScope()
    messages: list[Message] = [{"role": "user", "content": "Hi"}]
    
    streamed_chunks = []
    async for chunk in provider.stream(messages, None, {}, cancel_scope):
        streamed_chunks.append(chunk)
        if chunk.text == "2":
            cancel_scope.cancel()
            
    # Should yield "1", "2", and then a CANCELLED error chunk.
    assert len(streamed_chunks) == 3
    assert streamed_chunks[0].text == "1"
    assert streamed_chunks[1].text == "2"
    assert streamed_chunks[2].kind == "error"
    assert streamed_chunks[2].error.code == "CANCELLED"


@pytest.mark.anyio
async def test_fake_provider_token_count():
    provider = FakeProvider()
    messages: list[Message] = [
        {"role": "system", "content": "You are helpful."},
        {"role": "user", "content": "Hello there."}
    ]
    # "You are helpful." -> 3 words, "Hello there." -> 2 words. Total 5.
    count = await provider.count_tokens(messages)
    assert count == 5


def test_model_registry_resolution():
    """Test that ModelRegistry loads providers based on configuration."""
    config = AppConfig(
        models=[
            ModelConfig(
                id="fake-1",
                provider="fake",
                model="fake-model",
                role="primary"
            )
        ]
    )
    
    registry = ModelRegistry(config)
    provider = registry.get_provider("primary")
    
    assert provider is not None
    assert isinstance(provider, FakeProvider)
    assert provider.name == "fake-model"
    assert provider.config is config.models[0]
    
    assert registry.get_provider("fast") is None
    assert "primary" in registry.get_all_roles()


def test_model_config_validation():
    """Test proper validation for model config."""
    # Invalid num_ctx (too small)
    with pytest.raises(ValidationError):
        ModelConfig(id="test", provider="fake", model="fake", role="primary", num_ctx=100)
        
    # Invalid role
    with pytest.raises(ValidationError):
        ModelConfig(id="test", provider="fake", model="fake", role="unknown")
        
    # Provider settings have an explicit, validated namespace.
    cfg = ModelConfig(
        id="test",
        provider="fake",
        model="fake",
        role="primary",
        num_ctx=4096,
        options={"keep_alive": "30m"},
    )
    assert cfg.num_ctx == 4096
    assert cfg.options == {"keep_alive": "30m"}

    with pytest.raises(ValidationError):
        ModelConfig(id="test", provider="fake", model="fake", role="primary", num_ctc=123)

    with pytest.raises(ValidationError):
        ModelConfig(provider="fake", model="fake", role="primary")


def test_duplicate_role_registry():
    """Prevent silent duplicate-role overwrites in the registry."""
    cfg1 = ModelConfig(id="t1", provider="fake", model="m1", role="primary")
    cfg2 = ModelConfig(id="t2", provider="fake", model="m2", role="primary")
    config = AppConfig(models=[cfg1, cfg2])
    with pytest.raises(ValueError, match="Duplicate role 'primary'"):
        ModelRegistry(config)


@pytest.mark.anyio
async def test_fake_provider_cancel_during_delay():
    """Test that cancels while the provider is actively blocked in a delay, not merely between chunks."""
    provider = FakeProvider()
    provider.scripted_chunks = [
        Chunk(kind="content", text="1"),
        Chunk(kind="content", text="2"),
        Chunk(kind="done", finish_reason="stop")
    ]
    provider.chunk_delay_s = 5.0

    messages = [{"role": "user", "content": "Hi"}]
    streamed_chunks = []
    delay_started = anyio.Event()
    stream_finished = anyio.Event()
    provider.delay_started = delay_started
    
    async def run_stream(c_scope):
        async for chunk in provider.stream(messages, None, {}, c_scope):
            streamed_chunks.append(chunk)
        stream_finished.set()

    async with anyio.create_task_group() as tg:
        cancel_scope = anyio.CancelScope()
        tg.start_soon(run_stream, cancel_scope)
        with anyio.fail_after(0.2):
            await delay_started.wait()
        started_at = time.perf_counter()
        cancel_scope.cancel()
        with anyio.fail_after(0.2):
            await stream_finished.wait()

    # Since it cancels during the sleep for the first chunk, only the CANCELLED error chunk is emitted
    assert len(streamed_chunks) == 1
    assert streamed_chunks[0].kind == "error"
    assert streamed_chunks[0].error.code == "CANCELLED"
    assert time.perf_counter() - started_at < 0.2


@pytest.mark.anyio
async def test_fake_provider_contract_strengthened():
    """Strengthen provider contract tests for Capabilities, GenOptions, health behavior, defaults."""
    cfg = ModelConfig(id="fake-test", provider="fake", model="my-fake-model", role="primary")
    provider = FakeProvider(config=cfg)
    
    # 1. Check Capabilities and constructor
    assert provider.name == "my-fake-model"
    assert provider.capabilities == {
        "streaming": True,
        "tools": True,
        "structured_output": True,
        "reasoning": True,
        "vision": False,
        "context_window": 8192,
        "recommended_num_ctx": 8192,
    }
    
    # 2. Check defaults
    provider.scripted_chunks = []
    cancel_scope = anyio.CancelScope()
    messages: list[Message] = [{"role": "user", "content": "Hi"}]
    # Using GenOptions
    options = {"temperature": 0.7, "num_ctx": 4096, "max_tokens": 100, "stop": ["END"], "seed": 7}
    chunks = [c async for c in provider.stream(messages, None, options, cancel_scope)]
    assert len(chunks) == 3
    assert chunks[0].kind == "content"
    assert chunks[1].kind == "usage"
    
    # 3. Check health behavior
    health = await provider.health()
    assert health["status"] == "ok"
    
    provider.health_status = {"status": "error", "details": "simulated"}
    health2 = await provider.health()
    assert health2["status"] == "error"


@pytest.mark.anyio
async def test_fake_provider_preserves_reasoning_chunks():
    provider = FakeProvider()
    provider.scripted_chunks = [
        Chunk(kind="reasoning", text="considering options"),
        Chunk(kind="content", text="Final answer"),
        Chunk(kind="done", finish_reason="stop"),
    ]

    chunks = [
        chunk
        async for chunk in provider.stream(
            [{"role": "user", "content": "Hi"}], None, {}, anyio.CancelScope()
        )
    ]

    assert [chunk.kind for chunk in chunks] == ["reasoning", "content", "done"]
    assert chunks[0].text == "considering options"
    assert chunks[1].text == "Final answer"


def test_registry_rejects_unknown_provider():
    config = AppConfig(models=[ModelConfig(id="unknown", provider="missing", model="m", role="primary")])
    with pytest.raises(ValueError, match="Unknown provider 'missing'"):
        ModelRegistry(config)


def test_model_config_loads_documented_toml_shape(tmp_path):
    config, _ = load_config(
        Paths.resolve(tmp_path),
        toml_text='''
[[models]]
id = "qwen3-8b"
provider = "ollama"
model = "qwen3:8b"
role = "primary"
num_ctx = 8192
capabilities = { tools = true, reasoning = true, vision = false }
options = { keep_alive = "5m" }
''',
    )

    assert len(config.models) == 1
    model = config.models[0]
    assert (model.id, model.provider, model.model, model.role) == ("qwen3-8b", "ollama", "qwen3:8b", "primary")
    assert model.capabilities.tools is True
    assert model.capabilities.streaming is True
    assert model.options == {"keep_alive": "5m"}


def test_model_config_loader_rejects_unknown_model_field(tmp_path):
    with pytest.raises(ConfigError, match="num_ctc"):
        load_config(
            Paths.resolve(tmp_path),
            toml_text='''
[[models]]
id = "qwen3-8b"
provider = "ollama"
model = "qwen3:8b"
role = "primary"
num_ctc = 123
''',
        )
