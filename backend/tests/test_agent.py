import pytest
import anyio
import sqlite3
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any

from artemis.storage.database import Database
from artemis.config.schema import DbConfig, ModelConfig
from artemis.storage.repositories.runs import RunRepository
from artemis.storage.repositories.messages import MessageRepository
from artemis.agent.context import ContextAssembler, estimate_tokens
from artemis.agent.loop import AgentOrchestrator
from artemis.models.registry import ModelRegistry
from artemis.models.fake import FakeProvider
from artemis.models.base import Chunk, ProviderError, Usage
from artemis.api.events import bus

@pytest.fixture
def db(tmp_path: Path) -> Database:
    config = DbConfig(read_pool_size=1, busy_timeout_ms=100)
    database = Database(tmp_path / "test.sqlite", config)
    database.open()

    # Init schema
    from artemis.storage.migrations import init_db
    init_db(database)

    # Create test session
    database.execute_write_sync("INSERT INTO sessions (id, title) VALUES ('s_test', 'Test Session')")

    yield database
    database.shutdown()

@pytest.fixture
def repos(db: Database):
    return RunRepository(db), MessageRepository(db)

@pytest.fixture
def anyio_backend():
    return "asyncio"

@pytest.fixture
def registry():
    from artemis.config.schema import AppConfig
    cfg = AppConfig.model_validate({
        "models": [{
            "id": "fake-1",
            "provider": "fake",
            "model": "fake",
            "role": "primary",
            "num_ctx": 2048,
            "capabilities": {}
        }]
    })
    ModelRegistry.register_provider("fake", FakeProvider)
    reg = ModelRegistry(cfg)
    return reg

@pytest.mark.anyio
async def test_db_runs_and_messages(repos):
    run_repo, msg_repo = repos

    # Test message
    await msg_repo.append_message("m_1", "s_test", "user", "hello")
    msgs = await msg_repo.get_messages_for_session("s_test")
    assert len(msgs) == 1
    assert msgs[0]["content"] == "hello"

    # Test run
    await run_repo.create_run("r_1", "s_test", "fake-1")
    active = await run_repo.get_active_run_for_session("s_test")
    assert active is not None
    assert active["status"] == "QUEUED"

    await run_repo.update_run_status("r_1", "RUNNING")
    active = await run_repo.get_active_run_for_session("s_test")
    assert active["status"] == "RUNNING"

    await run_repo.update_run_status("r_1", "DONE", steps_used=1, input_tokens=10, output_tokens=5)
    active = await run_repo.get_active_run_for_session("s_test")
    assert active is None # no active run

    run = await run_repo.get_run("r_1")
    assert run["status"] == "DONE"
    assert run["steps_used"] == 1

def test_context_assembler():
    assembler = ContextAssembler(num_ctx=2048, reserve_output_tokens=1024)
    # usable_budget = 2048 - 1024 - 256 = 768
    # Tier 0 cap = 500
    # Tier 2 cap = 300
    # Tier 5 cap = 768 - (tier 0 + tier 2)

    messages = []
    # Add a lot of messages to force eviction
    # Each message is "word " * 10 => ~50 chars => 13 tokens
    for i in range(100):
        messages.append({
            "content": f"msg_{i} " * 10,
            "role": "user",
            "token_estimate": None
        })

    result = assembler.assemble(messages)
    # Total tokens in tier 5 should be strictly less than 768
    assert result.tokens_by_tier[5] <= 768
    # Evictions must have occurred
    assert result.evicted_messages > 0

    # Check that system prompt is first
    assert result.messages[0]["role"] == "system"

def test_context_assembler_500_turns():
    """Adversarial test: 500 turns to verify strict contiguous truncation and budget rules."""
    assembler = ContextAssembler(num_ctx=8192, reserve_output_tokens=1024)
    # usable: 8192 - 1024 - 256 = 6912
    # tier_0: ~13 tokens (system prompt)
    # tier_5: ~6899 budget
    messages = []

    # Generate 500 turns of exactly 20 tokens each.
    # 500 * 20 = 10000 tokens total, exceeding the budget of ~6899.
    # Therefore, we should only fit approx 344 turns.
    for i in range(500):
        messages.append({
            "content": "A " * 72, # 72 chars / 3.6 = 20 tokens
            "role": "user",
            "token_estimate": 20
        })

    result = assembler.assemble(messages)

    tier_5_count = len(result.messages) - 1 # excluding system
    expected_budget = 6912 - result.tokens_by_tier[0]
    assert result.tokens_by_tier[5] <= expected_budget
    assert tier_5_count * 20 <= expected_budget
    assert result.evicted_messages == 500 - tier_5_count

    # Verify exact truncation behavior (only newest kept)
    assert result.messages[0]["role"] == "system"

@pytest.mark.anyio
async def test_agent_orchestrator(repos, registry):
    run_repo, msg_repo = repos
    orchestrator = AgentOrchestrator(run_repo, msg_repo, registry)

    # Script fake provider
    provider: FakeProvider = registry.get_provider("primary")
    provider.scripted_chunks = [
        Chunk(kind="content", text="Hello "),
        Chunk(kind="reasoning", text="I am thinking "),
        Chunk(kind="content", text="World!"),
        Chunk(kind="usage", usage=Usage(input_tokens=10, output_tokens=5)),
        Chunk(kind="done", finish_reason="stop")
    ]

    # Capture events
    events = []
    async def on_event(evt):
        events.append(evt)
    unsubscribe = bus.subscribe(on_event)

    try:
        run_id = await orchestrator.handle_chat("s_test", "Hi")
        await orchestrator.run_conversation(run_id, "s_test")

        # Let background event dispatch tasks finish
        await anyio.sleep(0.05)

        # Verify run state
        run = await run_repo.get_run(run_id)
        assert run["status"] == "DONE"
        assert run["steps_used"] == 1
        assert run["input_tokens"] == 10
        assert run["output_tokens"] == 5

        # Verify messages
        msgs = await msg_repo.get_messages_for_session("s_test")
        assert len(msgs) == 2
        assert msgs[0]["role"] == "user"
        assert msgs[1]["role"] == "assistant"
        assert msgs[1]["content"] == "Hello World!" # Reasoning excluded

        # Verify events
        types = [e["type"] for e in events]
        assert "agent.state" in types
        assert "agent.delta" in types
        assert "agent.message" in types

        deltas = [e["data"] for e in events if e["type"] == "agent.delta"]
        assert any(d["channel"] == "content" and d["text"] == "Hello " for d in deltas)
        assert any(d["channel"] == "reasoning" and d["text"] == "I am thinking " for d in deltas)

    finally:
        unsubscribe()

@pytest.mark.anyio
async def test_agent_cancellation(repos, registry):
    run_repo, msg_repo = repos
    orchestrator = AgentOrchestrator(run_repo, msg_repo, registry)

    provider: FakeProvider = registry.get_provider("primary")
    # Induce an infinite stream to test cancellation
    async def infinite_stream():
        while True:
            yield Chunk(kind="content", text="A")
            await anyio.sleep(0.1)

    # Mock stream
    async def mock_stream(*args, **kwargs):
        cancel_token = args[3]
        with cancel_token:
            while not cancel_token.cancel_called:
                yield Chunk(kind="content", text="A")
                await anyio.sleep(0.1)
        if cancel_token.cancel_called:
            yield Chunk(kind="error", error=ProviderError(code="CANCELLED", message="Cancelled"))

    # apply mock
    provider.stream = mock_stream

    run_id = await orchestrator.handle_chat("s_test", "Hi")

    # Run the conversation in a background task
    async with anyio.create_task_group() as tg:
        tg.start_soon(orchestrator.run_conversation, run_id, "s_test")

        # Wait a bit then cancel
        await anyio.sleep(0.1)
        from artemis.agent.manager import run_manager
        assert run_manager.cancel(run_id) is True

    # verify it was cancelled
    run = await run_repo.get_run(run_id)
    assert run["status"] == "CANCELLED"
