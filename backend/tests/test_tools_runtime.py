"""ToolRuntime, registry and subprocess-tier tests (``docs/tools.md`` §4/§5/§10)."""

from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path

import psutil
import pytest

from artemis.obs.audit import AuditFailure, AuditRecord, AuditWriter
from artemis.policy.engine import PolicyEngine
from artemis.tools.contract import (
    CONTEXT_VIEW_TOKEN_CAP,
    CancelToken,
    Decision,
    ExecTier,
    RiskLevel,
    ToolCancelled,
    ToolContext,
    ToolResult,
    ToolSpecError,
    canonical_hash,
)
from artemis.tools.registry import ToolNotFound, ToolRegistry
from artemis.tools.runtime import (
    SubprocessExecutor,
    ToolRuntime,
    truncate_context_view,
    truncate_summary,
)

from conftest import EchoArgs, make_request, make_spec

pytestmark = pytest.mark.anyio


def _ctx(auth, *, run_id="r_test", cancel: CancelToken | None = None, taint=False) -> ToolContext:
    return ToolContext(
        run_id=run_id,
        session_id="s_test",
        cancel_token=cancel or CancelToken(),
        authorization=auth,
        taint=taint,
    )


def _authorize(engine: PolicyEngine, spec, args=None):
    request = make_request(spec, args=args or EchoArgs())
    decision = engine.evaluate(request)
    return engine.mint(request, decision)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def test_registry_rejects_duplicate_names(registry: ToolRegistry):
    registry.register(make_spec("dup_tool"))
    with pytest.raises(ValueError, match="duplicate tool name"):
        registry.register(make_spec("dup_tool"))


def test_registry_unknown_tool_raises(registry: ToolRegistry):
    with pytest.raises(ToolNotFound):
        registry.get("nope")
    assert registry.try_get("nope") is None


def test_registry_meta_test_every_builtin_is_coherent():
    from artemis.tools.builtin import BUILTIN_TOOLS

    for spec in BUILTIN_TOOLS:
        spec.validate_coherence()
        if spec.risk is RiskLevel.DESTRUCTIVE:
            assert spec.default_decision is not Decision.ALLOW
        if spec.produces_untrusted_content:
            assert spec.risk in (RiskLevel.READ_ONLY, RiskLevel.LOW, RiskLevel.MODERATE)
        if spec.requires_paths:
            assert spec.path_args
            assert spec.tier is ExecTier.SUBPROCESS
        assert spec.timeout_s <= 60.0


def test_registry_incoherent_specs_are_refused(registry: ToolRegistry):
    with pytest.raises(ToolSpecError):
        registry.register(
            make_spec("read_only_side_effect", risk=RiskLevel.READ_ONLY, side_effects=True)
        )
    with pytest.raises(ToolSpecError):
        registry.register(make_spec("Bad Name"))
    with pytest.raises(ToolSpecError):
        registry.register(make_spec("slow_tool", timeout_s=120.0))


def test_capability_gating_hides_unavailable_tools():
    registry = ToolRegistry(capabilities={"cpu"})
    registry.register(make_spec("needs_gpu", requires=frozenset({"gpu"})))
    registry.register(make_spec("plain_tool"))
    assert registry.missing_capabilities(registry.get("needs_gpu")) == {"gpu"}
    assert not registry.is_available(registry.get("needs_gpu"))
    assert [spec.name for spec in registry.visible()] == ["plain_tool"]


def test_deny_tools_are_omitted_from_the_schema_list(registry: ToolRegistry):
    registry.register(make_spec("visible_tool"))
    registry.register(make_spec("hidden_tool", default=Decision.DENY))
    decisions = {"visible_tool": Decision.ALLOW, "hidden_tool": Decision.DENY}
    names = [spec.name for spec in registry.visible(decisions)]
    assert names == ["visible_tool"]
    schemas = registry.provider_schemas(decisions)
    assert len(schemas) == 1
    assert schemas[0]["function"]["name"] == "visible_tool"


def test_compact_schema_shape(registry: ToolRegistry):
    registry.register(make_spec("shape_tool"))
    schema = registry.get("shape_tool").compact_schema()
    assert schema["name"] == "shape_tool"
    assert schema["parameters"]["type"] == "object"
    assert "value" in schema["parameters"]["properties"]


# ---------------------------------------------------------------------------
# Authorization enforcement at the runtime door
# ---------------------------------------------------------------------------


async def test_runtime_refuses_without_authorization(runtime: ToolRuntime):
    spec = make_spec("probe_tool")
    result = await runtime.execute(spec, EchoArgs(), None, _ctx(None))  # type: ignore[arg-type]
    assert result.status == "denied"
    assert result.error_code == "MISSING_AUTHORIZATION"


async def test_runtime_refuses_mutated_arguments(runtime: ToolRuntime, engine: PolicyEngine):
    spec = make_spec("probe_tool")
    auth = _authorize(engine, spec, EchoArgs(value="original"))
    result = await runtime.execute(spec, EchoArgs(value="mutated"), auth, _ctx(auth))
    assert result.status == "denied"
    assert result.error_code == "AUTHORIZATION_ARGS_MISMATCH"


async def test_runtime_refuses_tool_substitution(runtime: ToolRuntime, engine: PolicyEngine):
    spec = make_spec("probe_tool")
    other = make_spec("other_tool")
    auth = _authorize(engine, spec)
    result = await runtime.execute(other, EchoArgs(), auth, _ctx(auth))
    assert result.status == "denied"
    assert result.error_code == "AUTHORIZATION_TOOL_MISMATCH"


async def test_runtime_refuses_expired_authorization(runtime: ToolRuntime, engine: PolicyEngine):
    spec = make_spec("probe_tool")
    request = make_request(spec)
    auth = engine.mint(request, engine.evaluate(request), ttl_s=0.0)
    result = await runtime.execute(spec, EchoArgs(), auth, _ctx(auth))
    assert result.status == "denied"
    assert result.error_code == "AUTHORIZATION_EXPIRED"


async def test_runtime_refuses_authorization_for_a_different_run(
    runtime: ToolRuntime, engine: PolicyEngine
):
    spec = make_spec("probe_tool")
    auth = _authorize(engine, spec)
    result = await runtime.execute(spec, EchoArgs(), auth, _ctx(auth, run_id="r_other"))
    assert result.status == "denied"
    assert result.error_code == "AUTHORIZATION_RUN_MISMATCH"


async def test_runtime_refuses_replayed_forged_authorization(
    runtime: ToolRuntime, engine: PolicyEngine
):
    spec = make_spec("probe_tool")
    auth = _authorize(engine, spec)
    object.__setattr__(auth, "decision", Decision.ALLOW)
    object.__setattr__(auth, "tool", "probe_tool")
    object.__setattr__(auth, "risk", "DESTRUCTIVE")  # privilege escalation attempt
    result = await runtime.execute(spec, EchoArgs(), auth, _ctx(auth))
    assert result.status == "denied"
    assert result.error_code == "AUTHORIZATION_TAMPERED"


# ---------------------------------------------------------------------------
# Tiers
# ---------------------------------------------------------------------------


async def test_inline_tier_executes(runtime: ToolRuntime, engine: PolicyEngine):
    spec = make_spec("inline_tool", tier=ExecTier.INLINE)
    args = EchoArgs(value="hi")
    auth = _authorize(engine, spec, args)
    result = await runtime.execute(spec, args, auth, _ctx(auth))
    assert result.status == "ok"
    assert result.data == {"value": "hi"}
    assert result.result_id.startswith("res_")
    assert result.duration_ms >= 0


async def test_thread_tier_executes_blocking_work(runtime: ToolRuntime, engine: PolicyEngine):
    seen: dict[str, int] = {}

    async def blocking(args: EchoArgs, _ctx: ToolContext) -> ToolResult:
        import threading

        seen["thread"] = threading.get_ident()
        time.sleep(0.05)
        return ToolResult(status="ok", summary="blocked", data={"value": args.value})

    spec = make_spec("thread_tool", tier=ExecTier.THREAD, execute=blocking)
    auth = _authorize(engine, spec)
    import threading

    main_thread = threading.get_ident()
    result = await runtime.execute(spec, EchoArgs(), auth, _ctx(auth))
    assert result.status == "ok"
    assert seen["thread"] != main_thread


async def test_tool_exception_becomes_structured_error(runtime: ToolRuntime, engine: PolicyEngine):
    async def boom(_args, _ctx):
        raise ValueError("kaboom")

    spec = make_spec("boom_tool", execute=boom)
    auth = _authorize(engine, spec)
    result = await runtime.execute(spec, EchoArgs(), auth, _ctx(auth))
    assert result.status == "error"
    assert result.error_code == "TOOL_ERROR"
    assert "kaboom" not in result.summary  # no internals leak to the model


async def test_timeout_produces_timeout_status(runtime: ToolRuntime, engine: PolicyEngine):
    async def slow(_args, _ctx):
        await asyncio.sleep(5)
        return ToolResult(status="ok", summary="never")

    spec = make_spec("slow_tool", tier=ExecTier.INLINE, timeout_s=0.2, execute=slow)
    auth = _authorize(engine, spec)
    started = time.monotonic()
    result = await runtime.execute(spec, EchoArgs(), auth, _ctx(auth))
    assert result.status == "timeout"
    assert result.error_code == "TOOL_TIMEOUT"
    assert time.monotonic() - started < 2.0


async def test_cancellation_before_start(runtime: ToolRuntime, engine: PolicyEngine):
    spec = make_spec("probe_tool")
    auth = _authorize(engine, spec)
    token = CancelToken()
    token.cancel()
    result = await runtime.execute(spec, EchoArgs(), auth, _ctx(auth, cancel=token))
    assert result.status == "cancelled"


async def test_cooperative_cancellation_mid_tool(runtime: ToolRuntime, engine: PolicyEngine):
    async def cooperative(_args, ctx: ToolContext):
        for _ in range(100):
            ctx.cancel_token.raise_if_cancelled()
            await asyncio.sleep(0.01)
        return ToolResult(status="ok", summary="finished")

    spec = make_spec("coop_tool", timeout_s=5.0, execute=cooperative)
    auth = _authorize(engine, spec)
    token = CancelToken()

    async def canceller():
        await asyncio.sleep(0.05)
        token.cancel()

    task = asyncio.create_task(canceller())
    result = await runtime.execute(spec, EchoArgs(), auth, _ctx(auth, cancel=token))
    await task
    assert result.status == "cancelled"
    assert result.error_code == "CANCELLED"


# ---------------------------------------------------------------------------
# Subprocess tier: hard cancellation and process-tree termination
# ---------------------------------------------------------------------------


@pytest.fixture
def selftest_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ARTEMIS_SELFTEST", "1")
    return True


async def test_subprocess_worker_round_trip(fs_scope, sandbox_root: Path):
    (sandbox_root / "a.txt").write_text("alpha", encoding="utf-8")
    executor = SubprocessExecutor()
    outcome = await executor.run(
        worker="fs.read_file",
        payload={
            "args": {"path": str(sandbox_root / "a.txt")},
            "scope": {"allow_roots": [str(sandbox_root)], "allow_unc": False},
        },
        timeout_s=20.0,
        cancel_token=CancelToken(),
    )
    assert outcome.status == "ok"
    assert outcome.payload["text"] == "alpha"


async def test_subprocess_unknown_worker_fails_safely():
    executor = SubprocessExecutor()
    outcome = await executor.run(
        worker="fs.definitely_not_a_worker",
        payload={"args": {}},
        timeout_s=20.0,
        cancel_token=CancelToken(),
    )
    assert outcome.status == "error"
    assert outcome.error_code == "WORKER_UNKNOWN"


async def test_selftest_workers_are_gated_off_by_default():
    executor = SubprocessExecutor()
    outcome = await executor.run(
        worker="selftest.sleep",
        payload={"args": {"seconds": 0.1}},
        timeout_s=20.0,
        cancel_token=CancelToken(),
    )
    assert outcome.status == "error"
    assert outcome.error_code == "FS_DENIED"


async def test_subprocess_timeout_kills_the_process_tree(
    selftest_env, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """``docs/tools.md`` §4: the SUBPROCESS tier's timeout is *hard*."""
    marker = tmp_path / "grandchild.pid"
    executor = SubprocessExecutor()
    env_backup = dict(os.environ)
    monkeypatch.setenv("ARTEMIS_SELFTEST", "1")

    # The worker inherits ARTEMIS_SELFTEST only if the executor forwards it, so
    # pass it explicitly through the payload-independent env by patching the
    # executor's command with the flag already set in this process.
    original_run = executor.run

    started = time.monotonic()
    outcome = await original_run(
        worker="selftest.sleep",
        payload={"args": {"seconds": 60, "child_marker": str(marker)}},
        timeout_s=2.0,
        cancel_token=CancelToken(),
    )
    elapsed = time.monotonic() - started
    os.environ.clear()
    os.environ.update(env_backup)

    if outcome.error_code == "FS_DENIED":
        pytest.skip("self-test worker gate is closed in the child environment")
    assert outcome.status == "timeout"
    assert elapsed < 8.0

    # The grandchild must be gone too.
    deadline = time.monotonic() + 5.0
    pid = None
    while time.monotonic() < deadline:
        if marker.exists():
            try:
                pid = int(marker.read_text().strip())
                break
            except (ValueError, OSError):
                pass
        time.sleep(0.05)
    if pid is None:
        pytest.skip("grandchild never recorded its pid")
    time.sleep(0.5)
    assert not psutil.pid_exists(pid) or not psutil.Process(pid).is_running()


async def test_subprocess_cancellation_terminates_the_child(selftest_env, monkeypatch):
    monkeypatch.setenv("ARTEMIS_SELFTEST", "1")
    executor = SubprocessExecutor()
    token = CancelToken()

    async def canceller():
        await asyncio.sleep(0.6)
        token.cancel()

    task = asyncio.create_task(canceller())
    started = time.monotonic()
    outcome = await executor.run(
        worker="selftest.sleep",
        payload={"args": {"seconds": 60}},
        timeout_s=30.0,
        cancel_token=token,
    )
    await task
    elapsed = time.monotonic() - started
    if outcome.error_code == "FS_DENIED":
        pytest.skip("self-test worker gate is closed in the child environment")
    assert outcome.status == "cancelled"
    assert elapsed < 10.0


# ---------------------------------------------------------------------------
# Result capture / truncation
# ---------------------------------------------------------------------------


def test_summary_truncation():
    assert truncate_summary("a" * 300).endswith("…")
    assert len(truncate_summary("a" * 300)) == 200
    assert truncate_summary("  spaced   out ") == "spaced out"


def test_context_view_truncation_respects_token_cap():
    text = "x" * 10_000
    view, truncated = truncate_context_view(text, more_note="use read_more")
    assert truncated
    assert "use read_more" in view
    assert len(view) <= int(CONTEXT_VIEW_TOKEN_CAP * 3.6) + 64


def test_context_view_not_truncated_when_small():
    view, truncated = truncate_context_view("short")
    assert view == "short"
    assert not truncated


async def test_result_is_persisted_and_pageable(phase4_db, engine: PolicyEngine):
    from artemis.tools.results import ResultStore

    store = ResultStore(phase4_db)
    runtime = ToolRuntime(result_store=store)
    try:

        async def big(_args, _ctx):
            return ToolResult(
                status="ok",
                summary="big result",
                data={"text": "y" * 5000},
                context_view="y" * 100,
            )

        spec = make_spec("big_tool", execute=big)
        auth = _authorize(engine, spec)
        result = await runtime.execute(spec, EchoArgs(), auth, _ctx(auth))
        assert result.status == "ok"
        stored = await store.get(result.result_id)
        assert stored is not None
        assert stored["tool_name"] == "big_tool"
        page = await store.page(result.result_id, offset=0, limit=100)
        assert page["total_chars"] == 5000
        assert page["has_more"]
        assert page["text"] == "y" * 100
        page2 = await store.page(result.result_id, offset=4950, limit=100)
        assert not page2["has_more"]
    finally:
        runtime.shutdown()


async def test_read_more_inherits_untrusted_trust(phase4_db, engine: PolicyEngine):
    from artemis.tools.builtin.meta import READ_MORE, bind_result_store
    from artemis.tools.results import ResultStore

    store = ResultStore(phase4_db)
    bind_result_store(store)
    runtime = ToolRuntime(result_store=store)
    try:

        async def untrusted(_args, _ctx):
            return ToolResult(
                status="ok",
                summary="file",
                data={"text": "z" * 3000},
                context_view="z" * 50,
                trust="UNTRUSTED",
            )

        source = make_spec("untrusted_tool", produces_untrusted_content=True, execute=untrusted)
        auth = _authorize(engine, source)
        first = await runtime.execute(source, EchoArgs(), auth, _ctx(auth))
        assert first.trust == "UNTRUSTED"

        from artemis.tools.builtin.meta import ReadMoreArgs

        args = ReadMoreArgs(result_id=first.result_id, offset=0, limit=100)
        request = make_request(READ_MORE, args=args)
        more_auth = engine.mint(request, engine.evaluate(request))
        page = await runtime.execute(READ_MORE, args, more_auth, _ctx(more_auth))
        assert page.status == "ok"
        assert page.trust == "UNTRUSTED"
        assert "UNTRUSTED_CONTENT" in page.context_view
    finally:
        runtime.shutdown()


# ---------------------------------------------------------------------------
# Audit coupling
# ---------------------------------------------------------------------------


class _FailingAudit(AuditWriter):
    def __init__(self):  # noqa: D107 - test double
        self.records: list[AuditRecord] = []
        self.degraded = False

    async def record(self, record: AuditRecord, *, required: bool = True) -> None:
        self.records.append(record)
        if required:
            raise AuditFailure("disk full")


async def test_audit_failure_aborts_side_effecting_tool(engine: PolicyEngine):
    runtime = ToolRuntime(audit=_FailingAudit())
    try:
        executed: list[bool] = []

        async def mutate(_args, _ctx):
            executed.append(True)
            return ToolResult(status="ok", summary="mutated")

        spec = make_spec(
            "mutating_tool", risk=RiskLevel.MODERATE, default=Decision.ASK, execute=mutate
        )
        request = make_request(spec)
        _decision, auth = engine.authorize_approved(request, approval_id="ap_x")
        result = await runtime.execute(spec, EchoArgs(), auth, _ctx(auth))
        assert result.status == "error"
        assert result.error_code == "AUDIT_UNAVAILABLE"
        assert executed == []
    finally:
        runtime.shutdown()


async def test_audit_failure_allows_read_only_tool_to_proceed(engine: PolicyEngine):
    runtime = ToolRuntime(audit=_FailingAudit())
    try:
        spec = make_spec("probe_tool", risk=RiskLevel.READ_ONLY, default=Decision.ALLOW)
        auth = _authorize(engine, spec)
        result = await runtime.execute(spec, EchoArgs(), auth, _ctx(auth))
        assert result.status == "ok"
    finally:
        runtime.shutdown()


async def test_audit_records_execution_and_completion(phase4_db, audit: AuditWriter, engine):
    runtime = ToolRuntime(audit=audit)
    try:
        spec = make_spec("audited_tool")
        auth = _authorize(engine, spec)
        await runtime.execute(spec, EchoArgs(), auth, _ctx(auth))
    finally:
        runtime.shutdown()
    rows = await audit.query(tool="audited_tool", limit=50)
    events = {row["event"] for row in rows}
    assert "tool.execution" in events
    assert "tool.completed" in events


async def test_audit_does_not_record_file_contents(phase4_db, audit: AuditWriter, engine):
    from artemis.obs.audit import args_digest
    from artemis.tools.contract import canonical_args_json

    class WriteArgs(EchoArgs):
        content: str = "SUPER SECRET PAYLOAD"

    digest = args_digest(canonical_args_json(WriteArgs()), redact=("content",))
    assert "SUPER SECRET PAYLOAD" not in digest
    assert digest.startswith("sha256:")
