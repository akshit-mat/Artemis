"""Shared Phase 4/5 test fixtures.

Deliberately small: the point is to exercise the real policy engine, real
runtime and real registry, not to build a parallel framework.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

import pytest
from pydantic import BaseModel, ConfigDict

from artemis.config.schema import DbConfig
from artemis.policy.approvals import ApprovalManager
from artemis.policy.engine import MODE_STANDARD, PolicyEngine, PolicyRequest
from artemis.policy.fsconfig import FilesystemScope
from artemis.policy.store import PolicyStore
from artemis.storage.database import Database
from artemis.storage.migrations import init_db
from artemis.obs.audit import AuditWriter
from artemis.tools.contract import (
    CancelToken,
    Decision,
    ExecTier,
    RiskLevel,
    ToolCategory,
    ToolContext,
    ToolResult,
    ToolSpec,
)
from artemis.tools.registry import ToolRegistry
from artemis.tools.runtime import ToolRuntime


class EchoArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    value: str = "x"


class EchoResult(BaseModel):
    model_config = ConfigDict(extra="allow")


async def _echo(args: EchoArgs, _ctx: ToolContext) -> ToolResult:
    return ToolResult(status="ok", summary=f"echo {args.value}", data={"value": args.value})


def make_spec(
    name: str = "probe_tool",
    *,
    risk: RiskLevel = RiskLevel.READ_ONLY,
    default: Decision = Decision.ALLOW,
    side_effects: bool | None = None,
    destructive: bool = False,
    tier: ExecTier = ExecTier.INLINE,
    timeout_s: float = 5.0,
    produces_untrusted_content: bool = False,
    execute: Callable[..., Any] | None = None,
    requires: frozenset[str] = frozenset(),
    reversible: bool = True,
    category: ToolCategory = ToolCategory.SYSTEM,
    args_model: type[BaseModel] = EchoArgs,
) -> ToolSpec:
    if side_effects is None:
        side_effects = risk in (RiskLevel.MODERATE, RiskLevel.DESTRUCTIVE)
    return ToolSpec(
        name=name,
        summary=f"test tool {name}",
        args_model=args_model,
        returns_model=EchoResult,
        category=category,
        risk=risk,
        side_effects=side_effects,
        reversible=reversible,
        produces_untrusted_content=produces_untrusted_content,
        tier=tier,
        timeout_s=timeout_s,
        default_decision=default,
        execute=execute or _echo,
        destructive=destructive or risk is RiskLevel.DESTRUCTIVE,
        requires=requires,
    )


def make_request(
    spec: ToolSpec,
    *,
    args: Any = None,
    run_id: str = "r_test",
    session_id: str = "s_test",
    tainted: bool = False,
    paths: tuple[Any, ...] = (),
    item_count: int = 1,
    user_turn_text: str = "",
    side_effect_budget_exceeded: bool = False,
) -> PolicyRequest:
    return PolicyRequest(
        spec=spec,
        args=args if args is not None else EchoArgs(),
        run_id=run_id,
        session_id=session_id,
        tainted=tainted,
        paths=paths,
        item_count=item_count,
        user_turn_text=user_turn_text,
        side_effect_budget_exceeded=side_effect_budget_exceeded,
    )


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def engine() -> PolicyEngine:
    return PolicyEngine(mode=MODE_STANDARD, rules={}, grants=[])


@pytest.fixture
def registry() -> ToolRegistry:
    return ToolRegistry(capabilities={"cpu", "windows", "psutil"})


@pytest.fixture
def phase4_db(tmp_path: Path) -> Database:
    database = Database(tmp_path / "phase4.sqlite", DbConfig(read_pool_size=1, busy_timeout_ms=200))
    database.open()
    init_db(database)
    database.execute_write_sync(
        "INSERT OR IGNORE INTO sessions (id, title) VALUES ('s_test', 'Test')"
    )
    yield database
    database.shutdown()


@pytest.fixture
def audit(phase4_db: Database) -> AuditWriter:
    return AuditWriter(phase4_db)


@pytest.fixture
def policy_store(phase4_db: Database) -> PolicyStore:
    return PolicyStore(phase4_db)


@pytest.fixture
def approvals(phase4_db: Database) -> ApprovalManager:
    return ApprovalManager(phase4_db, timeout_s=2.0)


@pytest.fixture
def runtime(audit: AuditWriter) -> ToolRuntime:
    instance = ToolRuntime(audit=audit)
    yield instance
    instance.shutdown()


@pytest.fixture
def sandbox_root(tmp_path: Path) -> Path:
    root = tmp_path / "workspace"
    root.mkdir()
    return root


@pytest.fixture
def fs_scope(sandbox_root: Path) -> FilesystemScope:
    return FilesystemScope(allow_roots=[str(sandbox_root)])


@pytest.fixture
def cancel_token() -> CancelToken:
    return CancelToken()
