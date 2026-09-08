import os
from contextlib import asynccontextmanager
from typing import Callable
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from .ws import router as ws_router
from .errors import install_exception_handlers, ApiError, ErrorCode, error_response
from .security import TransportPolicy, AuthToken, OriginVerdict, TokenError
from .models import SessionStateResponse, AssistantStateData
from ..config.paths import Paths
from ..config.schema import load_config
from ..storage.database import Database
from ..obs.logging import get_logger

log = get_logger("api")

paths = Paths.resolve()
config, clamps = load_config(paths)

# Fallback for tests if needed, but we prefer env
try:
    auth_token = AuthToken.from_environ(os.environ, consume=True)
except TokenError as exc:
    log.error("auth_token_error", error=str(exc))
    raise

dev_mode = os.environ.get("ARTEMIS_DEV_MODE", "1") == "1"
port = int(os.environ.get("ARTEMIS_PORT", "0"))
host = os.environ.get("ARTEMIS_HOST", "127.0.0.1")

# Production transport policy: only the actually-bound host:port is trusted.
# "testserver" is NOT included here — tests that need Host validation must
# supply a correct Host header explicitly (all existing tests do this).
policy = TransportPolicy.for_binding(host, port, dev_mode=dev_mode)

db = Database(paths.db_path, config.db)

from ..storage.migrations import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    for key, requested, clamped in clamps:
        log.warning("config_clamped", key=key, requested=requested, clamped=clamped)
    db.open()
    # Initialize DB schema off the event loop
    import asyncio
    await asyncio.to_thread(init_db, db)
    if hasattr(app.state, "fs_scope"):
        await app.state.fs_scope.load()
    yield
    await asyncio.to_thread(db.shutdown)


app = FastAPI(title="ARTEMIS Phase 1", lifespan=lifespan)
app.state.auth_token = auth_token
app.state.policy = policy
app.state.db = db
app.state.config = config

from ..models.registry import ModelRegistry
app.state.model_registry = ModelRegistry(config)

from ..storage.repositories.runs import RunRepository
from ..storage.repositories.messages import MessageRepository
from ..storage.repositories.sessions import SessionRepository
from ..agent.loop import AgentOrchestrator

run_repo = RunRepository(db)
message_repo = MessageRepository(db)
session_repo = SessionRepository(db)
app.state.run_repo = run_repo
app.state.message_repo = message_repo
app.state.session_repo = session_repo

# Phase 4/5 Component Wiring
from ..tools.registry import ToolRegistry
from ..tools.builtin import register_builtin_tools
from ..tools.results import ResultStore
from ..tools.builtin.meta import bind_result_store
from ..obs.audit import AuditWriter
from ..tools.runtime import ToolRuntime
from ..policy.approvals import ApprovalManager
from ..policy.engine import PolicyEngine
from ..policy.store import PolicyStore
from ..policy.fsconfig import FilesystemScope
from ..agent.tools import ToolMediator
from .events import bus

registry = register_builtin_tools(ToolRegistry(capabilities={"windows", "psutil", "cpu"}))
store = ResultStore(db)
bind_result_store(store)
audit = AuditWriter(db)
runtime = ToolRuntime(audit=audit, result_store=store)
approvals = ApprovalManager(db)
app.state.approvals = approvals

fs_scope = FilesystemScope(db=db)
app.state.fs_scope = fs_scope

mediator = ToolMediator(
    engine=PolicyEngine(),
    runtime=runtime,
    approvals=approvals,
    audit=audit,
    store=PolicyStore(db),
    fs_scope=fs_scope,
    registry=registry,
    publish=bus.publish,
)
app.state.agent_orchestrator = AgentOrchestrator(run_repo, message_repo, app.state.model_registry, session_repo, mediator=mediator)

install_exception_handlers(app)


# --------------------------------------------------------------------------
# Middleware (registered in reverse order: last registered = outermost = first to run)
# --------------------------------------------------------------------------

@app.middleware("http")
async def security_middleware(request: Request, call_next: Callable):
    req_policy = request.app.state.policy
    auth_token = request.app.state.auth_token

    if not req_policy.check_host(request.headers.get("host")):
        log.warning("invalid_host_rejected", host=request.headers.get("host"))
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"error": {"code": "POLICY_DENIED", "message": "Invalid Host"}}
        )

    if req_policy.requires_origin(request.url.path):
        verdict = req_policy.check_origin(request.headers.get("origin"))
        if verdict == OriginVerdict.REJECTED:
            log.warning("invalid_origin_rejected", origin=request.headers.get("origin"))
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"error": {"code": "ORIGIN_REJECTED", "message": "Origin not allowed"}}
            )

    if req_policy.requires_auth(request.url.path) and request.url.path != "/v1/events":
        if not auth_token.verify_bearer(request.headers.get("Authorization")):
            log.warning("invalid_auth_rejected")
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"error": {"code": "UNAUTHORIZED", "message": "Invalid token"}}
            )

    response = await call_next(request)
    return response


@app.middleware("http")
async def body_size_middleware(request: Request, call_next: Callable):
    """Reject HTTP requests whose body exceeds the configured limit.

    This middleware runs *before* security_middleware (outermost) so oversized
    payloads are rejected cheaply without doing auth work.  WebSocket upgrade
    requests carry no body, so the Content-Length check is safely a no-op for
    them.  Documented in ``docs/api.md`` §1: Request body ≤ 1 MB.
    """
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            size = int(content_length)
        except ValueError:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"error": {"code": "BAD_REQUEST", "message": "Invalid Content-Length header"}},
            )
        max_body = request.app.state.config.http.max_body_bytes
        if size > max_body:
            log.warning("body_too_large", size=size, limit=max_body)
            return JSONResponse(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                content={
                    "error": {
                        "code": "PAYLOAD_TOO_LARGE",
                        "message": f"Request body exceeds the {max_body}-byte limit",
                    }
                },
            )
    return await call_next(request)


# --------------------------------------------------------------------------
# HTTP endpoints
# --------------------------------------------------------------------------

@app.get("/health")
async def health_check():
    db_status = db.integrity_check()
    return {
        "status": "ok",
        "version": "0.1.0",
        "model": {"loaded": False, "name": None},
        "db": db_status,
        "uptime_s": 0
    }


@app.get("/v1/sessions")
async def list_sessions(request: Request):
    session_repo = request.app.state.session_repo
    sessions = await session_repo.get_sessions()
    return {"sessions": sessions}


@app.get("/v1/sessions/{session_id}")
async def get_session(request: Request, session_id: str):
    session_repo = request.app.state.session_repo
    session = await session_repo.get_session(session_id)
    if not session:
        raise ApiError(
            ErrorCode.NOT_FOUND,
            f"Session '{session_id}' not found",
            status_code=404,
        )
    return session


@app.get("/v1/sessions/{session_id}/state", response_model=SessionStateResponse)
async def get_session_state(request: Request, session_id: str) -> SessionStateResponse:
    """Return the authoritative session snapshot for full resync.

    Called by the frontend when the WS event bus sends ``client.resync_required``
    (i.e. the requested replay window is no longer available).

    See ``docs/api.md`` §3 and §4.
    """
    from .events import bus

    session_repo = request.app.state.session_repo
    session = await session_repo.get_session(session_id)
    if not session:
        raise ApiError(
            ErrorCode.NOT_FOUND,
            f"Session '{session_id}' not found",
            status_code=404,
        )

    from ..agent.state import state_computer
    
    approvals = request.app.state.approvals.pending() if hasattr(request.app.state, "approvals") else []

    return SessionStateResponse(
        session_id=session_id,
        last_seq=bus.current_seq,
        assistant_state=AssistantStateData(**state_computer.compute()),
        active_run=None,
        pending_approvals=[a.model_dump() for a in approvals],
        active_task=None,
    )


from pydantic import BaseModel
class ModelSelectionReq(BaseModel):
    role: str
    model_id: str


@app.get("/v1/models")
async def get_models(request: Request):
    from ..models.registry import ModelRegistry
    registry: ModelRegistry = request.app.state.model_registry
    models_resp = []
    for role in registry.get_all_roles():
        provider = registry.get_provider(role)
        if provider:
            health = await provider.health()
            cfg = registry.get_config(role)
            if cfg:
                models_resp.append({
                    "id": cfg.id,
                    "provider": cfg.provider,
                    "model": cfg.model,
                    "role": role,
                    "num_ctx": cfg.num_ctx,
                    "capabilities": cfg.capabilities.model_dump(),
                    "health": health,
                    "active": True
                })
    return {"models": models_resp}


@app.post("/v1/models/select")
async def select_model(request: Request, body: ModelSelectionReq):
    from ..models.registry import ModelRegistry
    registry: ModelRegistry = request.app.state.model_registry
    provider = registry.get_provider(body.role)
    if not provider:
        return JSONResponse(status_code=404, content={"error": {"code": "NOT_FOUND", "message": f"Role {body.role} not found"}})
    cfg = registry.get_config(body.role)
    if cfg and cfg.id != body.model_id:
        return JSONResponse(status_code=400, content={"error": {"code": "BAD_REQUEST", "message": "Model selection is static per role. Only the configured model is selectable."}})

    return {"status": "ok", "active_model_id": cfg.id if cfg else body.model_id}


app.include_router(ws_router, prefix="/v1")


# --------------------------------------------------------------------------
# Approvals
# --------------------------------------------------------------------------

@app.get("/v1/approvals")
async def list_approvals(request: Request):
    approvals = request.app.state.approvals.pending()
    return {"approvals": [a.model_dump() for a in approvals]}

class ApprovalResponseReq(BaseModel):
    action: str
    scope: str = "once"

@app.post("/v1/approvals/{approval_id}")
async def respond_approval(request: Request, approval_id: str, payload: ApprovalResponseReq):
    from ..policy.approvals import ApprovalError
    try:
        await request.app.state.approvals.respond(approval_id, payload.action, payload.scope)
        return {"status": "ok"}
    except ApprovalError as e:
        status_code = 400
        if e.code == "APPROVAL_UNKNOWN":
            status_code = 404
        elif e.code == "APPROVAL_REPLAY":
            status_code = 409
        raise ApiError(ErrorCode.BAD_REQUEST if status_code != 404 else ErrorCode.NOT_FOUND, str(e), status_code=status_code)
    except Exception as e:
        raise ApiError(ErrorCode.BAD_REQUEST, str(e), status_code=400)

# --------------------------------------------------------------------------
# Grants / Permissions
# --------------------------------------------------------------------------

@app.get("/v1/grants")
async def list_grants(request: Request):
    from ..policy.store import PolicyStore
    store = PolicyStore(request.app.state.db)
    grants = await store.list_grants()
    return {"grants": [g.model_dump() for g in grants]}

@app.delete("/v1/grants/{grant_id}")
async def revoke_grant(request: Request, grant_id: str):
    from ..policy.store import PolicyStore
    store = PolicyStore(request.app.state.db)
    await store.revoke_grant(grant_id)
    return {"status": "ok"}

# --------------------------------------------------------------------------
# Filesystem Scope Settings
# --------------------------------------------------------------------------

@app.get("/v1/settings/fs")
async def get_fs_settings(request: Request):
    fs = request.app.state.fs_scope
    return {"allow_roots": fs.allow_roots}

class AddRootReq(BaseModel):
    root: str
    confirm_risk: bool = False

@app.post("/v1/settings/fs/roots")
async def add_fs_root(request: Request, payload: AddRootReq):
    fs = request.app.state.fs_scope
    try:
        await fs.add_root(payload.root, confirm_risk=payload.confirm_risk)
        return {"allow_roots": fs.allow_roots}
    except Exception as e:
        raise ApiError(ErrorCode.BAD_REQUEST, str(e), status_code=400)

class RemoveRootReq(BaseModel):
    root: str

@app.delete("/v1/settings/fs/roots")
async def remove_fs_root(request: Request, payload: RemoveRootReq):
    fs = request.app.state.fs_scope
    try:
        await fs.remove_root(payload.root)
        return {"allow_roots": fs.allow_roots}
    except Exception as e:
        raise ApiError(ErrorCode.BAD_REQUEST, str(e), status_code=400)
