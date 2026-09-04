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
    yield
    await asyncio.to_thread(db.shutdown)


app = FastAPI(title="ARTEMIS Phase 1", lifespan=lifespan)
app.state.auth_token = auth_token
app.state.policy = policy
app.state.db = db
app.state.config = config

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


@app.get("/v1/sessions/{session_id}/state", response_model=SessionStateResponse)
async def get_session_state(session_id: str) -> SessionStateResponse:
    """Return the authoritative session snapshot for full resync.

    Called by the frontend when the WS event bus sends ``client.resync_required``
    (i.e. the requested replay window is no longer available).

    See ``docs/api.md`` §3 and §4.
    """
    from .events import bus

    # Phase 1 supports only the single hardcoded session.
    if session_id != "s_test":
        raise ApiError(
            ErrorCode.NOT_FOUND,
            f"Session '{session_id}' not found",
            status_code=404,
        )

    return SessionStateResponse(
        session_id=session_id,
        last_seq=bus.current_seq,
        assistant_state=AssistantStateData(state="idle", intensity=0),
        active_run=None,
        pending_approvals=[],
        active_task=None,
    )


app.include_router(ws_router, prefix="/v1")
