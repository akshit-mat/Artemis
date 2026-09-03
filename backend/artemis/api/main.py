import os
from contextlib import asynccontextmanager
from typing import Callable
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from .ws import router as ws_router
from .errors import install_exception_handlers, ApiError, ErrorCode
from .security import TransportPolicy, AuthToken, OriginVerdict, TokenError
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

# Tests override TransportPolicy via for_testing if they aren't listening on a real socket,
# but using `testserver` or manual host headers. We'll add `testserver` to expected hosts.
expected_hosts = frozenset({f"{host}:{port}", "testserver"})
policy = TransportPolicy.for_testing(expected_hosts, dev_mode=dev_mode)

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

app.include_router(ws_router, prefix="/v1")
