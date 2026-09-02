import time
from fastapi import FastAPI, Request, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from typing import Callable

from .ws import router as ws_router
from ..config.settings import settings
from ..obs.logging import log

app = FastAPI(title="ARTEMIS Phase 1")

@app.middleware("http")
async def security_middleware(request: Request, call_next: Callable):
    # 1. Host validation (anti-DNS-rebinding)
    host = request.headers.get("host", "")
    expected_host = f"{settings.host}:{settings.port}"
    if host != expected_host and not (host.startswith("127.0.0.1:") or host.startswith("localhost:") or host == "testserver"):
        log.warning("invalid_host_rejected", host=host)
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"error": {"code": "POLICY_DENIED", "message": "Invalid Host"}}
        )

    # 2. Origin validation for browser requests (CORS is disabled, but we manually check Origin)
    origin = request.headers.get("origin")
    if origin and origin not in ["http://tauri.localhost", "http://localhost:1420"]:
        log.warning("invalid_origin_rejected", origin=origin)
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"error": {"code": "ORIGIN_REJECTED", "message": "Origin not allowed"}}
        )

    # 3. Authentication (Skip for /health and WebSocket upgrade since WS auth is via subprotocol)
    if request.url.path not in ["/health", "/v1/events"]:
        auth_header = request.headers.get("Authorization")
        expected_token = f"Bearer {settings.auth_token}"
        if not auth_header or not _constant_time_compare(auth_header, expected_token):
            log.warning("invalid_auth_rejected")
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"error": {"code": "UNAUTHORIZED", "message": "Invalid token"}}
            )
            
    response = await call_next(request)
    return response

def _constant_time_compare(val1: str, val2: str) -> bool:
    if len(val1) != len(val2):
        return False
    result = 0
    for x, y in zip(val1, val2):
        result |= ord(x) ^ ord(y)
    return result == 0

@app.get("/health")
async def health_check():
    return {
        "status": "ok",
        "version": "0.1.0",
        "model": {"loaded": False, "name": None},
        "db": "ok",
        "uptime_s": 0 # simplified for Phase 1
    }

app.include_router(ws_router, prefix="/v1")
