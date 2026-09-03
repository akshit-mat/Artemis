"""Stable error codes and the uniform error envelope.

``docs/api.md`` §1: every failure is ``{"error": {code, message, detail,
correlation_id}}``.  Clients switch on ``code``, never on ``message``.

Messages are written for a human reading the ARTEMIS UI.  They never contain
stack traces, tokens, or absolute paths outside the configured roots; the
correlation id is the bridge to the server-side log entry that has the detail.
"""

from __future__ import annotations

import uuid
from enum import Enum
from typing import Any, Final

from fastapi import Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from ..obs.logging import get_logger

_log = get_logger("api.errors")


class ErrorCode(str, Enum):
    """Stable, permanent identifiers.  Never rename a shipped value."""

    # transport / auth
    UNAUTHORIZED = "UNAUTHORIZED"
    ORIGIN_REJECTED = "ORIGIN_REJECTED"
    HOST_REJECTED = "HOST_REJECTED"
    PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
    TOO_MANY_CONNECTIONS = "TOO_MANY_CONNECTIONS"

    # protocol
    BAD_MESSAGE = "BAD_MESSAGE"
    BAD_REQUEST = "BAD_REQUEST"
    RESYNC_REQUIRED = "RESYNC_REQUIRED"

    # resources
    NOT_FOUND = "NOT_FOUND"
    DB_UNAVAILABLE = "DB_UNAVAILABLE"

    # generic
    CANCELLED = "CANCELLED"
    INTERNAL = "INTERNAL"

    # reserved for later phases; declared now so the client union is stable
    MODEL_UNAVAILABLE = "MODEL_UNAVAILABLE"
    MODEL_TIMEOUT = "MODEL_TIMEOUT"
    POLICY_DENIED = "POLICY_DENIED"
    TAINTED_DESTRUCTIVE = "TAINTED_DESTRUCTIVE"
    PATH_OUT_OF_SCOPE = "PATH_OUT_OF_SCOPE"
    TOOL_TIMEOUT = "TOOL_TIMEOUT"
    TOOL_ERROR = "TOOL_ERROR"
    TOOL_CALL_UNPARSEABLE = "TOOL_CALL_UNPARSEABLE"
    MAX_STEPS = "MAX_STEPS"
    REPEATED_TOOL_CALL = "REPEATED_TOOL_CALL"
    APPROVAL_TIMEOUT = "APPROVAL_TIMEOUT"


_STATUS_BY_CODE: Final[dict[ErrorCode, int]] = {
    ErrorCode.UNAUTHORIZED: 401,
    ErrorCode.ORIGIN_REJECTED: 403,
    ErrorCode.HOST_REJECTED: 403,
    ErrorCode.PAYLOAD_TOO_LARGE: 413,
    ErrorCode.TOO_MANY_CONNECTIONS: 503,
    ErrorCode.BAD_MESSAGE: 400,
    ErrorCode.BAD_REQUEST: 400,
    ErrorCode.RESYNC_REQUIRED: 409,
    ErrorCode.NOT_FOUND: 404,
    ErrorCode.DB_UNAVAILABLE: 503,
    ErrorCode.CANCELLED: 499,
    ErrorCode.INTERNAL: 500,
}


def new_correlation_id() -> str:
    return f"c_{uuid.uuid4().hex[:16]}"


class ApiError(Exception):
    """Raise to return a structured error without leaking internals."""

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        *,
        detail: dict[str, Any] | None = None,
        status_code: int | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.detail = detail or {}
        self.status_code = status_code or _STATUS_BY_CODE.get(code, 400)
        self.correlation_id = new_correlation_id()


def error_body(
    code: ErrorCode,
    message: str,
    *,
    detail: dict[str, Any] | None = None,
    correlation_id: str | None = None,
) -> dict[str, Any]:
    return {
        "error": {
            "code": code.value,
            "message": message,
            "detail": detail or {},
            "correlation_id": correlation_id or new_correlation_id(),
        }
    }


def error_response(
    code: ErrorCode,
    message: str,
    *,
    detail: dict[str, Any] | None = None,
    status_code: int | None = None,
    correlation_id: str | None = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code or _STATUS_BY_CODE.get(code, 400),
        content=error_body(code, message, detail=detail, correlation_id=correlation_id),
    )


def install_exception_handlers(app: Any) -> None:
    """Register handlers so no unhandled exception ever reaches the client raw."""

    @app.exception_handler(ApiError)
    async def _api_error(_request: Request, exc: ApiError) -> JSONResponse:
        _log.warning(
            "api_error",
            error_code=exc.code.value,
            correlation_id=exc.correlation_id,
            status=exc.status_code,
        )
        return JSONResponse(
            status_code=exc.status_code,
            content=error_body(
                exc.code,
                exc.message,
                detail=exc.detail,
                correlation_id=exc.correlation_id,
            ),
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = {
            401: ErrorCode.UNAUTHORIZED,
            403: ErrorCode.ORIGIN_REJECTED,
            404: ErrorCode.NOT_FOUND,
            413: ErrorCode.PAYLOAD_TOO_LARGE,
        }.get(exc.status_code, ErrorCode.BAD_REQUEST)
        if exc.status_code >= 500:
            code = ErrorCode.INTERNAL
        message = exc.detail if isinstance(exc.detail, str) else code.value
        return JSONResponse(
            status_code=exc.status_code,
            content=error_body(code, message),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(
        _request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # Field-level messages are safe (they describe the client's own input)
        # but are passed through ``jsonable_encoder`` so exotic objects cannot
        # break serialisation.
        return JSONResponse(
            status_code=400,
            content=error_body(
                ErrorCode.BAD_REQUEST,
                "Request body or parameters failed validation.",
                detail={"fields": jsonable_encoder(exc.errors())[:20]},
            ),
        )

    @app.exception_handler(Exception)
    async def _unhandled(_request: Request, exc: Exception) -> JSONResponse:
        correlation_id = new_correlation_id()
        # exc_info goes to the log only; the client gets a code and an id.
        _log.error(
            "unhandled_exception",
            correlation_id=correlation_id,
            error_code=ErrorCode.INTERNAL.value,
            exc_info=exc,
        )
        return JSONResponse(
            status_code=500,
            content=error_body(
                ErrorCode.INTERNAL,
                "An internal error occurred. See the ARTEMIS log for details.",
                correlation_id=correlation_id,
            ),
        )
