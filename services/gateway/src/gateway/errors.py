"""HTTP error rendering.

Every failure leaves the gateway in the same envelope:

    {"error": {"code": "...", "message": "...", "request_id": "..."}}

`code` is the stable `ErrorCode` from the shared taxonomy, so clients branch on it
rather than on status codes or message text.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import JSONResponse

from authmesh_common.context import REQUEST_ID_HEADER, get_request_id
from authmesh_common.errors import AppError, ErrorCode
from authmesh_common.logging import get_logger

log = get_logger("authmesh.gateway.errors")


def _envelope(
    code: str, message: str, *, details: dict | None = None, retry_after: int | None = None
) -> dict:
    error: dict = {"code": code, "message": message}
    request_id = get_request_id()
    if request_id:
        error["request_id"] = request_id
    if details:
        error["details"] = details
    if retry_after is not None:
        error["retry_after"] = retry_after
    return {"error": error}


def _headers(retry_after: int | None) -> dict[str, str]:
    headers: dict[str, str] = {}
    request_id = get_request_id()
    if request_id:
        headers[REQUEST_ID_HEADER] = request_id
    if retry_after is not None:
        # Standard header so clients and load balancers back off correctly.
        headers["retry-after"] = str(retry_after)
    return headers


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def handle_app_error(request: Request, exc: AppError) -> JSONResponse:
        if exc.code is ErrorCode.INTERNAL:
            log.error("internal error surfaced to client", extra={"path": request.url.path})
        return JSONResponse(
            status_code=exc.http_status,
            content=_envelope(
                exc.code.value,
                exc.message,
                details=exc.details or None,
                retry_after=exc.retry_after,
            ),
            headers=_headers(exc.retry_after),
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # Report which fields failed, but never echo the submitted values: the
        # body may contain a password.
        fields = [
            {
                "field": ".".join(str(part) for part in error.get("loc", ())[1:]),
                "problem": error.get("msg", "invalid value"),
            }
            for error in exc.errors()
        ]
        return JSONResponse(
            status_code=422,
            content=_envelope(
                ErrorCode.INVALID_ARGUMENT.value,
                "the request body is invalid",
                details={"fields": fields},
            ),
            headers=_headers(None),
        )

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_exception(
        request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        code = {
            401: ErrorCode.UNAUTHENTICATED.value,
            403: ErrorCode.PERMISSION_DENIED.value,
            404: ErrorCode.NOT_FOUND.value,
            405: "method_not_allowed",
            429: ErrorCode.RATE_LIMITED.value,
        }.get(exc.status_code, "http_error")
        return JSONResponse(
            status_code=exc.status_code,
            content=_envelope(code, str(exc.detail)),
            headers={**_headers(None), **(exc.headers or {})},
        )

    @app.exception_handler(Exception)
    async def handle_unexpected(request: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled exception", extra={"path": request.url.path})
        return JSONResponse(
            status_code=500,
            content=_envelope(ErrorCode.INTERNAL.value, "internal error"),
            headers=_headers(None),
        )
