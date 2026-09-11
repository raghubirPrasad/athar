"""RFC 7807 problem+json (SPEC §13, §15). Never a stack trace, never an internal path."""

from __future__ import annotations

import secrets
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from athar.api.schemas import Problem, ValidationIssue
from athar.log import get_logger

log = get_logger("athar.api")

PROBLEM_MEDIA_TYPE = "application/problem+json"

_STATUS_TITLES: dict[int, tuple[str, str]] = {
    400: ("Bad Request", "bad_request"),
    401: ("Unauthorized", "auth.required"),
    403: ("Forbidden", "forbidden"),
    404: ("Not Found", "not_found"),
    405: ("Method Not Allowed", "method_not_allowed"),
    409: ("Conflict", "conflict"),
    413: ("Payload Too Large", "request.too_large"),
    415: ("Unsupported Media Type", "unsupported_media_type"),
    422: ("Unprocessable Content", "validation.failed"),
    429: ("Too Many Requests", "rate.limited"),
    500: ("Internal Server Error", "internal.error"),
    503: ("Service Unavailable", "unavailable"),
}


def new_request_id() -> str:
    return secrets.token_hex(8)


def problem_response(
    status: int,
    code: str,
    *,
    detail: str | None = None,
    title: str | None = None,
    instance: str | None = None,
    errors: list[ValidationIssue] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    default_title, _ = _STATUS_TITLES.get(status, ("Error", "error"))
    body = Problem(
        type=f"urn:athar:problem:{code}",
        title=title or default_title,
        status=status,
        detail=detail,
        code=code,
        instance=instance,
        errors=errors,
    )
    return JSONResponse(
        status_code=status,
        content=body.model_dump(mode="json", exclude_none=True),
        media_type=PROBLEM_MEDIA_TYPE,
        headers=headers,
    )


class ProblemException(HTTPException):
    """HTTPException with a stable machine-readable `code`."""

    def __init__(
        self,
        status_code: int,
        code: str,
        detail: str | None = None,
        *,
        title: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(status_code=status_code, detail=detail, headers=headers)
        self.code = code
        self.title = title


class UnauthorizedError(ProblemException):
    def __init__(self, detail: str = "Authentication required", code: str = "auth.required") -> None:
        super().__init__(401, code, detail)


class ForbiddenError(ProblemException):
    def __init__(self, code: str = "forbidden", detail: str = "Not allowed") -> None:
        super().__init__(403, code, detail)


class NotFoundError(ProblemException):
    def __init__(self, what: str = "resource", code: str = "not_found") -> None:
        super().__init__(404, code, f"{what} not found")


class ConflictError(ProblemException):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(409, code, detail)


class InvalidInputError(ProblemException):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(422, code, detail)


class PayloadTooLargeError(ProblemException):
    def __init__(self, limit: int) -> None:
        super().__init__(413, "request.too_large", f"Request body exceeds {limit} bytes")


class UnavailableError(ProblemException):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(503, code, detail)


def request_instance(request: Request) -> str | None:
    rid = getattr(request.state, "request_id", None)
    return f"urn:athar:request:{rid}" if rid else None


def _sanitise_errors(exc: RequestValidationError) -> list[ValidationIssue]:
    """Keep loc/msg/type only; drop `input`, `ctx`, `url` (may echo secrets or paths)."""
    issues: list[ValidationIssue] = []
    for err in exc.errors():
        loc = [str(part) for part in err.get("loc", ())]
        issues.append(
            ValidationIssue(loc=loc, msg=str(err.get("msg", "invalid")), type=str(err.get("type", "")))
        )
    return issues


async def _http_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, StarletteHTTPException)
    status = exc.status_code
    _, default_code = _STATUS_TITLES.get(status, ("Error", "http.error"))
    code = getattr(exc, "code", None) or default_code
    title = getattr(exc, "title", None)
    detail = exc.detail if isinstance(exc.detail, str) else None
    headers = dict(exc.headers) if exc.headers else None
    return problem_response(
        status, code, detail=detail, title=title, instance=request_instance(request), headers=headers
    )


async def _validation_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, RequestValidationError)
    return problem_response(
        422,
        "validation.failed",
        detail="Request did not match the schema",
        instance=request_instance(request),
        errors=_sanitise_errors(exc),
    )


async def _unhandled_handler(request: Request, exc: Exception) -> JSONResponse:
    rid = getattr(request.state, "request_id", None) or new_request_id()
    log.error(
        "unhandled exception",
        extra={"request_id": rid, "path": request.url.path, "exc_type": type(exc).__name__},
        exc_info=exc,
    )
    return problem_response(
        500, "internal.error", detail="Internal error", instance=f"urn:athar:request:{rid}"
    )


def install_problem_handlers(app: FastAPI) -> None:
    app.add_exception_handler(StarletteHTTPException, _http_exception_handler)
    app.add_exception_handler(RequestValidationError, _validation_handler)
    app.add_exception_handler(Exception, _unhandled_handler)


def problem_responses(*statuses: int) -> dict[int | str, dict[str, Any]]:
    """OpenAPI `responses` entry documenting problem+json for the given statuses."""
    out: dict[int | str, dict[str, Any]] = {}
    for status in statuses:
        title, _ = _STATUS_TITLES.get(status, ("Error", "error"))
        out[status] = {"model": Problem, "description": title, "content": {PROBLEM_MEDIA_TYPE: {}}}
    return out
