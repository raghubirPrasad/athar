"""Platform hygiene middlewares (SPEC §15.3): security headers, CSRF header check,
request body size limit, catch-all problem+json, structured request logging.

All are pure ASGI so they compose without BaseHTTPMiddleware's streaming caveats.
"""

from __future__ import annotations

import time

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from athar.api.problem import PayloadTooLargeError, new_request_id, problem_response
from athar.config import Settings
from athar.log import get_logger
from athar.security.auth import COOKIE_NAME, decode_token

log = get_logger("athar.api.request")

CSRF_HEADER = "x-requested-with"
CSRF_VALUE = "athar"
MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
BODY_SLACK_BYTES = 1024 * 1024  # multipart framing + form fields on top of one max-size file

STRICT_CSP = "default-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
# Swagger UI loads its bundle from jsdelivr and boots with an inline script; docs only.
DOCS_CSP = (
    "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
    "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; img-src 'self' data: https://fastapi.tiangolo.com; "
    "frame-ancestors 'none'"
)


def _header(scope: Scope, name: str) -> str | None:
    target = name.lower().encode("latin-1")
    for key, value in scope.get("headers", []):
        if key.lower() == target:
            return value.decode("latin-1")
    return None


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp, *, hsts: bool, docs_paths: tuple[str, ...] = ()) -> None:
        self.app = app
        self.hsts = hsts
        self.docs_paths = docs_paths

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        is_docs = any(path.startswith(p) for p in self.docs_paths)

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["Content-Security-Policy"] = DOCS_CSP if is_docs else STRICT_CSP
                headers["X-Content-Type-Options"] = "nosniff"
                headers["X-Frame-Options"] = "DENY"
                headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
                headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
                if path.startswith("/api"):
                    headers["Cache-Control"] = "no-store"
                if self.hsts:
                    headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
            await send(message)

        await self.app(scope, receive, send_with_headers)


class CsrfHeaderMiddleware:
    """Every mutating request under `prefix` must carry `X-Requested-With: athar` (SPEC §13)."""

    def __init__(self, app: ASGIApp, prefix: str = "/api") -> None:
        self.app = app
        self.prefix = prefix

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] == "http"
            and scope.get("method", "GET").upper() in MUTATING_METHODS
            and scope.get("path", "").startswith(self.prefix)
            and (_header(scope, CSRF_HEADER) or "").strip().lower() != CSRF_VALUE
        ):
            response = problem_response(
                403,
                "csrf.header_missing",
                detail=f"Mutating requests must send X-Requested-With: {CSRF_VALUE}",
            )
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


class BodySizeLimitMiddleware:
    """413 problem+json when Content-Length (or the streamed body) exceeds `max_bytes`."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        declared = _header(scope, "content-length")
        if declared and declared.isdigit() and int(declared) > self.max_bytes:
            response = problem_response(
                413, "request.too_large", detail=f"Request body exceeds {self.max_bytes} bytes"
            )
            await response(scope, receive, send)
            return
        received = 0
        limit = self.max_bytes

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise PayloadTooLargeError(limit)
            return message

        await self.app(scope, limited_receive, send)


class ProblemCatchAllMiddleware:
    """Turn any escaped exception into a 500 problem+json (inside the headers middleware, so
    even crashes carry the security headers). Logs with the request id; never the trace."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        started = False

        async def tracking_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, receive, tracking_send)
        except Exception as exc:
            if started:
                raise
            rid = scope.get("state", {}).get("request_id") or new_request_id()
            log.error(
                "unhandled exception",
                extra={"request_id": rid, "path": scope.get("path", ""), "exc_type": type(exc).__name__},
                exc_info=exc,
            )
            response = problem_response(
                500, "internal.error", detail="Internal error", instance=f"urn:athar:request:{rid}"
            )
            await response(scope, receive, send)


class RequestLogMiddleware:
    """One structured line per request: method, path, status, ms, role, request id. No query
    strings, no bodies, no cookies."""

    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        self.app = app
        self.settings = settings

    def _role(self, scope: Scope) -> str:
        cookie_header = _header(scope, "cookie") or ""
        for part in cookie_header.split(";"):
            name, _, value = part.strip().partition("=")
            if name == COOKIE_NAME and value:
                user = decode_token(value, self.settings)
                return user.role if user else "invalid"
        return "anon"

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        rid = new_request_id()
        scope.setdefault("state", {})["request_id"] = rid
        start = time.perf_counter()
        status = 0

        async def send_logged(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = int(message["status"])
                MutableHeaders(scope=message)["X-Request-Id"] = rid
            await send(message)

        try:
            await self.app(scope, receive, send_logged)
        finally:
            ms = round((time.perf_counter() - start) * 1000, 1)
            log.info(
                "request",
                extra={
                    "request_id": rid,
                    "method": scope.get("method", ""),
                    "path": scope.get("path", ""),
                    "status": status,
                    "ms": ms,
                    "role": self._role(scope),
                },
            )
