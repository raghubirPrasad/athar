"""FastAPI application factory (SPEC §13, §15.3).

`create_app()` builds the app from `Settings`; `uvicorn athar.api.app:create_app --factory`
serves it. In mock mode (`ATHAR_API_MOCK=true`) every route answers from the in-process
`MockRepo`; otherwise the integrator installs `app.state.repo_factory` (and appends ledger /
scheduler bootstrap callables to `app.state.startup_hooks`) and the lifespan runs migrations
and seeds the demo users.

Middleware, outermost first: request log → security headers → catch-all problem+json →
body-size limit → CORS → rate limit → CSRF header → routers.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Callable, Sequence
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.routing import APIRoute

from athar import __version__
from athar.api.problem import install_problem_handlers
from athar.api.routers import all_routers, debug_router
from athar.config import APP_NAME, Settings, get_settings
from athar.log import configure, get_logger
from athar.security.headers import (
    BODY_SLACK_BYTES,
    BodySizeLimitMiddleware,
    CsrfHeaderMiddleware,
    ProblemCatchAllMiddleware,
    RequestLogMiddleware,
    SecurityHeadersMiddleware,
)
from athar.security.limits import RateLimitMiddleware, default_rules

API_PREFIX = "/api/v1"
DOCS_URL = "/api/docs"
OPENAPI_URL = "/api/openapi.json"

StartupHook = Callable[[FastAPI], None]
log = get_logger("athar.api")


def _operation_id(route: APIRoute) -> str:
    """Operation ids are the handler names → clean generated TypeScript (`make types`)."""
    return route.name


def create_app(settings: Settings | None = None, startup_hooks: Sequence[StartupHook] = ()) -> FastAPI:
    settings = settings or get_settings()
    settings.assert_startable()

    app = FastAPI(
        title=APP_NAME,
        version=__version__,
        description="Multi-cloud access governance: normalise, score, explain, remediate, attest.",
        docs_url=DOCS_URL,
        redoc_url=None,
        swagger_ui_oauth2_redirect_url=None,  # keep every route under /api
        openapi_url=OPENAPI_URL,
        lifespan=_lifespan,
        generate_unique_id_function=_operation_id,
    )
    app.state.settings = settings
    app.state.startup_hooks = list(startup_hooks)
    app.state.rate_limit_rules = default_rules(API_PREFIX)

    if settings.api_mock:
        from athar.api.mock import MockRepo  # lazy: the real path never imports the mock
        from athar.security.users import InMemoryUserStore

        app.state.mock_repo = MockRepo(settings)
        app.state.user_store = InMemoryUserStore(settings)

    install_problem_handlers(app)
    for router in all_routers():
        app.include_router(router, prefix=API_PREFIX)
    if settings.api_mock:
        app.include_router(debug_router, prefix=API_PREFIX)

    # add_middleware prepends, so the innermost goes first.
    app.add_middleware(CsrfHeaderMiddleware, prefix="/api")
    app.add_middleware(
        RateLimitMiddleware,
        rules=app.state.rate_limit_rules,
        trusted_proxies=settings.trusted_proxy_networks,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[settings.public_url.rstrip("/")],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "X-Requested-With"],
        expose_headers=["Content-Disposition", "Retry-After", "X-Request-Id"],
    )
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_upload_bytes + BODY_SLACK_BYTES)
    app.add_middleware(ProblemCatchAllMiddleware)
    app.add_middleware(
        SecurityHeadersMiddleware, hsts=settings.cookie_secure, docs_paths=(DOCS_URL, OPENAPI_URL)
    )
    app.add_middleware(RequestLogMiddleware, settings=settings)
    return app


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    settings.assert_startable()
    configure(settings.log_level)
    # httpx logs every outbound URL at INFO; an LLM provider URL could carry a key. Warnings only.
    for noisy in ("httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    if settings.api_mock:
        log.info("startup", extra={"mode": "mock", "version": __version__})
    else:
        _startup_real(app, settings)
    yield
    log.info("shutdown")


def _startup_real(app: FastAPI, settings: Settings) -> None:
    """Migrations, demo users, then the integrator's hooks. Each step is guarded so one failing
    dependency (DB down, Anvil down) leaves the API answering `/health` instead of dead."""
    log.info("startup", extra={"mode": "db", "version": __version__})
    try:
        from athar.db.migrate import upgrade_head

        upgrade_head()
        log.info("migrations applied")
    except Exception as exc:
        log.error("migrations failed", extra={"exc_type": type(exc).__name__}, exc_info=exc)
    try:
        from athar.db.session import get_sessionmaker
        from athar.security.users import seed_users

        with get_sessionmaker()() as session:
            changed = seed_users(session, settings)
        log.info("demo users seeded", extra={"changed": changed})
    except Exception as exc:
        log.error("seeding users failed", extra={"exc_type": type(exc).__name__}, exc_info=exc)
    hooks: list[StartupHook] = list(app.state.startup_hooks)
    for hook in hooks:
        name = getattr(hook, "__name__", type(hook).__name__)
        try:
            hook(app)
            log.info("startup hook ok", extra={"hook": name})
        except Exception as exc:
            log.error(
                "startup hook failed", extra={"hook": name, "exc_type": type(exc).__name__}, exc_info=exc
            )
