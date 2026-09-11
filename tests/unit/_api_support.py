"""Lane C helpers for the API / security tests. Not a test module.

Builds the app in mock mode (`ATHAR_API_MOCK=true`) with explicit Settings so nothing leaks
into other lanes' tests through the environment. Role clients mint a session cookie directly
(no argon2 round trip, no login rate-limit tokens consumed); the login tests exercise the
real `/auth/login` path.
"""

from __future__ import annotations

from typing import Any

from athar.api.app import create_app
from athar.api.mock import MockRepo
from athar.config import Settings
from athar.security.auth import COOKIE_NAME, AuthUser, Role, create_token
from athar.security.users import demo_users
from fastapi import FastAPI
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

CSRF = {"X-Requested-With": "athar"}
TEST_JWT_SECRET = "unit-test-secret-that-is-long-enough-for-hs256-0123456789"
PROBLEM = "application/problem+json"


def make_settings(**overrides: Any) -> Settings:
    base: dict[str, Any] = dict(
        ATHAR_API_MOCK=True,
        ATHAR_DEV=True,
        LLM_PROVIDER="none",
        LEDGER_ENABLED=True,
        JWT_SECRET=TEST_JWT_SECRET,
        PUBLIC_URL="http://localhost:8080",
        COOKIE_SECURE=False,
    )
    base.update(overrides)
    return Settings(**base)


def make_app(settings: Settings | None = None, **overrides: Any) -> FastAPI:
    return create_app(settings or make_settings(**overrides))


def api_routes(app: FastAPI) -> list[tuple[str, APIRoute]]:
    """(full path, route) for every APIRoute. FastAPI ≥ 0.13x keeps included routers lazy
    (`_IncludedRouter` wrappers in `app.routes`), so a plain isinstance filter finds nothing."""
    out: list[tuple[str, APIRoute]] = []
    for entry in app.routes:
        if isinstance(entry, APIRoute):
            out.append((entry.path, entry))
            continue
        inner = getattr(entry, "original_router", None)
        if inner is None:
            continue
        prefix = getattr(getattr(entry, "include_context", None), "prefix", "")
        out.extend((prefix + r.path, r) for r in inner.routes if isinstance(r, APIRoute))
    return out


def reset_rate_limits(app: FastAPI) -> None:
    for rule in app.state.rate_limit_rules:
        rule.bucket.reset()


def fresh_repo(app: FastAPI) -> MockRepo:
    """Replace the shared mock dataset so mutation tests do not depend on ordering."""
    repo = MockRepo(app.state.settings)
    app.state.mock_repo = repo
    return repo


def credentials(settings: Settings, role: Role) -> tuple[str, str]:
    user = next(u for u in demo_users(settings) if u.role == role)
    return user.email, user.password


def auth_user(settings: Settings, role: Role) -> AuthUser:
    user = next(u for u in demo_users(settings) if u.role == role)
    return AuthUser(user_id=user.user_id, email=user.email, role=user.role)


def client_as(app: FastAPI, role: Role) -> TestClient:
    """A client carrying a valid session cookie for the demo user with `role`."""
    settings: Settings = app.state.settings
    client = TestClient(app)
    client.cookies.set(COOKIE_NAME, create_token(auth_user(settings, role), settings))
    return client


def login(client: TestClient, settings: Settings, role: Role, password: str | None = None) -> Any:
    email, real_password = credentials(settings, role)
    return client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password if password is not None else real_password},
        headers=CSRF,
    )


def assert_problem(response: Any, status: int, code: str | None = None) -> dict[str, Any]:
    assert response.status_code == status, response.text
    assert response.headers["content-type"].startswith(PROBLEM), response.headers["content-type"]
    body = response.json()
    assert body["status"] == status
    assert body["title"]
    assert body["type"].startswith("urn:athar:problem:")
    if code is not None:
        assert body["code"] == code, body
    text = response.text
    assert "Traceback" not in text
    assert "/Users/" not in text and "/backend/" not in text and ".py" not in text
    return body
