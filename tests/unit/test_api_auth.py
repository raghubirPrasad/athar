"""`/auth/*` through the real app in mock mode (SPEC §13, §15.1, §15.3)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from _api_support import CSRF, assert_problem, login, make_app, reset_rate_limits
from athar.security.auth import COOKIE_NAME
from fastapi.testclient import TestClient

CSRF_FROM_198_0 = {**CSRF, "X-Forwarded-For": "198.51.100.1"}


@pytest.fixture(scope="module")
def app():
    return make_app()


@pytest.fixture(scope="module")
def settings(app):
    return app.state.settings


@pytest.fixture(autouse=True)
def _reset(app) -> None:
    reset_rate_limits(app)


def test_login_sets_httponly_cookie_and_never_returns_the_token(app, settings) -> None:
    with TestClient(app) as client:
        response = login(client, settings, "analyst")
        assert response.status_code == 200, response.text
        assert response.json() == {
            "user_id": "usr-analyst",
            "email": "analyst@athar.local",
            "role": "analyst",
        }
        cookie = response.headers["set-cookie"].lower()
        assert cookie.startswith(f"{COOKIE_NAME}=")
        assert "httponly" in cookie and "samesite=strict" in cookie and "path=/" in cookie
        token = client.cookies.get(COOKIE_NAME)
        assert token and token.count(".") == 2
        assert token not in response.text
        assert "token" not in response.json()


def test_login_wrong_password_is_401_problem(app, settings) -> None:
    with TestClient(app) as client:
        body = assert_problem(
            login(client, settings, "analyst", password="wrong"), 401, "auth.invalid_credentials"
        )
        assert COOKIE_NAME not in client.cookies
        assert "set-cookie" not in body


def test_login_unknown_email_uses_the_same_problem_code(app, settings) -> None:
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/auth/login", json={"email": "ghost@athar.local", "password": "whatever"}, headers=CSRF
        )
        assert_problem(response, 401, "auth.invalid_credentials")


def test_login_is_rate_limited_to_five_per_minute(app, settings) -> None:
    with TestClient(app) as client:
        for _ in range(5):
            assert login(client, settings, "viewer", password="bad").status_code == 401
        sixth = login(client, settings, "viewer")  # even the right password is refused now
        body = assert_problem(sixth, 429, "rate.limited")
        assert int(sixth.headers["retry-after"]) >= 1
        assert "detail" in body
        assert COOKIE_NAME not in client.cookies


def test_rotating_x_forwarded_for_does_not_buy_more_login_attempts(app, settings) -> None:
    """Regression: the header is ignored unless TRUSTED_PROXY_CIDRS names the peer (SPEC §15.3)."""
    with TestClient(app) as client:
        for i in range(5):
            response = login(client, settings, "viewer", password="bad")
            assert response.status_code == 401, i
        for i in range(3):
            forged = client.post(
                "/api/v1/auth/login",
                json={"email": "approver@athar.local", "password": f"guess-{i}"},
                headers={**CSRF, "X-Forwarded-For": f"198.51.100.{i}"},
            )
            assert_problem(forged, 429, "rate.limited")


def test_a_declared_proxy_gets_one_bucket_per_forwarded_client() -> None:
    """The compose topology: without this every browser would share one login bucket."""
    proxied = make_app(TRUSTED_PROXY_CIDRS="172.20.0.0/16")
    body = {"email": "approver@athar.local", "password": "wrong"}
    with TestClient(proxied, client=("172.20.0.5", 40000)) as client:
        for _ in range(5):
            assert client.post("/api/v1/auth/login", json=body, headers=CSRF_FROM_198_0).status_code == 401
        assert_problem(client.post("/api/v1/auth/login", json=body, headers=CSRF_FROM_198_0), 429)
        other = {**CSRF, "X-Forwarded-For": "198.51.100.7"}
        assert client.post("/api/v1/auth/login", json=body, headers=other).status_code == 401


def test_login_validation_error_is_422_problem(app) -> None:
    with TestClient(app) as client:
        response = client.post("/api/v1/auth/login", json={"email": "analyst@athar.local"}, headers=CSRF)
        body = assert_problem(response, 422, "validation.failed")
        assert body["errors"] and body["errors"][0]["loc"] == ["body", "password"]
        assert all(set(err) == {"loc", "msg", "type"} for err in body["errors"])


def test_login_without_csrf_header_is_403(app, settings) -> None:
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/auth/login",
            json={"email": "analyst@athar.local", "password": settings.demo_analyst_password},
        )
        assert_problem(response, 403, "csrf.header_missing")


def test_me_requires_a_session(app) -> None:
    assert_problem(TestClient(app).get("/api/v1/auth/me"), 401, "auth.required")


def test_me_returns_the_cookie_user(app, settings) -> None:
    with TestClient(app) as client:
        login(client, settings, "approver")
        response = client.get("/api/v1/auth/me")
        assert response.status_code == 200
        assert response.json() == {
            "user_id": "usr-approver",
            "email": "approver@athar.local",
            "role": "approver",
        }


def test_logout_clears_the_cookie(app, settings) -> None:
    with TestClient(app) as client:
        login(client, settings, "viewer")
        assert client.get("/api/v1/auth/me").status_code == 200
        response = client.post("/api/v1/auth/logout", headers=CSRF)
        assert response.status_code == 200 and response.json() == {"logged_out": True}
        assert "max-age=0" in response.headers["set-cookie"].lower()
        assert COOKIE_NAME not in client.cookies
        assert client.get("/api/v1/auth/me").status_code == 401


def test_tampered_cookie_is_rejected(app, settings) -> None:
    with TestClient(app) as client:
        login(client, settings, "viewer")
        token = client.cookies.get(COOKIE_NAME)
        assert token
        client.cookies.set(COOKIE_NAME, token[:-2] + "xx")
        assert_problem(client.get("/api/v1/auth/me"), 401, "auth.required")
        client.cookies.set(COOKIE_NAME, "garbage")
        assert_problem(client.get("/api/v1/estate/summary"), 401, "auth.required")
