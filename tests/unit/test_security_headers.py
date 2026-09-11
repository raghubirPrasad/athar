"""Security headers, CORS, request ids (SPEC §15.3) — asserted on every response class."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from _api_support import CSRF, client_as, make_app, reset_rate_limits
from fastapi.testclient import TestClient

REQUIRED = {
    "content-security-policy": "default-src 'self'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
}


@pytest.fixture(scope="module")
def app():
    return make_app()


@pytest.fixture(autouse=True)
def _reset(app) -> None:
    reset_rate_limits(app)


def _assert_headers(response) -> None:
    for name, expected in REQUIRED.items():
        assert expected in response.headers[name], (name, response.headers.get(name))
    assert response.headers["cache-control"] == "no-store"
    assert "strict-transport-security" not in response.headers
    assert len(response.headers["x-request-id"]) == 16


def test_headers_on_success_and_404(app) -> None:
    with client_as(app, "viewer") as client:
        _assert_headers(client.get("/api/v1/health"))
        _assert_headers(client.get("/api/v1/estate/summary"))
        _assert_headers(client.get("/api/v1/does-not-exist"))


def test_headers_on_401_403_csrf_and_422(app) -> None:
    anon = TestClient(app)
    _assert_headers(anon.get("/api/v1/auth/me"))
    _assert_headers(anon.post("/api/v1/auth/logout"))  # no CSRF header → 403 from middleware
    with client_as(app, "viewer") as client:
        _assert_headers(client.get("/api/v1/identities?limit=9999"))


def test_headers_on_429_and_500(app) -> None:
    anon = TestClient(app)
    for _ in range(5):
        anon.post("/api/v1/auth/login", json={"email": "x@athar.local", "password": "x"}, headers=CSRF)
    limited = anon.post("/api/v1/auth/login", json={"email": "x@athar.local", "password": "x"}, headers=CSRF)
    assert limited.status_code == 429
    _assert_headers(limited)
    with client_as(app, "viewer") as client:
        crashed = client.get("/api/v1/debug/raise")
        assert crashed.status_code == 500
        _assert_headers(crashed)


def test_docs_get_a_relaxed_csp_for_swagger_only(app) -> None:
    client = TestClient(app)
    docs = client.get("/api/docs")
    assert docs.status_code == 200
    assert "cdn.jsdelivr.net" in docs.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in docs.headers["content-security-policy"]
    spec = client.get("/api/openapi.json")
    assert spec.status_code == 200
    api = client.get("/api/v1/health")
    assert "cdn.jsdelivr.net" not in api.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in api.headers["content-security-policy"]


def test_hsts_only_when_cookie_secure() -> None:
    secure = make_app(COOKIE_SECURE=True)
    response = TestClient(secure).get("/api/v1/health")
    assert response.headers["strict-transport-security"].startswith("max-age=31536000")


def test_cors_restricted_to_public_url(app) -> None:
    client = TestClient(app)
    headers = {"Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "X-Requested-With"}
    ok = client.options("/api/v1/scan", headers={"Origin": "http://localhost:8080", **headers})
    assert ok.status_code == 200
    assert ok.headers["access-control-allow-origin"] == "http://localhost:8080"
    assert ok.headers["access-control-allow-credentials"] == "true"
    assert "x-requested-with" in ok.headers["access-control-allow-headers"].lower()
    other = client.options("/api/v1/scan", headers={"Origin": "https://evil.example", **headers})
    assert "access-control-allow-origin" not in other.headers
    assert other.status_code in (400, 403)


def test_request_id_matches_problem_instance(app) -> None:
    response = TestClient(app).get("/api/v1/auth/me")
    assert response.status_code == 401
    assert response.json()["instance"] == f"urn:athar:request:{response.headers['x-request-id']}"
