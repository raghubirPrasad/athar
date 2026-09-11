"""Error contract: RFC 7807 everywhere, CSRF, limits, catch-all (SPEC §13, §15.2, §15.3)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from _api_support import (
    CSRF,
    PROBLEM,
    api_routes,
    assert_problem,
    client_as,
    make_app,
    make_settings,
    reset_rate_limits,
)
from athar.api.problem import problem_response
from athar.security.auth import COOKIE_NAME, create_token
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def app():
    return make_app()


@pytest.fixture(autouse=True)
def _reset(app) -> None:
    reset_rate_limits(app)


def test_404_is_problem_json(app) -> None:
    with client_as(app, "viewer") as client:
        assert_problem(client.get("/api/v1/nothing-here"), 404, "not_found")
        assert_problem(client.get("/api/v1/identities/does-not-exist"), 404, "identity.not_found")
        assert_problem(client.get(f"/api/v1/findings/{'0' * 32}"), 404, "finding.not_found")
        assert_problem(client.get("/api/v1/scans/999"), 404, "scan.not_found")
        assert_problem(client.get("/api/v1/ledger/scans/999/verify"), 404, "scan.not_found")


def test_405_is_problem_json(app) -> None:
    with client_as(app, "viewer") as client:
        assert_problem(client.delete("/api/v1/estate/summary", headers=CSRF), 405)


def test_500_is_problem_json_without_trace_or_path(app) -> None:
    with client_as(app, "viewer") as client:
        response = client.get("/api/v1/debug/raise")
        body = assert_problem(response, 500, "internal.error")
        assert body["detail"] == "Internal error"
        assert "deliberate" not in response.text and "secret" not in response.text
        assert body["instance"].startswith("urn:athar:request:")


def test_debug_route_only_exists_in_mock_mode(app) -> None:
    assert any(path.startswith("/api/v1/debug") for path, _ in api_routes(app))
    real = make_app(ATHAR_API_MOCK=False)
    assert not any(path.startswith("/api/v1/debug") for path, _ in api_routes(real))
    settings = real.state.settings
    client = TestClient(real)
    client.cookies.set(COOKIE_NAME, create_token(_viewer(), settings))
    assert_problem(client.get("/api/v1/debug/raise"), 404, "not_found")


def _viewer():
    from athar.security.auth import AuthUser

    return AuthUser(user_id="usr-judge", email="judge@athar.local", role="viewer")


def test_data_routes_answer_503_until_services_are_wired() -> None:
    real = make_app(ATHAR_API_MOCK=False)
    client = TestClient(real)
    client.cookies.set(COOKIE_NAME, create_token(_viewer(), real.state.settings))
    assert_problem(client.get("/api/v1/estate/summary"), 503, "services.not_wired")
    health = client.get("/api/v1/health")
    assert health.status_code == 200 and health.json()["month"] is None and health.json()["mock"] is False


def test_repo_factory_is_used_when_installed() -> None:
    real = make_app(ATHAR_API_MOCK=False)
    from athar.api.mock import MockRepo

    calls: list[int] = []

    def factory():
        calls.append(1)
        return MockRepo(real.state.settings)

    real.state.repo_factory = factory
    client = TestClient(real)
    client.cookies.set(COOKIE_NAME, create_token(_viewer(), real.state.settings))
    assert client.get("/api/v1/estate/summary").status_code == 200
    assert calls == [1]


@pytest.mark.parametrize("method,path", [("post", "/api/v1/scan"), ("put", "/api/v1/settings")])
def test_mutating_request_without_csrf_header_is_403(app, method, path) -> None:
    with client_as(app, "approver") as client:
        response = getattr(client, method)(path, json={})
        assert_problem(response, 403, "csrf.header_missing")


def test_csrf_header_with_wrong_value_is_403(app) -> None:
    with client_as(app, "approver") as client:
        response = client.post("/api/v1/scan", headers={"X-Requested-With": "XMLHttpRequest"})
        assert_problem(response, 403, "csrf.header_missing")


def test_csrf_header_value_is_case_insensitive_and_gets_are_exempt(app) -> None:
    with client_as(app, "approver") as client:
        assert client.post("/api/v1/scan", headers={"X-Requested-With": "ATHAR"}).status_code == 200
        assert client.get("/api/v1/estate/summary").status_code == 200


def test_pagination_limit_over_500_is_422_problem(app) -> None:
    with client_as(app, "viewer") as client:
        body = assert_problem(client.get("/api/v1/identities?limit=501"), 422, "validation.failed")
        assert body["errors"][0]["loc"] == ["query", "limit"]
        assert_problem(client.get("/api/v1/findings?limit=0"), 422, "validation.failed")
        assert_problem(client.get("/api/v1/findings?offset=-1"), 422, "validation.failed")
        assert client.get("/api/v1/findings?limit=500").status_code == 200


def test_unknown_filter_values_are_422(app) -> None:
    with client_as(app, "viewer") as client:
        assert_problem(client.get("/api/v1/identities?cloud=oci"), 422, "validation.failed")
        assert_problem(client.get("/api/v1/findings?severity=Extreme"), 422, "validation.failed")
        assert_problem(client.get("/api/v1/findings?rule=R99"), 422, "validation.failed")
        assert_problem(client.get("/api/v1/findings?bogus=1"), 422, "validation.failed")
        assert_problem(client.get("/api/v1/findings?sort=score;drop"), 422, "validation.failed")
        assert_problem(client.get("/api/v1/findings?sort=unknown_field"), 422, "sort.unknown_field")


def test_validation_errors_never_echo_input(app) -> None:
    with client_as(app, "approver") as client:
        response = client.put("/api/v1/settings", headers=CSRF, json={"dormant_days": "SECRET-VALUE"})
        body = assert_problem(response, 422, "validation.failed")
        assert "SECRET-VALUE" not in response.text
        assert all("input" not in err and "url" not in err and "ctx" not in err for err in body["errors"])


def test_oversized_body_is_413_problem() -> None:
    small = make_app(MAX_UPLOAD_BYTES=16)
    with client_as(small, "analyst") as client:
        too_big = b"x" * (16 + 1024 * 1024 + 1)
        response = client.post(
            "/api/v1/scan", headers={**CSRF, "Content-Type": "application/json"}, content=too_big
        )
        assert_problem(response, 413, "request.too_large")


def test_upload_file_over_per_file_limit_is_413() -> None:
    small = make_app(MAX_UPLOAD_BYTES=16)
    with client_as(small, "analyst") as client:
        response = client.post(
            "/api/v1/ingest/upload",
            headers=CSRF,
            data={"provider": "aws", "month": "12"},
            files={"files": ("authorization-details.json", b"{" + b" " * 40 + b"}", "application/json")},
        )
        assert_problem(response, 413, "request.too_large")


def test_upload_rejects_bad_provider_and_month(app) -> None:
    with client_as(app, "analyst") as client:
        bad = client.post(
            "/api/v1/ingest/upload",
            headers=CSRF,
            data={"provider": "oci", "month": "12"},
            files={"files": ("x.json", b"{}", "application/json")},
        )
        assert_problem(bad, 422, "validation.failed")
        bad_month = client.post(
            "/api/v1/ingest/upload",
            headers=CSRF,
            data={"provider": "aws", "month": "0"},
            files={"files": ("x.json", b"{}", "application/json")},
        )
        assert_problem(bad_month, 422, "validation.failed")


def test_problem_response_helper_shape() -> None:
    response = problem_response(409, "plan.invalid_state", detail="d", headers={"Retry-After": "3"})
    assert response.status_code == 409
    assert response.media_type == PROBLEM
    assert response.headers["retry-after"] == "3"
    assert b'"code":"plan.invalid_state"' in response.body
    assert b"errors" not in response.body  # exclude_none keeps the payload minimal


def test_settings_refuse_example_secret_outside_dev() -> None:
    from athar.config import EXAMPLE_JWT_SECRET

    with pytest.raises(RuntimeError):
        make_app(make_settings(JWT_SECRET=EXAMPLE_JWT_SECRET, ATHAR_DEV=False))
    make_app(make_settings(JWT_SECRET=EXAMPLE_JWT_SECRET, ATHAR_DEV=True))  # allowed in dev
