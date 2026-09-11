"""The OpenAPI document IS the frontend contract (SPEC §13, §14, CLAUDE.md `make types`)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from _api_support import api_routes, client_as, make_app
from athar import __version__
from athar.api.app import API_PREFIX, DOCS_URL, OPENAPI_URL
from athar.config import APP_NAME
from fastapi.responses import Response
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

# Every row of SPEC §13, method by method.
SPEC_13 = {
    ("POST", "/auth/login"),
    ("POST", "/auth/logout"),
    ("GET", "/auth/me"),
    ("GET", "/estate/summary"),
    ("GET", "/identities"),
    ("GET", "/identities/{identity_id}"),
    ("GET", "/findings"),
    ("GET", "/findings/{finding_key}"),
    ("GET", "/departments/halflife"),
    ("GET", "/timeline"),
    ("POST", "/scan"),
    ("GET", "/scans"),
    ("GET", "/scans/{scan_id}"),
    ("POST", "/ingest/upload"),
    ("POST", "/simulate/advance"),
    ("POST", "/agent/investigate/{finding_key}"),
    ("POST", "/agent/plan/{finding_key}"),
    ("POST", "/agent/summary"),
    ("GET", "/remediation"),
    ("POST", "/remediation/{plan_id}/approve"),
    ("POST", "/remediation/{plan_id}/reject"),
    ("POST", "/remediation/{plan_id}/apply"),
    ("POST", "/findings/{finding_key}/exception"),
    ("GET", "/ledger/scans"),
    ("GET", "/ledger/scans/{scan_id}/verify"),
    ("GET", "/ledger/decisions"),
    ("GET", "/eval"),
    ("GET", "/export/findings.csv"),
    ("GET", "/export/findings.pdf"),
    ("GET", "/export/findings.json"),
    ("GET", "/settings"),
    ("PUT", "/settings"),
    ("GET", "/health"),
    ("GET", "/health/deps"),
}


@pytest.fixture(scope="module")
def app():
    return make_app()


@pytest.fixture(scope="module")
def spec(app) -> dict:
    return app.openapi()


def _api_routes(app) -> list[tuple[str, APIRoute]]:
    return [(path, r) for path, r in api_routes(app) if path.startswith(API_PREFIX)]


def test_openapi_and_docs_are_served_under_api(app, spec) -> None:
    client = TestClient(app)
    assert client.get(OPENAPI_URL).status_code == 200
    assert client.get(DOCS_URL).status_code == 200
    assert client.get("/docs").status_code == 404 and client.get("/redoc").status_code == 404
    assert client.get("/docs/oauth2-redirect").status_code == 404  # nothing lives outside /api
    assert spec["info"]["title"] == APP_NAME and spec["info"]["version"] == __version__


def test_every_spec_13_endpoint_exists(spec) -> None:
    present = {
        (method.upper(), path.removeprefix(API_PREFIX))
        for path, ops in spec["paths"].items()
        for method in ops
    }
    missing = SPEC_13 - present
    assert not missing, sorted(missing)
    assert all(path.startswith(API_PREFIX) for path in spec["paths"])


def test_operation_ids_are_function_names_and_unique(app, spec) -> None:
    routes = [r for _, r in _api_routes(app) if r.include_in_schema]
    assert routes, "route walker found nothing — FastAPI changed how included routers are stored"
    ids = [op["operationId"] for ops in spec["paths"].values() for op in ops.values()]
    assert len(ids) == len(set(ids)), "duplicate operation ids break `make types`"
    assert set(ids) == {r.name for r in routes}
    assert {
        "login",
        "logout",
        "me",
        "estate_summary",
        "list_identities",
        "identity_detail",
        "run_scan",
    } <= set(ids)


def test_every_route_declares_a_response_model_or_file_response(app) -> None:
    for path, route in _api_routes(app):
        if path.startswith(f"{API_PREFIX}/export/"):
            assert route.response_class is Response, path  # raw bytes + Content-Disposition
        else:
            assert route.response_model is not None, path


def test_every_operation_is_tagged_per_resource(spec) -> None:
    for path, ops in spec["paths"].items():
        for method, op in ops.items():
            assert op.get("tags"), (method, path)
            resource = path.removeprefix(API_PREFIX).strip("/").split("/")[0]
            expected = {"scan": "scans", "scans": "scans"}.get(resource, resource)
            assert op["tags"] == [expected], (method, path, op["tags"])


def test_problem_schema_and_enums_are_in_components(spec) -> None:
    schemas = spec["components"]["schemas"]
    for name in (
        "Problem",
        "EstateSummary",
        "IdentityRow",
        "IdentityDetail",
        "FindingOut",
        "RemediationPlanOut",
    ):
        assert name in schemas, name
    problem = schemas["Problem"]["properties"]
    assert {"type", "title", "status", "detail", "code", "instance"} <= set(problem)
    severity = schemas["FindingOut"]["properties"]["severity"]
    assert "enum" in severity or severity.get("$ref", "").endswith("/Severity"), severity


def test_mutating_operations_document_problem_responses(spec) -> None:
    for path, ops in spec["paths"].items():
        for method, op in ops.items():
            if method in ("post", "put") and "/health" not in path:
                assert "403" in op["responses"], (method, path)  # CSRF header check applies to all
                if op.get("requestBody") or op.get("parameters"):
                    assert "422" in op["responses"], (method, path)


def test_page_shape_on_every_list_endpoint(app) -> None:
    with client_as(app, "viewer") as client:
        for path in (
            "/identities",
            "/findings",
            "/scans",
            "/remediation",
            "/ledger/scans",
            "/ledger/decisions",
        ):
            body = client.get(f"/api/v1{path}?limit=2&offset=1").json()
            assert set(body) == {"items", "total", "limit", "offset"}, path
            assert body["limit"] == 2 and body["offset"] == 1 and len(body["items"]) <= 2, path
            assert body["total"] >= len(body["items"])


def test_health_is_public_because_the_compose_healthcheck_polls_it(app) -> None:
    health = TestClient(app).get("/api/v1/health").json()
    assert health == {"status": "ok", "app": APP_NAME, "version": __version__, "month": 12, "mock": True}


def test_health_deps_requires_a_viewer_session(app) -> None:
    """It names the LLM provider, model, key presence and chain id (SPEC §13 role column)."""
    anonymous = TestClient(app).get("/api/v1/health/deps")
    assert anonymous.status_code == 401
    assert anonymous.headers["content-type"].startswith("application/problem+json")
    assert anonymous.json()["code"] == "auth.required"
    with client_as(app, "viewer") as client:
        response = client.get("/api/v1/health/deps")
    assert response.status_code == 200
    deps = response.json()
    assert set(deps) == {"db", "anvil", "llm"}
    for row in deps.values():
        assert set(row) == {"ok", "detail"} and isinstance(row["ok"], bool)
        assert "http" not in row["detail"] and "key=" not in row["detail"]


def test_health_probes_never_reveal_urls_or_keys() -> None:
    from athar.api.routers.health import llm_status, probe_anvil
    from athar.config import Settings

    down = Settings(
        ATHAR_DEV=True,
        LEDGER_RPC_URL="http://127.0.0.1:9",
        LLM_PROVIDER="gemini",
        GEMINI_API_KEY="sk-super-secret",
    )
    anvil = probe_anvil(down)
    assert anvil.ok is False and "127.0.0.1" not in anvil.detail and "http" not in anvil.detail
    llm = llm_status(down)
    assert llm.ok is True and "present" in llm.detail and "sk-super-secret" not in llm.detail
    assert (
        llm_status(Settings(ATHAR_DEV=True, LLM_PROVIDER="gemini", GEMINI_API_KEY="", GOOGLE_API_KEY="")).ok
        is False
    )
    assert llm_status(Settings(ATHAR_DEV=True, LLM_PROVIDER="none")).ok is True
    assert probe_anvil(Settings(ATHAR_DEV=True, LEDGER_ENABLED=False)).ok is True
