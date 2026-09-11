"""Roles, separation of duties and state gates (SPEC §13 role column, §15.1, §10.3, §11.5)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from _api_support import CSRF, assert_problem, client_as, fresh_repo, make_app, reset_rate_limits
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def app():
    return make_app()


@pytest.fixture(autouse=True)
def _reset(app) -> None:
    reset_rate_limits(app)


@pytest.fixture
def repo(app):
    return fresh_repo(app)


def _plan(repo, status: str, proposer: str | None = None, proposed_by: str | None = None) -> str:
    for plan in repo.plans.values():
        if plan.status != status:
            continue
        if proposer is not None and plan.proposer_user_id != proposer:
            continue
        if proposed_by is not None and plan.proposed_by != proposed_by:
            continue
        return plan.plan_id
    raise AssertionError(f"mock has no {status} plan (proposer={proposer}, by={proposed_by})")


# ----------------------------------------------------------- reads and runs


def test_anonymous_reads_are_401(app) -> None:
    anon = TestClient(app)
    for path in ("/estate/summary", "/identities", "/findings", "/timeline", "/ledger/scans", "/eval"):
        assert_problem(anon.get(f"/api/v1{path}"), 401, "auth.required")


@pytest.mark.parametrize("role", ["viewer", "analyst", "approver"])
def test_every_role_can_read(app, role) -> None:
    with client_as(app, role) as client:
        for path in ("/estate/summary", "/identities?limit=1", "/findings?limit=1", "/departments/halflife"):
            assert client.get(f"/api/v1{path}").status_code == 200, path


def test_viewer_cannot_run_a_scan(app) -> None:
    with client_as(app, "viewer") as client:
        assert_problem(client.post("/api/v1/scan", headers=CSRF), 403, "rbac.role_required")


def test_analyst_and_approver_can_run_a_scan(app, repo) -> None:
    with client_as(app, "analyst") as analyst:
        response = analyst.post("/api/v1/scan", headers=CSRF, json={"month": 12})
        assert response.status_code == 200, response.text
        assert response.json()["ledger_status"] == "already_anchored"  # same snapshot, root, ruleset
    with client_as(app, "approver") as approver:
        assert approver.post("/api/v1/scan", headers=CSRF).status_code == 200


@pytest.mark.parametrize("path", ["/simulate/advance", "/agent/summary", "/ingest/upload"])
def test_viewer_cannot_run_analyst_actions(app, path) -> None:
    with client_as(app, "viewer") as client:
        assert_problem(client.post(f"/api/v1{path}", headers=CSRF), 403, "rbac.role_required")


def test_agent_endpoints_are_rate_limited_to_twenty_per_minute(app) -> None:
    with client_as(app, "analyst") as client:
        for _ in range(20):
            assert client.post("/api/v1/agent/summary", headers=CSRF).status_code == 200
        limited = client.post("/api/v1/agent/summary", headers=CSRF)
        assert_problem(limited, 429, "rate.limited")
        assert "retry-after" in limited.headers


# ------------------------------------------------------------- decisions


def test_analyst_cannot_decide(app, repo) -> None:
    plan_id = _plan(repo, "proposed", proposed_by="model")
    key = repo.plans[plan_id].finding_key
    with client_as(app, "analyst") as client:
        for path in (f"/remediation/{plan_id}/approve", f"/remediation/{plan_id}/apply"):
            assert_problem(client.post(f"/api/v1{path}", headers=CSRF), 403, "rbac.role_required")
        reject = client.post(f"/api/v1/remediation/{plan_id}/reject", headers=CSRF, json={"reason": "no"})
        assert_problem(reject, 403, "rbac.role_required")
        exc = client.post(
            f"/api/v1/findings/{key}/exception",
            headers=CSRF,
            json={"exception_type": "break-glass", "justification": "not allowed for analysts"},
        )
        assert_problem(exc, 403, "rbac.role_required")
    assert repo.plans[plan_id].status == "proposed"


def test_proposer_cannot_approve_their_own_plan(app, repo) -> None:
    plan_id = _plan(repo, "proposed", proposer="usr-approver")
    with client_as(app, "approver") as client:
        response = client.post(f"/api/v1/remediation/{plan_id}/approve", headers=CSRF)
        assert_problem(response, 403, "rbac.separation_of_duties")
    assert repo.plans[plan_id].status == "proposed"
    assert not any(d.plan_id == plan_id for d in repo.decisions)


def test_model_proposed_plan_can_be_approved_by_any_approver(app, repo) -> None:
    plan_id = _plan(repo, "proposed", proposed_by="model")
    with client_as(app, "approver") as client:
        response = client.post(f"/api/v1/remediation/{plan_id}/approve", headers=CSRF)
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["status"] == "approved"
        assert body["decisions"][-1]["decision"] == "approved"
        assert body["decisions"][-1]["actor_user_id"] == "usr-approver"
        assert body["decisions"][-1]["ledger_tx"]
        assert client.get(f"/api/v1/findings/{body['finding_key']}").json()["status"] == "approved"


def test_apply_requires_a_prior_approve(app, repo) -> None:
    proposed = _plan(repo, "proposed", proposed_by="model")
    with client_as(app, "approver") as client:
        response = client.post(f"/api/v1/remediation/{proposed}/apply", headers=CSRF)
        assert_problem(response, 409, "plan.invalid_state")
        approved = _plan(repo, "approved")
        applied = client.post(f"/api/v1/remediation/{approved}/apply", headers=CSRF)
        assert applied.status_code == 200, applied.text
        body = applied.json()
        assert body["plan"]["status"] == "applied"
        assert body["finding"]["status"] == "remediated"
        assert body["score_after"] <= body["score_before"]
        assert body["scan_id"] > 12  # apply re-scans
        assert body["plan"]["decisions"][-1]["decision"] == "remediation_applied"
        again = client.post(f"/api/v1/remediation/{approved}/apply", headers=CSRF)
        assert_problem(again, 409, "plan.invalid_state")


def test_reject_returns_the_finding_to_open(app, repo) -> None:
    plan_id = _plan(repo, "proposed", proposed_by="model")
    key = repo.plans[plan_id].finding_key
    with client_as(app, "approver") as client:
        response = client.post(
            f"/api/v1/remediation/{plan_id}/reject", headers=CSRF, json={"reason": "Access is still required"}
        )
        assert response.status_code == 200, response.text
        assert response.json()["status"] == "rejected"
        assert client.get(f"/api/v1/findings/{key}").json()["status"] == "open"
        applied = _plan(repo, "applied")
        assert_problem(
            client.post(f"/api/v1/remediation/{applied}/reject", headers=CSRF, json={"reason": "late"}),
            409,
            "plan.invalid_state",
        )
        missing = client.post("/api/v1/remediation/plan-9999/approve", headers=CSRF)
        assert_problem(missing, 404, "plan.not_found")


def test_reject_requires_a_reason(app, repo) -> None:
    plan_id = _plan(repo, "proposed", proposed_by="model")
    with client_as(app, "approver") as client:
        assert_problem(
            client.post(f"/api/v1/remediation/{plan_id}/reject", headers=CSRF, json={}),
            422,
            "validation.failed",
        )


def test_approver_can_grant_an_exception(app, repo) -> None:
    finding = next(f for f in repo.findings.values() if f.status == "open" and f.rule_id == "R1")
    with client_as(app, "approver") as client:
        response = client.post(
            f"/api/v1/findings/{finding.finding_key}/exception",
            headers=CSRF,
            json={
                "exception_type": "approved-privileged-role",
                "justification": "Sanctioned platform administrator, reviewed quarterly",
                "review_date": "2027-01-01",
            },
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["status"] == "exception_granted"
        assert body["exception"]["source"] == "workflow" and body["exception"]["valid"] is True
        assert body["exception"]["approved_by"] == "usr-approver"
    decision = repo.decisions[-1]
    assert decision.decision == "exception_granted" and decision.finding_key == finding.finding_key
    assert decision.ledger_tx


# --------------------------------------------------------------- settings


def test_settings_readable_by_viewer_but_not_writable(app) -> None:
    with client_as(app, "viewer") as client:
        assert client.get("/api/v1/settings").status_code == 200
        assert_problem(client.put("/api/v1/settings", headers=CSRF, json={"dormant_days": 60}), 403)


def test_analyst_may_change_thresholds_but_not_auto_remediation(app, repo) -> None:
    with client_as(app, "analyst") as client:
        ok = client.put(
            "/api/v1/settings", headers=CSRF, json={"dormant_days": 60, "approved_regions": ["uaenorth"]}
        )
        assert ok.status_code == 200, ok.text
        assert ok.json()["dormant_days"] == 60 and ok.json()["approved_regions"] == ["uaenorth"]
        assert ok.json()["updated_by"] == "usr-analyst"
        denied = client.put("/api/v1/settings", headers=CSRF, json={"auto_remediate_departed": True})
        assert_problem(denied, 403, "rbac.approver_required")
        assert client.get("/api/v1/settings").json()["auto_remediate_departed"] is False


def test_approver_may_toggle_auto_remediation(app, repo) -> None:
    with client_as(app, "approver") as client:
        response = client.put("/api/v1/settings", headers=CSRF, json={"auto_remediate_departed": True})
        assert response.status_code == 200, response.text
        assert response.json()["auto_remediate_departed"] is True
        assert response.json()["updated_by"] == "usr-approver"


def test_settings_rejects_unknown_fields_and_bad_values(app) -> None:
    with client_as(app, "approver") as client:
        assert_problem(client.put("/api/v1/settings", headers=CSRF, json={"jwt_secret": "x"}), 422)
        assert_problem(client.put("/api/v1/settings", headers=CSRF, json={"dormant_days": 0}), 422)
