"""MockRepo: deterministic dataset with everything SPEC §14 pages need, and the full flows."""

from __future__ import annotations

import csv
import io
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from _api_support import (
    CSRF,
    assert_problem,
    client_as,
    fresh_repo,
    make_app,
    make_settings,
    reset_rate_limits,
)
from athar.api.mock import EXPORT_COLUMNS, MockRepo
from athar.hashing import finding_key, instance_hash
from athar.ledger import merkle

RULES = [f"R{n}" for n in range(11)]
SPEC_16_COLUMNS = [
    "finding_key",
    "identity_id",
    "display_name",
    "identity_type",
    "department",
    "clouds",
    "rule_id",
    "rule_name",
    "severity",
    "risk_score",
    "blast_radius_pct",
    "first_seen_month",
    "causal_trigger",
    "plain_english_finding",
    "recommended_action",
    "attack_technique",
    "control_ref",
    "status",
    "instance_hash",
    "scan_id",
    "merkle_root",
    "ledger_tx",
]


@pytest.fixture(scope="module")
def app():
    return make_app()


@pytest.fixture(autouse=True)
def _reset(app) -> None:
    reset_rate_limits(app)


@pytest.fixture
def repo(app) -> MockRepo:
    return fresh_repo(app)


# --------------------------------------------------------------- dataset


def test_mock_is_deterministic_across_instances() -> None:
    settings = make_settings()
    a, b = MockRepo(settings), MockRepo(settings)
    assert a.estate_summary().model_dump_json() == b.estate_summary().model_dump_json()
    assert [f.model_dump_json() for f in a.findings.values()] == [
        f.model_dump_json() for f in b.findings.values()
    ]
    assert a.identity_detail("emp-0001") == b.identity_detail("emp-0001")
    assert a.timeline() == b.timeline() and a.eval_result() == b.eval_result()
    assert [s.ledger_tx for s in a.scans] == [s.ledger_tx for s in b.scans]


def test_dataset_size_and_coverage(repo) -> None:
    assert len(repo.identities) >= 40
    assert {i.department for i in repo.identities.values()} == set(repo.timeline_points[0].half_life)
    assert len({i.department for i in repo.identities.values()}) == 8
    assert {c for i in repo.identities.values() for c in i.clouds} == {"aws", "azure", "gcp"}
    assert {i.identity_type for i in repo.identities.values()} == {"human", "service"}
    assert 40 <= len(repo.findings) <= 80
    assert {f.rule_id for f in repo.findings.values()} == set(RULES)
    assert len(repo.scans) == 12 and len(repo.timeline_points) == 12
    assert len(repo.halflife_rows) >= 8 and len(repo.plans) >= 3 and len(repo.decisions) >= 3
    assert all("@nda.example" in i.tags.get("owner", "@nda.example") for i in repo.identities.values())
    assert not any("gov.ae" in json.dumps(i.tags) for i in repo.identities.values())


def test_summary_carries_the_overview_page(app) -> None:
    with client_as(app, "viewer") as client:
        body = client.get("/api/v1/estate/summary").json()
    assert body["current_month"] == 12 and body["current_month_label"] == "August 2026"
    assert body["identity_count"] == body["humans"] + body["services"]
    assert set(body["findings_by_severity"]) == {"Low", "Medium", "High", "Critical"}
    assert sum(body["findings_by_severity"].values()) == body["findings_total"]
    assert set(body["findings_by_cloud"]) == {"aws", "azure", "gcp"}
    rollups = body["findings_by_department"]
    assert len(rollups) == 8
    finance = next(r for r in rollups if r["department"] == "Finance")
    assert finance["offboarding_half_life"] is None and finance["half_life_label"] == "Broken"  # "Never"
    assert body["ledger"]["status"] == "anchored" and body["ledger"]["chain_id"] == 31337
    assert body["ledger"]["last_root"].startswith("0x") and body["ledger"]["last_tx"].startswith("0x")
    assert body["executive_summary"] and "identities" in body["executive_summary"]
    assert body["scan_id"] == 12


def test_ledger_badge_disabled_when_ledger_off() -> None:
    repo = MockRepo(make_settings(LEDGER_ENABLED=False))
    assert repo.estate_summary().ledger.status == "disabled"
    assert repo.ledger_info().enabled is False


def test_identity_rows_and_filters(app) -> None:
    with client_as(app, "viewer") as client:
        page = client.get("/api/v1/identities?limit=500").json()
        assert page["total"] == len(page["items"]) >= 40
        row = page["items"][0]
        assert {
            "identity_id", "display_name", "identity_type", "department", "clouds", "score", "severity", "top_rule",
            "top_rule_name", "blast_radius_pct", "last_activity_at", "status", "finding_count", "external",
            "mfa_enforced",
        } <= set(row)  # fmt: skip
        scores = [r["score"] for r in page["items"]]
        assert scores == sorted(scores, reverse=True)  # default sort -score
        asc = client.get("/api/v1/identities?sort=score&limit=500").json()["items"]
        assert [r["score"] for r in asc] == sorted(scores)
        aws = client.get("/api/v1/identities?cloud=aws&limit=500").json()["items"]
        assert aws and all("aws" in r["clouds"] for r in aws)
        finance = client.get("/api/v1/identities?department=finance&limit=500").json()["items"]
        assert finance and all(r["department"] == "Finance" for r in finance)
        r3 = client.get("/api/v1/identities?rule=R3&limit=500").json()["items"]
        assert r3 and all(r["status"] == "departed" for r in r3)
        crit = client.get("/api/v1/identities?severity=Critical&limit=500").json()["items"]
        assert crit and all(r["severity"] == "Critical" for r in crit)
        q = client.get(f"/api/v1/identities?q={row['display_name'].split()[0]}").json()["items"]
        assert any(r["identity_id"] == row["identity_id"] for r in q)
        assert client.get("/api/v1/identities?q=zzzz-nobody").json() == {
            "items": [],
            "total": 0,
            "limit": 100,
            "offset": 0,
        }


def test_identity_detail_carries_the_drilldown(app, repo) -> None:
    departed = next(i for i in repo.identities.values() if "R3" in i.rules)
    with client_as(app, "viewer") as client:
        body = client.get(f"/api/v1/identities/{departed.identity_id}").json()
    assert body["employment_status"] == "departed" and body["departure_month"]
    grant = body["grants"][0]
    assert grant["raw_snippet"] and grant["source_file"] and grant["source_pointer"].startswith("/")
    assert grant["granted_via"] and grant["effect"] == "allow"
    assert body["activity"] and {"cloud", "service_category", "last_activity_at", "operation_count"} <= set(
        body["activity"][0]
    )
    score = body["score"]
    assert score["score"] == body["findings"][0]["score"]
    terms = [li["term"] for li in score["line_items"]]
    assert terms == ["reach", "exploitability", "compensating", "formula", "floor", "final"]
    assert any("departed" in li["label"] for li in score["line_items"])
    assert len(body["risk_history"]) == 12 and body["risk_history"][-1]["score"] == score["score"]
    assert any(p["events"] for p in body["risk_history"])
    assert body["causal_history"] and body["causal_history"][0]["description"]
    assert (
        body["altitudes"]["headline"] and body["altitudes"]["explanation"] and body["altitudes"]["evidence"]
    )
    assert body["top_finding_key"] == body["findings"][0]["finding_key"]
    assert body["principals"] and {"link_method", "link_confidence"} <= set(body["principals"][0])
    assert body["tags"]  # displayed as evidence only


def test_privileged_identity_has_escalation_paths_and_valid_exception(app, repo) -> None:
    with client_as(app, "viewer") as client:
        body = client.get("/api/v1/identities/emp-0006").json()  # break-glass decoy from the register
    assert body["score"]["escalation_paths"] and len(body["score"]["escalation_paths"][0]) == 3
    edge = body["score"]["escalation_paths"][0][0]
    assert {"src", "verb", "dst", "grant_id"} == set(edge) and edge["grant_id"]
    assert body["exceptions"] and body["exceptions"][0]["valid"] is True
    assert body["exceptions"][0]["source"] == "register"
    assert not any(f["rule_id"] == "R1" for f in body["findings"])  # register suppresses; tags never do
    expired = client.get("/api/v1/identities/emp-0023").json()
    assert expired["exceptions"] and expired["exceptions"][0]["valid"] is False


def test_findings_carry_evidence_leaf_and_verifiable_proof(app, repo) -> None:
    root = merkle.from_hex(repo.scans[-1].merkle_root)
    with client_as(app, "viewer") as client:
        page = client.get("/api/v1/findings?limit=500").json()
        assert page["total"] == len(repo.findings)
        for f in page["items"]:
            assert f["evidence_refs"], f["finding_key"]  # evidence or it did not fire
            assert f["finding_key"] == finding_key(f["identity_id"], f["rule_id"])
            assert f["instance_hash"] == instance_hash(f["facts"]["instance"])
            assert f["leaf"] == merkle.to_hex(merkle.leaf_from_instance_hash(f["instance_hash"]))
            assert merkle.verify(root, merkle.from_hex(f["leaf"]), [merkle.from_hex(p) for p in f["proof"]])
            assert f["allowed_actions"] and f["altitudes"]["headline"]
            assert f["altitudes"]["evidence"]["ledger"]["merkle_root"] == repo.scans[-1].merkle_root
        one = client.get(f"/api/v1/findings/{page['items'][0]['finding_key']}").json()
        assert one == page["items"][0]
        assert {f["rule_id"] for f in page["items"]} == set(RULES)
        for rule in RULES:
            rows = client.get(f"/api/v1/findings?rule={rule}").json()["items"]
            assert rows and all(r["rule_id"] == rule for r in rows) and all(r["rule_name"] for r in rows)
        month = client.get("/api/v1/findings?month=11").json()
        assert month["total"] == 0
        statuses = {f["status"] for f in page["items"]}
        assert {
            "open",
            "remediation_proposed",
            "approved",
            "remediated",
            "investigated",
            "exception_granted",
        } <= statuses


def test_finding_statuses_align_with_plans_and_investigations(repo) -> None:
    for plan in repo.plans.values():
        finding = repo.findings[plan.finding_key]
        assert finding.plan is plan
        expected = {
            "proposed": "remediation_proposed",
            "approved": "approved",
            "applied": "remediated",
            "rejected": "open",
        }
        assert finding.status == expected[plan.status], plan.plan_id
    assert any(f.investigation is not None and f.investigation.cached for f in repo.findings.values())
    sod = [p for p in repo.plans.values() if p.status == "proposed" and p.proposer_user_id == "usr-approver"]
    assert sod, "the mock must include a plan proposed by the approver so SoD can be exercised"


def test_halflife_timeline_and_eval(app) -> None:
    with client_as(app, "viewer") as client:
        hl = client.get("/api/v1/departments/halflife").json()
        assert hl["month"] == 12 and len(hl["rows"]) == 24
        assert {r["label"] for r in hl["rows"]} <= {"Healthy", "Slow", "Broken"}
        assert any(r["half_life_months"] is None and r["label"] == "Broken" for r in hl["rows"])
        tl = client.get("/api/v1/timeline").json()
        assert tl["current_month"] == 12 and [p["month"] for p in tl["points"]] == list(range(1, 13))
        assert tl["points"][0]["month_label"] == "September 2025"
        assert set(tl["points"][-1]["half_life"]) == {r["department"] for r in hl["rows"]}
        ev = client.get("/api/v1/eval").json()
        # The mock reports whatever ATHAR_EVAL_SEED is configured, so the assertion reads the
        # setting rather than a literal: a developer who changes the held-out seed in `.env` must
        # not find an unrelated test failing on it.
        from athar.config import get_settings

        assert ev["held_out"] is True and ev["seed"] == get_settings().athar_eval_seed
        assert ev["threshold"] == "High+"
        assert 0 < ev["precision"] <= 1 and 0 < ev["recall"] <= 1 and 0 < ev["f1"] <= 1
        assert len(ev["per_rule"]) == 10 and ev["decoys"]
        assert all(d["why_legitimate"] and d["looks_like"] for d in ev["decoys"])
        assert all(d["correctly_handled"] for d in ev["decoys"])
        assert "precision" in ev["engineer_sentence"] and "flagged" in ev["director_sentence"]


# ------------------------------------------------------------------ flows


def test_investigate_is_cached_until_regenerate(app, repo) -> None:
    key = next(
        f.finding_key for f in repo.findings.values() if f.investigation is None and f.status == "open"
    )
    with client_as(app, "analyst") as client:
        first = client.post(f"/api/v1/agent/investigate/{key}", headers=CSRF).json()
        assert first["cached"] is False and first["generated_by"] == "template"
        assert first["recommended_action"] in repo.findings[key].allowed_actions
        assert client.get(f"/api/v1/findings/{key}").json()["status"] == "investigated"
        second = client.post(f"/api/v1/agent/investigate/{key}", headers=CSRF).json()
        assert second["cached"] is True and second["hypothesis"] == first["hypothesis"]
        third = client.post(f"/api/v1/agent/investigate/{key}?regenerate=true", headers=CSRF).json()
        assert third["cached"] is False
        assert_problem(
            client.post(f"/api/v1/agent/investigate/{'f' * 32}", headers=CSRF), 404, "finding.not_found"
        )


def test_plan_then_full_decision_flow(app, repo) -> None:
    key = next(f.finding_key for f in repo.findings.values() if f.plan is None and f.rule_id == "R1")
    with client_as(app, "analyst") as analyst:
        plan = analyst.post(f"/api/v1/agent/plan/{key}", headers=CSRF).json()
        assert plan["status"] == "proposed" and plan["proposed_by"] == "rule"
        assert plan["proposer_user_id"] == "usr-analyst"
        assert plan["drop"] and set(plan["drop"]).isdisjoint(plan["keep"])
        assert 0 < plan["privilege_reduction_pct"] <= 100
        diff = plan["policy_diff"]
        assert diff["before"] != diff["after"] and diff["operations"][0]["op"] and diff["summary"]
        assert analyst.get(f"/api/v1/findings/{key}").json()["status"] == "remediation_proposed"
        assert analyst.post(f"/api/v1/agent/plan/{key}", headers=CSRF).json()["plan_id"] == plan["plan_id"]
    with client_as(app, "approver") as approver:
        queue = approver.get("/api/v1/remediation?status=proposed").json()
        assert any(p["plan_id"] == plan["plan_id"] for p in queue["items"])
        approved = approver.post(f"/api/v1/remediation/{plan['plan_id']}/approve", headers=CSRF).json()
        assert approved["status"] == "approved"
        applied = approver.post(f"/api/v1/remediation/{plan['plan_id']}/apply", headers=CSRF).json()
        assert applied["plan"]["status"] == "applied" and applied["finding"]["status"] == "remediated"
        decisions = approver.get("/api/v1/ledger/decisions?limit=500").json()["items"]
        kinds = [d["decision"] for d in decisions if d["plan_id"] == plan["plan_id"]]
        assert sorted(kinds) == ["approved", "remediation_applied"]
        for d in decisions:
            assert d["actor_hash"].startswith("0x") and d["evidence_hash"].startswith("0x")
            assert d["decision_code"] in range(1, 6)
        assert approver.get(f"/api/v1/remediation/{plan['plan_id']}").json()["status"] == "applied"


def test_scan_run_list_and_advance(app, repo) -> None:
    with client_as(app, "analyst") as client:
        scans = client.get("/api/v1/scans").json()
        assert scans["total"] == 12 and scans["items"][0]["scan_id"] == 12  # newest first
        assert client.get("/api/v1/scans/1").json()["snapshot_month"] == 1
        run = client.post("/api/v1/scan", headers=CSRF).json()
        assert run["scan_id"] == 13 and run["ledger_status"] == "already_anchored"
        assert run["merkle_root"] == scans["items"][0]["merkle_root"]  # same findings → same root
        assert_problem(
            client.post("/api/v1/scan", headers=CSRF, json={"month": 99}), 422, "scan.month_not_ingested"
        )
        advanced = client.post("/api/v1/simulate/advance", headers=CSRF).json()
        assert advanced["new_month"] == 13 and advanced["scan"]["snapshot_month"] == 13
        assert advanced["scan"]["ledger_status"] == "anchored"
        assert client.get("/api/v1/health").json()["month"] == 13
        assert len(client.get("/api/v1/timeline").json()["points"]) == 13
        assert client.get("/api/v1/scans?status=anchored").json()["total"] >= 13


def test_upload_multipart(app, repo) -> None:
    with client_as(app, "analyst") as client:
        response = client.post(
            "/api/v1/ingest/upload",
            headers=CSRF,
            data={"provider": "gcp", "month": "12"},
            files=[
                ("files", ("iam-policy.json", b'{"bindings": [1, 2]}', "application/json")),
                ("files", ("../../etc/passwd", b"\xff\xfe", "application/octet-stream")),
                ("files", ("broken.json", b"{not json", "application/json")),
            ],
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["provider"] == "gcp" and body["month"] == 12
        names = [f["filename"] for f in body["files"]]
        assert names == ["iam-policy.json", "passwd", "broken.json"]  # basename only
        assert body["files"][0]["rows"] == 1 and len(body["warnings"]) == 2


def test_exports_csv_json_pdf(app, repo) -> None:
    with client_as(app, "viewer") as client:
        csv_resp = client.get("/api/v1/export/findings.csv?severity=Critical")
        assert csv_resp.status_code == 200
        assert csv_resp.headers["content-type"].startswith("text/csv")
        assert 'filename="athar-findings.csv"' in csv_resp.headers["content-disposition"]
        rows = list(csv.reader(io.StringIO(csv_resp.text)))
        assert rows[0] == SPEC_16_COLUMNS == EXPORT_COLUMNS
        assert len(rows) - 1 == client.get("/api/v1/findings?severity=Critical&limit=500").json()["total"]
        assert all(row[8] == "Critical" for row in rows[1:])
        assert all(not cell.startswith(("=", "+", "-", "@")) for row in rows[1:] for cell in row)
        sidecar = client.get("/api/v1/export/findings.json?severity=Critical").json()
        assert sidecar["merkle_root"] == repo.scans[-1].merkle_root
        assert len(sidecar["findings"]) == len(rows) - 1
        entry = sidecar["findings"][0]
        assert entry["instance_hash"] == instance_hash(entry["instance"]) and entry["proof"] is not None
        pdf = client.get("/api/v1/export/findings.pdf")
        assert (
            pdf.status_code == 200
            and pdf.content.startswith(b"%PDF")
            and pdf.headers["content-type"] == "application/pdf"
        )


def test_csv_cells_are_escaped_against_formula_injection() -> None:
    assert MockRepo._escape('=HYPERLINK("x")') == '\'=HYPERLINK("x")'
    assert (
        MockRepo._escape("+1") == "'+1"
        and MockRepo._escape("-1") == "'-1"
        and MockRepo._escape("@x") == "'@x"
    )
    assert (
        MockRepo._escape("safe") == "safe" and MockRepo._escape(None) == "" and MockRepo._escape(12) == "12"
    )


def test_ledger_info_scans_and_verify(app, repo) -> None:
    with client_as(app, "viewer") as client:
        info = client.get("/api/v1/ledger").json()
        assert info["enabled"] and info["contract_address"].startswith("0x") and info["chain_id"] == 31337
        assert info["what_is_on_chain"] and info["what_is_not_on_chain"]
        assert "IAM" in " ".join(info["what_is_not_on_chain"])
        assert "compromised API host" in info["limits"]  # SPEC §12.1 honesty
        scans = client.get("/api/v1/ledger/scans").json()
        assert scans["total"] == 12
        last = scans["items"][0]
        assert last["block_number"] and last["timestamp"] and last["chain_root"] == last["merkle_root"]
        verify = client.get("/api/v1/ledger/scans/12/verify").json()
        assert verify["passed"] is True and verify["computed_root"] == verify["chain_root"]
        assert verify["finding_count"] == len(repo.findings) and verify["detail"].startswith("PASS")
    # Tamper: a severity edit in the "database" must fail the next verification (SPEC §12.6).
    victim = next(iter(repo.findings.values()))
    victim.instance_hash = "0x" + "ab" * 32
    with client_as(app, "viewer") as client:
        failed = client.get("/api/v1/ledger/scans/12/verify").json()
        assert failed["passed"] is False and failed["detail"].startswith("FAIL")


def test_settings_roundtrip_and_llm_status(app, repo) -> None:
    with client_as(app, "approver") as client:
        before = client.get("/api/v1/settings").json()
        assert before["llm"]["provider"] == "none" and before["updated_by"] is None
        assert before["approved_regions"] == ["me-central-1", "uaenorth", "uaecentral", "me-central1"]
        after = client.put("/api/v1/settings", headers=CSRF, json={"stale_key_days": 90}).json()
        assert after["stale_key_days"] == 90 and after["dormant_days"] == before["dormant_days"]
        assert after["updated_by"] == "usr-approver" and after["updated_at"]
        assert client.get("/api/v1/settings").json() == after
