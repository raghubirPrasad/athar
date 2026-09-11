"""`DbRepo` over a hand-seeded database (SPEC §13, §14, §16).

The rows are inserted directly with the models — no generator, no estate on disk — so the read
paths (identity table, drill-down, findings with altitudes and proofs, half-life, timeline,
ledger view, exports) are pinned against data this file can state exactly. The end-to-end path
through the real generator lives in `tests/integration/test_end_to_end.py`.

The module owns a **private schema** (`athar_test_repo`) so it never disturbs — and is never
disturbed by — whatever else is in the development database.
"""

from __future__ import annotations

import os
from datetime import UTC, date, datetime
from typing import Any

import pytest
from athar.api.problem import ConflictError, InvalidInputError
from athar.api.schemas import ExceptionRequest, ListFilters, SettingsUpdate
from athar.config import Settings, get_settings
from athar.db import models as m
from athar.hashing import finding_instance, finding_key, instance_hash
from athar.ledger import verify as ledger_verify
from athar.security.auth import AuthUser
from athar.services.repo import DbRepo
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

pytestmark = pytest.mark.integration

# Per-process so two test runs against one Postgres cannot drop each other's schema.
SCHEMA = f"athar_test_repo_{os.getpid()}"
RULESET = "0x" + "11" * 32
MONTH_1, MONTH_2 = 1, 2

ANALYST = AuthUser(user_id="usr-analyst", email="analyst@athar.local", role="analyst")
APPROVER = AuthUser(user_id="usr-approver", email="approver@athar.local", role="approver")

R1_KEY = finding_key("emp-0001", "R1")
R3_KEY = finding_key("emp-0001", "R3")
R6_KEY = finding_key("emp-0002", "R6")


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def engine(db_url: str) -> Any:
    admin = create_engine(db_url, future=True)
    with admin.begin() as conn:
        conn.execute(text(f"DROP SCHEMA IF EXISTS {SCHEMA} CASCADE"))
        conn.execute(text(f"CREATE SCHEMA {SCHEMA}"))
    admin.dispose()
    scoped = create_engine(db_url, future=True, connect_args={"options": f"-csearch_path={SCHEMA}"})
    m.Base.metadata.create_all(scoped)
    yield scoped
    scoped.dispose()
    admin = create_engine(db_url, future=True)
    with admin.begin() as conn:
        conn.execute(text(f"DROP SCHEMA IF EXISTS {SCHEMA} CASCADE"))
    admin.dispose()


@pytest.fixture(scope="module")
def settings(tmp_path_factory: pytest.TempPathFactory) -> Settings:
    """Real settings with an empty data directory, so `eval_result` reports "not computed"."""
    return get_settings().model_copy(update={"data_dir": str(tmp_path_factory.mktemp("data"))})


@pytest.fixture(scope="module")
def repo(engine: Any, settings: Settings) -> Any:
    session = Session(engine)
    seed(session)
    instance = DbRepo(session, settings)
    yield instance
    instance.close()


# ---------------------------------------------------------------------------
# seed
# ---------------------------------------------------------------------------


def _identity(identity_id: str, **kw: Any) -> m.Identity:
    base: dict[str, Any] = dict(
        identity_id=identity_id,
        display_name="Someone",
        identity_type="human",
        department="Finance",
        employment_type="staff",
        employment_status="active",
        hire_month=1,
        departure_month=None,
        external=False,
        mfa_enforced=True,
        tags={},
        contract_end_month=None,
        first_seen_month=1,
        last_seen_month=2,
    )
    base.update(kw)
    return m.Identity(**base)


def _grant(grant_id: str, identity_id: str, principal_ref: str, month: int, **kw: Any) -> m.Grant:
    base: dict[str, Any] = dict(
        grant_id=grant_id,
        identity_id=identity_id,
        principal_ref=principal_ref,
        cloud="aws",
        service_category="identity",
        verb="admin",
        scope_level="org",
        scope_ref="arn:aws:iam::123456789012:root",
        region="me-central-1",
        effect="allow",
        granted_via="managed_policy:AdministratorAccess",
        snapshot_month=month,
        raw_snippet={"PolicyName": "AdministratorAccess", "Statement": [{"Effect": "Allow"}]},
        source_file="aws/authorization-details.json",
        source_pointer="/UserDetailList/0/AttachedManagedPolicies/0",
        active=True,
    )
    base.update(kw)
    return m.Grant(**base)


def _finding(key: str, scan_id: int, identity_id: str, rule_id: str, severity: str, score: int) -> Any:
    """(row, instance) — the committed instance is rebuilt by the API from these very columns."""
    evidence = [f"grant:g-{identity_id}-{scan_id}"]
    causal = [f"evt-{identity_id}-1"]
    instance = finding_instance(
        finding_key=key,
        identity_id=identity_id,
        rule_id=rule_id,
        severity=severity,
        score=score,
        snapshot_month=scan_id,  # the seed uses scan_id == snapshot_month
        first_seen_month=MONTH_1,
        evidence_refs=evidence,
        causal_event_ids=causal,
    )
    row = m.Finding(
        finding_key=key,
        scan_id=scan_id,
        identity_id=identity_id,
        rule_id=rule_id,
        severity=severity,
        score=score,
        first_seen_month=MONTH_1,
        evidence_refs=evidence,
        causal_event_ids=causal,
        instance_hash=instance_hash(instance),
        leaf_proof=[],
        status="open",
        facts={
            "rule_id": rule_id,
            "display_name": "Layla Haddad" if identity_id == "emp-0001" else "svc-billing-etl",
            "department": "Finance" if identity_id == "emp-0001" else "Data Services",
            "cloud": "aws" if identity_id == "emp-0001" else "gcp",
            "scope_level": "org",
            "since_month": MONTH_1,
            "departure_month": MONTH_2,
            "age_days": 400,
        },
    )
    return row, instance


def _score(identity_id: str, scan_id: int, score: int, severity: str, blast: float) -> m.IdentityScore:
    return m.IdentityScore(
        identity_id=identity_id,
        scan_id=scan_id,
        blast_radius=blast,
        reach=min(1.0, blast / 0.25),
        exploitability=1.5,
        compensating=0.0,
        score=score,
        severity=severity,
        line_items=[
            {
                "term": "reach",
                "label": f"blast radius {blast * 100:.0f}% of estate, 3 high-sensitivity resources",
                "value": min(1.0, blast / 0.25),
                "detail": {"reachable": 12, "high_sensitivity": 3, "blast_radius": blast},
            },
            {"term": "exploitability", "label": "departed +0.5", "value": 0.5, "detail": {}},
            {"term": "formula", "label": "100 × reach × exploitability × controls", "value": 60.0},
            {"term": "floor", "label": "R3", "value": 75.0, "detail": {"rules": ["R3"]}},
            {"term": "final", "label": severity, "value": float(score)},
        ],
        escalation_paths=[
            [
                {"src": identity_id, "verb": "admin", "dst": "aws:org", "grant_id": f"g-{identity_id}-2"},
                {"src": "aws:org", "verb": "assume", "dst": "aws:role/IAMRoleManager", "grant_id": None},
            ]
        ],
    )


def seed(session: Session) -> None:
    """Three identities, two snapshot months, two scans, four findings, two plans."""
    session.add_all(
        [
            _identity(
                "emp-0001",
                display_name="Layla Haddad",
                department="Finance",
                employment_status="departed",
                departure_month=MONTH_2,
                mfa_enforced=False,
                tags={"owner": "layla.haddad@nda.example", "note": "cloud tag, never an exception"},
            ),
            _identity(
                "emp-0002",
                display_name="svc-billing-etl",
                identity_type="service",
                department="Data Services",
                employment_type="service",
                mfa_enforced=False,
                tags={"project": "nda-data-prod"},
            ),
            _identity(
                "emp-0003",
                display_name="Omar Al Nuaimi",
                department="HR",
                employment_type="contractor",
                external=True,
                contract_end_month=6,
                first_seen_month=MONTH_2,
            ),
        ]
    )
    session.flush()  # identities before the rows that reference them
    session.add_all(
        [
            m.Principal(
                principal_ref="arn:aws:iam::123456789012:user/layla.haddad",
                cloud="aws",
                principal_type="user",
                identity_id="emp-0001",
                raw={"UserName": "layla.haddad"},
                link_method="hr_email",
                link_confidence="exact",
            ),
            m.Principal(
                principal_ref="serviceAccount:billing-etl@nda-data-prod.iam.gserviceaccount.com",
                cloud="gcp",
                principal_type="service_account",
                identity_id="emp-0002",
                raw={},
                link_method="sa_project",
                link_confidence="derived",
            ),
            m.Principal(
                principal_ref="azure:user:11111111-2222-3333-4444-555555555555",
                cloud="azure",
                principal_type="user",
                identity_id="emp-0003",
                raw={},
                link_method="tag_owner",
                link_confidence="heuristic",
            ),
        ]
    )
    session.flush()
    aws_principal = "arn:aws:iam::123456789012:user/layla.haddad"
    gcp_principal = "serviceAccount:billing-etl@nda-data-prod.iam.gserviceaccount.com"
    azure_principal = "azure:user:11111111-2222-3333-4444-555555555555"
    session.add_all(
        [
            _grant("g-emp-0001-1", "emp-0001", aws_principal, MONTH_1),
            _grant("g-emp-0001-2", "emp-0001", aws_principal, MONTH_2),
            _grant(
                "g-emp-0002-1",
                "emp-0002",
                gcp_principal,
                MONTH_1,
                cloud="gcp",
                service_category="storage",
                verb="write",
                scope_level="project",
                scope_ref="projects/nda-data-prod",
                region="me-central1",
                granted_via="roles/storage.admin",
            ),
            _grant(
                "g-emp-0002-2",
                "emp-0002",
                gcp_principal,
                MONTH_2,
                cloud="gcp",
                service_category="storage",
                verb="write",
                scope_level="project",
                scope_ref="projects/nda-data-prod",
                region="me-central1",
                granted_via="roles/storage.admin",
            ),
            _grant(
                "g-emp-0003-2",
                "emp-0003",
                azure_principal,
                MONTH_2,
                cloud="azure",
                service_category="data",
                verb="write",
                scope_level="project",
                scope_ref="/subscriptions/abc/resourceGroups/rg-data",
                region="uaenorth",
                granted_via="roleDefinition:Contributor",
            ),
        ]
    )
    session.flush()
    session.add_all(
        [
            m.Activity(
                identity_id="emp-0001",
                cloud="aws",
                service_category="identity",
                snapshot_month=MONTH_2,
                last_activity_at=date(2025, 10, 20),
                operation_count=7,
            ),
            m.Activity(
                identity_id="emp-0002",
                cloud="gcp",
                service_category="storage",
                snapshot_month=MONTH_2,
                last_activity_at=None,
                operation_count=0,
            ),
            m.Credential(
                credential_ref="gcp:sa_key:emp-0002-1",
                identity_id="emp-0002",
                cloud="gcp",
                kind="sa_key",
                created_at=date(2024, 5, 1),
                last_rotated_at=date(2024, 6, 1),
                last_used_at=date(2025, 9, 30),
                active=True,
                snapshot_month=MONTH_2,
            ),
            m.Resource(
                resource_ref="gcp:storage:projects/nda-data-prod/buckets/finance",
                cloud="gcp",
                service_category="storage",
                region="me-central1",
                project_ref="projects/nda-data-prod",
                sensitivity="high",
                snapshot_month=MONTH_2,
            ),
            m.Project(
                project_id="prj-0001",
                name="Data Platform",
                department="Data Services",
                status="active",
                retired_month=None,
                cloud="gcp",
                project_ref="projects/nda-data-prod",
            ),
        ]
    )
    session.add_all(
        [
            m.GovernanceException(
                exception_id="exc-0001",
                identity_id="emp-0003",
                exception_type="approved-privileged-role",
                approved_by="ciso@nda.example",
                approved_on=date(2025, 9, 1),
                review_date=date(2030, 1, 1),
                expires_on=date(2030, 6, 1),
                justification="Sanctioned platform administrator, reviewed quarterly",
                source="register",
            ),
            m.GovernanceException(
                exception_id="exc-0002",
                identity_id="emp-0001",
                exception_type="time-boxed",
                approved_by="ciso@nda.example",
                approved_on=date(2024, 1, 1),
                review_date=date(2024, 6, 1),
                expires_on=date(2024, 12, 31),
                justification="Expired elevation, kept for audit",
                source="register",
            ),
        ]
    )
    added = {
        "principal_ref": aws_principal,
        "cloud": "aws",
        "service_category": "identity",
        "verb": "admin",
        "scope_ref": "arn:aws:iam::123456789012:root",
        "granted_via": "managed_policy:AdministratorAccess",
        "grant_id": "g-emp-0001-1",
    }
    session.add_all(
        [
            m.Event(
                event_id="evt-emp-0001-1",
                month=MONTH_1,
                kind="grant",
                identity_id="emp-0001",
                cloud="aws",
                grant_delta={"added": [added], "removed": []},
                trigger="role_change",
                note="",
            ),
            m.Event(
                event_id="evt-emp-0001-2",
                month=MONTH_2,
                kind="departure",
                identity_id="emp-0001",
                cloud=None,
                grant_delta={},
                trigger="departure",
                note="left the organisation",
            ),
            m.Event(
                event_id="evt-emp-0001-3",
                month=MONTH_2,
                kind="revoke",
                identity_id="emp-0001",
                cloud="aws",
                grant_delta={"added": [], "removed": [added]},
                trigger="departure",
                note="",
            ),
        ]
    )
    session.add_all(
        [
            m.Snapshot(
                snapshot_month=MONTH_1,
                ingested_at=datetime(2025, 9, 30, tzinfo=UTC),
                file_hashes={"aws/authorization-details.json": "a" * 64},
            ),
            m.Snapshot(
                snapshot_month=MONTH_2,
                ingested_at=datetime(2025, 10, 31, tzinfo=UTC),
                file_hashes={"aws/authorization-details.json": "b" * 64},
            ),
            m.EstateClock(id=1, current_month=MONTH_2),
        ]
    )
    session.flush()

    first, _ = _finding(R1_KEY, MONTH_1, "emp-0001", "R1", "High", 55)
    rows = [
        _finding(R1_KEY, MONTH_2, "emp-0001", "R1", "High", 82),
        _finding(R3_KEY, MONTH_2, "emp-0001", "R3", "Critical", 82),
        _finding(R6_KEY, MONTH_2, "emp-0002", "R6", "Medium", 41),
    ]
    hashes = [row.instance_hash for row, _ in rows]
    proofs = ledger_verify.leaf_proofs(hashes)
    for row, _instance in rows:
        row.leaf_proof = list(proofs[row.instance_hash][1])
    session.add_all(
        [
            m.Scan(
                scan_id=MONTH_1,
                snapshot_month=MONTH_1,
                ruleset_hash=RULESET,
                started_at=datetime(2025, 9, 30, 9, 0, tzinfo=UTC),
                finished_at=datetime(2025, 9, 30, 9, 0, 7, tzinfo=UTC),
                finding_count=1,
                merkle_root=ledger_verify.compute_root([first.instance_hash]),
                snapshot_hash="0x" + "aa" * 32,
                ledger_scan_index=None,
                ledger_tx=None,
                ledger_status="unanchored",
            ),
            m.Scan(
                scan_id=MONTH_2,
                snapshot_month=MONTH_2,
                ruleset_hash=RULESET,
                started_at=datetime(2025, 10, 31, 9, 0, tzinfo=UTC),
                finished_at=datetime(2025, 10, 31, 9, 0, 5, tzinfo=UTC),
                finding_count=len(rows),
                merkle_root=ledger_verify.compute_root(hashes),
                snapshot_hash="0x" + "bb" * 32,
                ledger_scan_index=None,
                ledger_tx=None,
                ledger_status="unanchored",
            ),
        ]
    )
    session.flush()  # scans before findings, scores and plans
    session.add(first)
    session.add_all([row for row, _ in rows])
    session.flush()
    session.add_all(
        [
            _score("emp-0001", MONTH_1, 55, "High", 0.11),
            _score("emp-0001", MONTH_2, 82, "Critical", 0.31),
            _score("emp-0002", MONTH_2, 41, "Medium", 0.06),
            _score("emp-0003", MONTH_2, 12, "Low", 0.01),
        ]
    )
    session.flush()
    session.add_all(
        [
            m.RemediationPlan(
                plan_id="plan-0001",
                finding_key=R1_KEY,
                scan_id=MONTH_2,
                action="revoke_grant",
                params={"grant_ids": ["g-emp-0001-2"]},
                policy_diff={
                    "cloud": "aws",
                    "before": {"attached": ["managed_policy:AdministratorAccess"]},
                    "after": {"attached": []},
                    "operations": [
                        {
                            "op": "detach_managed_policy",
                            "target": "managed_policy:AdministratorAccess",
                            "detail": "scope arn:aws:iam::123456789012:root",
                        }
                    ],
                    "summary": "Remove AdministratorAccess from layla.haddad",
                },
                keep=[],
                drop=["g-emp-0001-2"],
                privilege_reduction_pct=100.0,
                expected_blast_radius_after=0.0,
                proposed_by="model",
                proposer_user_id=None,
                model_id="gemini-2.5-flash",
                prompt_version="v1",
                rationale="Least-privilege diff: drop the admin grant cited by R1.",
                confidence=0.82,
                status="proposed",
                created_at=datetime(2025, 10, 31, 10, 0, tzinfo=UTC),
            ),
            m.RemediationPlan(
                plan_id="plan-0002",
                finding_key=R3_KEY,
                scan_id=MONTH_2,
                action="disable_identity",
                params={},
                policy_diff={"cloud": "aws", "before": {"Enabled": True}, "after": {"Enabled": False}},
                keep=[],
                drop=["g-emp-0001-2"],
                privilege_reduction_pct=100.0,
                expected_blast_radius_after=0.0,
                proposed_by="rule",
                proposer_user_id="usr-analyst",
                model_id=None,
                prompt_version=None,
                rationale="Departed identity: disable the account.",
                confidence=1.0,
                status="proposed",
                created_at=datetime(2025, 10, 31, 10, 5, tzinfo=UTC),
            ),
        ]
    )
    session.commit()
    # The seed sets scan ids by hand; move the sequence past them so `run_scan` can insert.
    session.execute(
        text("SELECT setval(pg_get_serial_sequence('scans', 'scan_id'), (SELECT max(scan_id) FROM scans))")
    )
    session.commit()


# ---------------------------------------------------------------------------
# reads
# ---------------------------------------------------------------------------


def test_current_month_and_scans(repo: DbRepo) -> None:
    assert repo.current_month() == MONTH_2
    page = repo.list_scans(ListFilters())
    assert page.total == 2
    assert [s.scan_id for s in page.items] == [2, 1], "newest first by default"
    assert page.items[0].merkle_root is not None and page.items[0].ledger_status == "unanchored"
    assert repo.scan(MONTH_1) is not None
    assert repo.scan(999) is None
    assert repo.list_scans(ListFilters(month=MONTH_1)).total == 1


def test_identity_table_rows_carry_score_severity_clouds_and_top_rule(repo: DbRepo) -> None:
    page = repo.list_identities(ListFilters())
    assert page.total == 3
    rows = {r.identity_id: r for r in page.items}
    layla = rows["emp-0001"]
    assert (layla.score, layla.severity) == (82, "Critical")
    assert layla.top_rule == "R3", "the worst finding decides the top rule"
    assert layla.top_rule_name and layla.top_rule_name != "R3"
    assert layla.clouds == ["aws"] and layla.blast_radius_pct == 31.0
    assert layla.finding_count == 2 and layla.status == "departed"
    assert layla.last_activity_at == date(2025, 10, 20)
    assert rows["emp-0002"].clouds == ["gcp"] and rows["emp-0003"].clouds == ["azure"]
    assert rows["emp-0003"].external is True and rows["emp-0003"].top_rule is None


def test_identity_filters_and_paging_happen_in_sql(repo: DbRepo) -> None:
    assert [r.identity_id for r in repo.list_identities(ListFilters(cloud="gcp")).items] == ["emp-0002"]
    assert repo.list_identities(ListFilters(department="finance")).total == 1, (
        "department is case-insensitive"
    )
    assert repo.list_identities(ListFilters(severity="Critical")).total == 1
    assert repo.list_identities(ListFilters(status="departed")).total == 1
    assert repo.list_identities(ListFilters(rule="R6")).total == 1
    assert [r.identity_id for r in repo.list_identities(ListFilters(q="al nuaimi")).items] == ["emp-0003"]
    assert repo.list_identities(ListFilters(q="%")).total == 0, "a LIKE wildcard is matched literally"
    first = repo.list_identities(ListFilters(limit=1, sort="identity_id"))
    assert first.total == 3 and len(first.items) == 1, "total ignores limit/offset"
    assert first.items[0].identity_id == "emp-0001"
    second = repo.list_identities(ListFilters(limit=1, offset=1, sort="identity_id"))
    assert second.items[0].identity_id == "emp-0002"


def test_identity_sorting_by_severity_uses_the_band_order(repo: DbRepo) -> None:
    ascending = repo.list_identities(ListFilters(sort="severity"))
    assert [r.severity for r in ascending.items] == ["Low", "Medium", "Critical"]
    descending = repo.list_identities(ListFilters(sort="-severity"))
    assert [r.severity for r in descending.items] == ["Critical", "Medium", "Low"]


def test_unknown_sort_field_is_a_stable_problem_code(repo: DbRepo) -> None:
    with pytest.raises(InvalidInputError) as raised:
        repo.list_identities(ListFilters(sort="-nope"))
    assert raised.value.code == "sort.unknown_field"
    assert raised.value.status_code == 422
    with pytest.raises(InvalidInputError) as raised:
        repo.list_findings(ListFilters(sort="nope"))
    assert raised.value.code == "sort.unknown_field"


def test_identity_detail_carries_everything_the_drill_down_needs(repo: DbRepo) -> None:
    detail = repo.identity_detail("emp-0001")
    assert detail is not None
    assert detail.display_name == "Layla Haddad" and detail.employment_status == "departed"
    assert detail.tags["note"], "cloud tags are shown as evidence"

    grant = detail.grants[0]
    assert grant.raw_snippet["PolicyName"] == "AdministratorAccess"
    assert grant.source_file == "aws/authorization-details.json"
    assert grant.source_pointer.startswith("/UserDetailList/")
    assert [g.snapshot_month for g in detail.grants] == [MONTH_2], "only the current month's grants"

    assert detail.activity and detail.activity[0].operation_count == 7
    assert detail.score is not None
    assert detail.score.reachable_resources == 12 and detail.score.high_sensitivity_reached == 3
    assert detail.score.rule_floor == 75 and detail.score.formula_score == 60.0
    assert next(li.term for li in detail.score.line_items) == "reach"
    assert detail.score.escalation_paths[0][0].grant_id == "g-emp-0001-2"

    assert {f.rule_id for f in detail.findings} == {"R1", "R3"}
    assert detail.top_finding_key == R3_KEY, "Critical outranks High"
    assert detail.altitudes is not None and "Layla Haddad" in detail.altitudes.headline

    assert [p.month for p in detail.risk_history] == [MONTH_1, MONTH_2], "one point per scanned month"
    assert [p.score for p in detail.risk_history] == [55, 82]
    assert any(e.kind == "departure" for p in detail.risk_history for e in p.events)
    assert {s.kind for s in detail.causal_history} == {"grant", "departure", "revoke"}

    exceptions = {e.exception_id: e for e in detail.exceptions}
    assert exceptions["exc-0002"].valid is False, "an expired register entry is shown but not valid"
    assert detail.principals[0].link_method == "hr_email"
    assert detail.principals[0].link_confidence == "exact"


def test_identity_detail_of_a_valid_exception_holder(repo: DbRepo) -> None:
    detail = repo.identity_detail("emp-0003")
    assert detail is not None
    assert detail.exceptions[0].valid is True
    assert detail.exceptions[0].source == "register"
    assert detail.credentials == [] and detail.findings == []
    assert detail.principals[0].link_confidence == "heuristic"
    assert repo.identity_detail("emp-9999") is None


def test_credential_age_is_measured_at_the_snapshot_month_end(repo: DbRepo) -> None:
    detail = repo.identity_detail("emp-0002")
    assert detail is not None
    credential = detail.credentials[0]
    assert credential.kind == "sa_key" and credential.active is True
    assert credential.age_days == (date(2025, 10, 31) - date(2024, 6, 1)).days


def test_findings_carry_evidence_altitudes_leaf_and_proof(repo: DbRepo) -> None:
    page = repo.list_findings(ListFilters())
    assert page.total == 3, "only the current scan's findings"
    by_key = {f.finding_key: f for f in page.items}
    r3 = by_key[R3_KEY]
    assert r3.severity == "Critical" and r3.score == 82
    assert r3.display_name == "Layla Haddad" and r3.department == "Finance"
    assert r3.rule_name and r3.allowed_actions and r3.attack_techniques is not None
    assert r3.first_seen_month == MONTH_1
    assert r3.evidence_refs[0].kind == "grant"
    assert r3.altitudes.headline and r3.altitudes.explanation
    assert r3.altitudes.evidence == {}, "the list view drops the evidence altitude (detail carries it)"
    assert "instance" not in r3.facts, "the list view drops the committed instance too"
    assert r3.leaf.startswith("0x") and len(r3.leaf) == 66
    assert r3.investigation is None, "agent prose is not persisted; POST /agent/investigate returns it"


def test_the_finding_detail_carries_the_evidence_altitude_and_the_committed_instance(
    repo: DbRepo,
) -> None:
    r3 = repo.finding(R3_KEY)
    assert r3 is not None
    assert set(r3.altitudes.evidence) >= {"evidence_refs", "rules_fired"}
    assert r3.facts["instance"]["finding_key"] == R3_KEY
    assert r3.instance_hash == instance_hash(r3.facts["instance"]), "the committed instance re-hashes"


def test_finding_proofs_reach_the_scan_root(repo: DbRepo) -> None:
    from athar.ledger import merkle

    scan = repo.scan(MONTH_2)
    assert scan is not None and scan.merkle_root is not None
    root = merkle.bytes32_from_hex(scan.merkle_root)
    for finding in repo.list_findings(ListFilters()).items:
        leaf = merkle.leaf_from_instance_hash(finding.instance_hash)
        path = [merkle.bytes32_from_hex(p) for p in finding.proof]
        assert merkle.verify(root, leaf, path), f"{finding.finding_key} is not in the committed tree"


def test_finding_filters(repo: DbRepo) -> None:
    assert repo.list_findings(ListFilters(rule="R6")).total == 1
    assert repo.list_findings(ListFilters(severity="Critical")).total == 1
    assert repo.list_findings(ListFilters(department="Data Services")).total == 1
    assert repo.list_findings(ListFilters(cloud="gcp")).total == 1
    assert repo.list_findings(ListFilters(status="open")).total == 3
    assert repo.list_findings(ListFilters(q="layla")).total == 2
    assert repo.list_findings(ListFilters(month=MONTH_1)).total == 1, "an older scan is addressable"
    lowest = repo.list_findings(ListFilters(sort="score")).items[0]
    assert lowest.severity == "Medium", "ascending score puts the lowest first"


def test_single_finding_comes_from_the_newest_scan(repo: DbRepo) -> None:
    found = repo.finding(R1_KEY)
    assert found is not None
    assert (found.scan_id, found.score) == (MONTH_2, 82)
    assert found.plan is not None and found.plan.plan_id == "plan-0001"
    assert found.plan.policy_diff.operations[0].op == "detach_managed_policy"
    assert found.plan.proposed_by == "model" and found.plan.model_id == "gemini-2.5-flash"
    assert repo.finding("0" * 32) is None


def test_estate_summary_counts_and_rollup(repo: DbRepo) -> None:
    summary = repo.estate_summary()
    assert summary.current_month == MONTH_2
    assert summary.current_month_label == "October 2025"
    assert (summary.identity_count, summary.humans, summary.services) == (3, 2, 1)
    assert summary.findings_total == 3
    assert summary.findings_by_severity == {"Critical": 1, "High": 1, "Medium": 1, "Low": 0}
    assert summary.findings_by_cloud == {"aws": 2, "azure": 0, "gcp": 1}
    assert summary.median_score == 41.0
    assert summary.scan_id == MONTH_2
    assert summary.ledger.status == "unanchored" and summary.ledger.last_scan_id == MONTH_2
    assert summary.executive_summary, "the Overview shows a templated paragraph before any agent runs"
    assert summary.model_id is None, "no model was consulted"
    assert "Nahar Digital Authority" in summary.executive_summary

    rollup = {r.department: r for r in summary.findings_by_department}
    assert rollup["Finance"].findings == 2 and rollup["Finance"].critical == 1
    assert rollup["Finance"].offboarding_half_life == 1.0, "granted month 1, revoked month 2"
    assert rollup["Finance"].half_life_label == "Healthy"
    assert rollup["HR"].identities == 1 and rollup["HR"].findings == 0
    assert rollup["HR"].offboarding_half_life is None and rollup["HR"].half_life_label == "Broken"


def test_halflife_table_covers_departments_and_triggers(repo: DbRepo) -> None:
    table = repo.halflife()
    assert table.month == MONTH_2
    departure = {r.department: r for r in table.rows if r.trigger == "departure"}
    assert departure["Finance"].grants == 1 and departure["Finance"].revocations == 1
    assert departure["Finance"].half_life_months == 1.0 and departure["Finance"].label == "Healthy"
    assert departure["all"].half_life_months == 1.0, "the overall row is served too"
    assert {r.trigger for r in table.rows} >= {"all", "departure", "role_change"}


def test_timeline_has_one_point_per_scanned_month(repo: DbRepo) -> None:
    timeline = repo.timeline()
    assert timeline.current_month == MONTH_2
    assert [p.month for p in timeline.points] == [MONTH_1, MONTH_2]
    assert [p.month_label for p in timeline.points] == ["September 2025", "October 2025"]
    assert timeline.points[0].identity_count == 2, "emp-0003 only appears in month 2"
    assert timeline.points[1].identity_count == 3
    assert timeline.points[1].findings_by_severity == {"Critical": 1, "High": 1, "Medium": 1, "Low": 0}
    assert timeline.points[1].median_score == 41.0
    assert "Finance" in timeline.points[1].half_life


def test_remediation_queue(repo: DbRepo) -> None:
    page = repo.list_plans(ListFilters())
    assert page.total == 2
    assert [p.plan_id for p in page.items] == ["plan-0002", "plan-0001"], "newest first"
    plan = repo.get_plan("plan-0001")
    assert plan is not None
    assert plan.identity_id == "emp-0001" and plan.display_name == "Layla Haddad"
    assert plan.rule_id == "R1" and plan.status == "proposed"
    assert plan.drop == ["g-emp-0001-2"] and plan.privilege_reduction_pct == 100.0
    assert plan.decisions == []
    assert repo.get_plan("plan-nope") is None
    assert repo.list_plans(ListFilters(status="applied")).total == 0
    assert repo.list_plans(ListFilters(department="Finance")).total == 2
    assert repo.list_plans(ListFilters(rule="R3")).total == 1


def test_ledger_view_is_honest_when_nothing_is_anchored(repo: DbRepo) -> None:
    info = repo.ledger_info()
    assert info.enabled is True
    assert "post-hoc alteration" in info.purpose
    assert "compromised API host" in info.limits
    assert any("findingsRoot" in row for row in info.what_is_on_chain)
    assert any("grants" in row for row in info.what_is_not_on_chain)

    scans = repo.ledger_scans(ListFilters())
    assert scans.total == 2
    assert scans.items[0].ledger_status == "unanchored"
    assert scans.items[0].chain_root is None and scans.items[0].ledger_scan_index is None
    assert scans.items[0].merkle_root is not None

    verified = repo.ledger_verify(MONTH_2)
    assert verified is not None
    assert verified.passed is False
    assert verified.finding_count == 3
    assert verified.computed_root == repo.scan(MONTH_2).merkle_root  # type: ignore[union-attr]
    assert "not anchored" in verified.detail or "not reachable" in verified.detail
    assert repo.ledger_verify(999) is None
    assert repo.ledger_decisions(ListFilters()).total == 0


def test_eval_result_says_so_when_it_has_not_been_computed(repo: DbRepo) -> None:
    result = repo.eval_result()
    assert result.generated_from == "not computed"
    assert result.held_out is True
    assert (result.precision, result.recall, result.f1) == (0.0, 0.0, 0.0)
    assert "not computed yet" in result.director_sentence
    assert result.per_rule == [] and result.decoys == []


def test_health_reports_the_database_it_is_using(repo: DbRepo) -> None:
    deps = repo.health_deps()
    assert deps.db.ok is True and deps.db.detail == "postgres reachable"
    assert isinstance(deps.anvil.ok, bool)
    assert "key" not in deps.llm.detail or "present" in deps.llm.detail or "missing" in deps.llm.detail
    assert "://" not in deps.llm.detail, "never a URL"


# ---------------------------------------------------------------------------
# exports (SPEC §16)
# ---------------------------------------------------------------------------


def test_csv_export_has_the_spec_columns_and_escapes_cells(repo: DbRepo) -> None:
    from athar.export.types import CSV_COLUMNS

    text_out = repo.export_csv(ListFilters()).decode("utf-8")
    lines = text_out.splitlines()
    assert lines[0] == ",".join(CSV_COLUMNS)
    assert len(lines) == 4, "header plus one line per finding"
    assert R3_KEY in text_out and "Layla Haddad" in text_out
    for line in lines[1:]:
        cells = line.split(",")
        assert not cells[0].startswith(("=", "+", "-", "@"))


def test_json_sidecar_carries_the_instance_and_the_proof(repo: DbRepo) -> None:
    from athar.export.json_export import read_findings_json

    sidecar = read_findings_json(repo.export_json(ListFilters()))
    assert sidecar.merkle_root == repo.scan(MONTH_2).merkle_root  # type: ignore[union-attr]
    assert {f.finding_key for f in sidecar.findings} == {R1_KEY, R3_KEY, R6_KEY}
    for row in sidecar.findings:
        assert instance_hash(row.instance) == row.instance_hash
    results = ledger_verify.verify_rows(
        ledger_verify.rows_from_sidecar(sidecar.findings), sidecar.merkle_root or ""
    )
    assert all(r.passed for r in results), "an exported report verifies against its own root"


def test_pdf_export_renders(repo: DbRepo) -> None:
    pdf = repo.export_pdf(ListFilters())
    assert pdf.startswith(b"%PDF") and len(pdf) > 2000


def test_exports_follow_the_filters(repo: DbRepo) -> None:
    text_out = repo.export_csv(ListFilters(rule="R6")).decode("utf-8")
    assert len(text_out.splitlines()) == 2
    assert "svc-billing-etl" in text_out


# ---------------------------------------------------------------------------
# writes — these mutate the seeded state, so they run last and in this order
# ---------------------------------------------------------------------------


def test_settings_round_trip(repo: DbRepo) -> None:
    before = repo.get_settings()
    assert before.updated_by is None and before.llm.cache_entries == 0
    after = repo.put_settings(SettingsUpdate(dormant_days=45, approved_regions=["me-central-1"]), ANALYST)
    assert after.dormant_days == 45 and after.approved_regions == ["me-central-1"]
    assert after.stale_key_days == before.stale_key_days, "untouched fields keep their value"
    assert after.updated_by == "usr-analyst" and after.updated_at is not None
    assert repo.get_settings().dormant_days == 45


def test_approve_then_apply_walks_the_lifecycle(repo: DbRepo) -> None:
    approved = repo.approve("plan-0001", APPROVER)
    assert approved.status == "approved"
    assert [d.decision for d in approved.decisions] == ["approved"]
    assert approved.decisions[0].actor_user_id == "usr-approver"
    assert approved.decisions[0].ledger_status == "unanchored", "no writer in this test"
    finding = repo.finding(R1_KEY)
    assert finding is not None and finding.status == "approved"

    with pytest.raises(ConflictError) as raised:
        repo.approve("plan-0001", APPROVER)
    assert raised.value.code == "plan.invalid_state"
    assert raised.value.status_code == 409

    applied = repo.apply("plan-0001", APPROVER)
    assert applied.plan.status == "applied"
    assert applied.finding.status == "remediated"
    assert applied.score_before == 82
    assert {d.decision for d in applied.plan.decisions} == {"approved", "remediation_applied"}
    assert repo.ledger_decisions(ListFilters()).total == 2
    decision = repo.ledger_decisions(ListFilters()).items[0]
    assert decision.decision_code in (1, 4) and decision.actor_hash.startswith("0x")
    assert decision.leaf is not None


def test_rejecting_a_plan_returns_the_finding_to_open(repo: DbRepo) -> None:
    rejected = repo.reject("plan-0002", APPROVER, "needs a narrower diff")
    assert rejected.status == "rejected"
    finding = repo.finding(R3_KEY)
    assert finding is not None and finding.status == "open", "SPEC §10.3"
    with pytest.raises(InvalidInputError) as raised:
        repo.approve("plan-nope", APPROVER)
    assert raised.value.code == "plan.not_found"


def test_granting_an_exception_writes_the_register(repo: DbRepo) -> None:
    body = ExceptionRequest(
        exception_type="break-glass",
        justification="Break-glass administrator, monitored, quarterly review",
        review_date=date(2030, 1, 1),
        expires_on=None,
    )
    finding = repo.grant_exception(R6_KEY, APPROVER, body)
    assert finding is not None
    assert finding.status == "exception_granted"
    assert finding.exception is not None
    assert finding.exception.source == "workflow" and finding.exception.valid is True
    assert finding.exception.approved_by == "usr-approver"
    detail = repo.identity_detail("emp-0002")
    assert detail is not None
    assert any(e.source == "workflow" for e in detail.exceptions), "the register is the only source"
    assert repo.grant_exception("0" * 32, APPROVER, body) is None


def test_investigate_and_summary_use_the_template_fallback_without_a_model(repo: DbRepo) -> None:
    investigation = repo.investigate(R1_KEY, regenerate=False, user=ANALYST)
    assert investigation is not None
    assert investigation.finding_key == R1_KEY
    assert investigation.hypothesis
    assert investigation.recommended_action in repo.finding(R1_KEY).allowed_actions  # type: ignore[union-attr]
    assert 0.0 <= investigation.confidence <= 1.0
    assert repo.investigate("0" * 32, regenerate=False, user=ANALYST) is None

    summary = repo.summary(regenerate=False, user=ANALYST)
    assert summary.summary_paragraph
    assert len(summary.top_themes) <= 3
    assert repo.estate_summary().executive_summary == summary.summary_paragraph, (
        "the Overview reads the cached paragraph, never a model"
    )


def test_run_scan_is_the_real_pipeline_and_is_idempotent(repo: DbRepo) -> None:
    first = repo.run_scan(None, ANALYST)
    assert first.snapshot_month == MONTH_2
    assert first.merkle_root is not None and first.ruleset_hash != RULESET
    assert first.ledger_status == "unanchored", "no writer configured in this test"
    again = repo.run_scan(MONTH_2, ANALYST)
    assert again.scan_id == first.scan_id, "same snapshot, ruleset and root → one scan row"
    assert again.merkle_root == first.merkle_root
    assert again.finding_count == first.finding_count
    with pytest.raises(InvalidInputError) as raised:
        repo.run_scan(11, ANALYST)
    assert raised.value.code == "scan.month_not_ingested"


@pytest.mark.integration
def test_uploading_a_month_already_ingested_adds_no_identity(repo: DbRepo, engine: Any) -> None:
    """An upload of data already ingested must be a no-op on the identity table (SPEC §13, §5.1).

    `HrBundle.from_identities` used to drop every stored `svc:` row, so the linker could not see
    that the HR feed already owns those accounts and minted each one again under a second id
    shape — one service account split across two CPM rows, findings on one and grants on the other.
    """
    from athar.db import models as m
    from athar.domain import IdentityRow
    from athar.normaliser.types import HrBundle
    from sqlalchemy import select

    with Session(engine) as session:
        stored = [
            IdentityRow(
                identity_id=row.identity_id,
                display_name=row.display_name,
                identity_type=row.identity_type,
                department=row.department,
                employment_type=row.employment_type,
                employment_status=row.employment_status,
                hire_month=row.hire_month,
                departure_month=row.departure_month,
                external=bool(row.external),
                mfa_enforced=bool(row.mfa_enforced),
                tags=dict(row.tags or {}),
                contract_end_month=row.contract_end_month,
                first_seen_month=row.first_seen_month,
                last_seen_month=row.last_seen_month,
            )
            for row in session.scalars(select(m.Identity))
        ]
    service_ids = {r.identity_id for r in stored if r.identity_id.startswith("svc:")}
    bundle = HrBundle.from_identities(stored)
    known = {e.employee_id for e in bundle.employees}
    assert service_ids <= known, "a service account the database already owns must be offered to the linker"
    assert not any(e.employee_id.startswith("unlinked:") for e in bundle.employees), (
        "an unowned principal must not become its own owner"
    )
