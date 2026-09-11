"""Identity correlation rules in SPEC §6 order, with confidence and synthetic identities."""

from __future__ import annotations

from datetime import date

from athar.domain import ProjectRow
from athar.normaliser.linker import LINK_METHODS, link_one, link_principals, synthetic_identities
from athar.normaliser.types import HrBundle, HrEmployee, RawPrincipal


def _emp(
    employee_id: str,
    email: str | None,
    name: str,
    employment_type: str = "staff",
    department: str = "Finance",
) -> HrEmployee:
    return HrEmployee(
        employee_id=employee_id,
        email=email,
        display_name=name,
        department=department,
        title="t",
        employment_type=employment_type,
        status="active",
        start_date=date(2025, 9, 1),
        end_date=None,
        contract_end=None,
        manager_id=None,
    )


def _hr() -> HrBundle:
    return HrBundle(
        employees=[
            _emp("emp-1", "aisha.almansoori@nda.example", "Aisha Al Mansoori"),
            _emp("emp-2", "omar.haddad@nda.example", "Omar Haddad", department="Platform Engineering"),
            _emp(
                "svc-1",
                "svc-etl@nda.example",
                "svc-etl",
                employment_type="service",
                department="Data Services",
            ),
        ],
        projects=[
            ProjectRow(
                "prj-analytics",
                "Citizen Analytics",
                "Data Services",
                "active",
                None,
                "gcp",
                "nda-analytics-prod",
            ),
            ProjectRow("prj-legacy", "Legacy Portal", "Smart Services", "retired", 1, "aws", "legacy-portal"),
        ],
    )


def _p(ref: str, cloud: str = "aws", **kw: object) -> RawPrincipal:
    base: dict = dict(
        principal_ref=ref, cloud=cloud, principal_type="user", name=ref.rsplit("/", 1)[-1], email=None
    )
    base.update(kw)
    return RawPrincipal(**base)


ENTRA = {
    "aaaaaaaa-0001-4000-8000-000000000001": {
        "id": "aaaaaaaa-0001-4000-8000-000000000001",
        "userPrincipalName": "Aisha.AlMansoori@nda.example",
    }
}


def test_rule_order_is_the_spec_order() -> None:
    assert LINK_METHODS == (
        "hr_email",
        "entra_directory",
        "aws_username",
        "sa_project",
        "tag_owner",
        "unlinked",
    )


def test_rule_1_hr_email_is_case_insensitive_and_exact() -> None:
    link = link_one(
        _p("user:AISHA.ALMANSOORI@nda.example", "gcp", email="aisha.almansoori@nda.example"), _hr(), {}
    )
    assert (link.identity_id, link.method, link.confidence) == ("emp-1", "hr_email", "exact")


def test_rule_2_entra_directory_resolves_object_id_to_upn_to_hr() -> None:
    p = _p("aaaaaaaa-0001-4000-8000-000000000001", "azure", name="Aisha Al Mansoori")
    link = link_one(p, _hr(), ENTRA)
    assert (link.identity_id, link.method, link.confidence) == ("emp-1", "entra_directory", "derived")
    assert link_one(p, _hr(), {}).method == "unlinked"  # no directory export → nothing to resolve


def test_rule_2_only_applies_to_azure() -> None:
    p = _p("aaaaaaaa-0001-4000-8000-000000000001", "aws", name="Aisha Al Mansoori")
    assert link_one(p, _hr(), ENTRA).method == "unlinked"


def test_rule_3_aws_username_equals_hr_local_part_for_users_only() -> None:
    user = _p("arn:aws:iam::123456789012:user/Omar.Haddad", name="Omar.Haddad")
    link = link_one(user, _hr(), {})
    assert (link.identity_id, link.method, link.confidence) == ("emp-2", "aws_username", "derived")
    role = _p("arn:aws:iam::123456789012:role/omar.haddad", name="omar.haddad", principal_type="role")
    assert link_one(role, _hr(), {}).method == "unlinked"
    gcp = _p("user:omar.haddad@other.example", "gcp", name="omar.haddad")
    assert link_one(gcp, _hr(), {}).method == "unlinked"


def test_rule_4_sa_project_mints_a_synthetic_identity() -> None:
    p = _p(
        "arn:aws:iam::123456789012:user/svc-batch",
        name="svc-batch",
        project_hint="legacy-portal",
        is_service=True,
    )
    link = link_one(p, _hr(), {})
    assert (link.identity_id, link.method, link.confidence) == (
        "svc:prj-legacy:svc-batch",
        "sa_project",
        "derived",
    )
    assert link.project is not None and link.project.project_id == "prj-legacy"
    by_id = _p("x", "azure", name="sp", project_hint="PRJ-ANALYTICS", principal_type="service_principal")
    assert link_one(by_id, _hr(), {}).identity_id == "svc:prj-analytics:sp"
    unknown_project = _p("y", "gcp", name="sa", project_hint="no-such-project")
    assert link_one(unknown_project, _hr(), {}).method == "unlinked"


def test_rule_4_prefers_an_hr_service_row_named_like_the_account() -> None:
    p = _p(
        "serviceAccount:etl@nda-analytics-prod.iam.gserviceaccount.com",
        "gcp",
        name="etl",
        project_hint="nda-analytics-prod",
        principal_type="service_account",
        is_service=True,
    )
    link = link_one(p, _hr(), {})
    assert (link.identity_id, link.method) == ("svc-1", "sa_project")


def test_rule_5_tag_owner_is_a_heuristic() -> None:
    p = _p(
        "arn:aws:iam::123456789012:user/rbinali",
        name="rbinali",
        tags={"owner": "Aisha.AlMansoori@nda.example"},
    )
    link = link_one(p, _hr(), {})
    assert (link.identity_id, link.method, link.confidence) == ("emp-1", "tag_owner", "heuristic")
    assert link_one(_p("z", tags={"owner": "nobody@nda.example"}), _hr(), {}).method == "unlinked"


def test_rule_6_unlinked_fallthrough() -> None:
    p = _p("arn:aws:iam::123456789012:user/ghost", name="ghost")
    link = link_one(p, _hr(), {})
    assert link.identity_id == "unlinked:aws:arn:aws:iam::123456789012:user/ghost"
    assert (link.method, link.confidence) == ("unlinked", "heuristic")


def test_earlier_rules_win() -> None:
    both = _p(
        "arn:aws:iam::123456789012:user/omar.haddad",
        name="omar.haddad",
        email="aisha.almansoori@nda.example",
        tags={"owner": "omar.haddad@nda.example"},
    )
    assert link_one(both, _hr(), {}).method == "hr_email"
    username_and_project = _p(
        "arn:aws:iam::123456789012:user/svc-etl", name="svc-etl", project_hint="nda-analytics-prod"
    )
    assert link_one(username_and_project, _hr(), {}).method == "aws_username"
    project_and_owner = _p(
        "arn:aws:iam::123456789012:user/svc-x",
        name="svc-x",
        project_hint="legacy-portal",
        tags={"owner": "aisha.almansoori@nda.example"},
    )
    assert link_one(project_and_owner, _hr(), {}).method == "sa_project"


def test_link_principals_is_sorted_and_carries_raw() -> None:
    a = _p("arn:aws:iam::123456789012:user/b", name="b", raw={"UserId": "B"})
    b = _p(
        "user:aisha.almansoori@nda.example", "gcp", email="aisha.almansoori@nda.example", raw={"member": "x"}
    )
    rows = link_principals([b, a], _hr(), ENTRA)
    assert [r.principal_ref for r in rows] == [a.principal_ref, b.principal_ref]
    assert rows[0].raw == {"UserId": "B"} and rows[0].link_method == "unlinked"
    assert rows[1].identity_id == "emp-1" and rows[1].cloud == "gcp"
    assert rows == link_principals([a, b], _hr(), ENTRA)


def test_projects_argument_overrides_the_bundle_registry() -> None:
    p = _p("x", name="sa", project_hint="other-ref", is_service=True)
    extra = [ProjectRow("prj-other", "Other", "HR", "active", None, "aws", "other-ref")]
    assert link_principals([p], _hr(), None, extra)[0].identity_id == "svc:prj-other:sa"
    assert link_principals([p], _hr())[0].link_method == "unlinked"


def test_synthetic_identities_for_svc_and_unlinked() -> None:
    svc = _p(
        "arn:aws:iam::123456789012:user/svc-batch",
        name="svc-batch",
        project_hint="legacy-portal",
        is_service=True,
        tags={"env": "prod"},
    )
    ghost = _p(
        "cccccccc-0102-4000-8000-000000000102", "azure", name="sp-unknown", principal_type="service_principal"
    )
    human = _p("user:aisha.almansoori@nda.example", "gcp", email="aisha.almansoori@nda.example")
    linked = link_principals([svc, ghost, human], _hr(), {})
    rows = {r.identity_id: r for r in synthetic_identities([svc, ghost, human], linked, _hr(), 4)}
    assert set(rows) == {"svc:prj-legacy:svc-batch", "unlinked:azure:cccccccc-0102-4000-8000-000000000102"}
    s = rows["svc:prj-legacy:svc-batch"]
    assert (s.identity_type, s.employment_type, s.department, s.display_name) == (
        "service",
        "service",
        "Smart Services",
        "svc-batch",
    )
    assert s.tags == {
        "env": "prod",
        "principal_ref": svc.principal_ref,
        "cloud": "aws",
        "project": "prj-legacy",
        "project_ref": "legacy-portal",
    }
    assert (s.first_seen_month, s.last_seen_month, s.mfa_enforced, s.external) == (4, 4, False, False)
    u = rows["unlinked:azure:cccccccc-0102-4000-8000-000000000102"]
    assert (u.identity_type, u.department, u.display_name, u.employment_status) == (
        "service",
        "Unassigned",
        "sp-unknown",
        "active",
    )
    assert u.tags == {"principal_ref": ghost.principal_ref, "cloud": "azure"}


def test_cloud_tags_never_become_exceptions() -> None:
    tagged = _p(
        "arn:aws:iam::123456789012:user/x",
        name="x",
        tags={"exception": "break-glass", "athar_exception": "approved"},
    )
    hr = _hr()
    link_principals([tagged], hr, {})
    assert hr.exceptions == []


def test_an_hr_service_row_and_its_principal_produce_exactly_one_identity() -> None:
    """The HR feed is the record for a service account it already lists (SPEC §4.6, §6 rule 4).

    The generator gives a service identity the same id the simulator uses — `svc:<project>:<name>`,
    which is how ground_truth.json names its decoys — so the feed and the linker describe the same
    identity. Minting a second row for it made `_upsert_identities` name one identity twice in a
    single INSERT ... ON CONFLICT, which Postgres refuses outright, so no month could be ingested.
    """
    identity_id = "svc:prj-analytics:etl"
    hr = HrBundle(
        employees=[
            _emp(
                identity_id,
                "etl@nda-analytics-prod.iam.gserviceaccount.example",
                "etl",
                employment_type="service",
                department="Data Services",
            )
        ],
        projects=list(_hr().projects),
    )
    principal = _p(
        "serviceAccount:etl@nda-analytics-prod.iam.gserviceaccount.example",
        "gcp",
        name="etl",
        project_hint="nda-analytics-prod",
        is_service=True,
        principal_type="service_account",
    )
    linked = link_principals([principal], hr, {})
    assert [r.identity_id for r in linked] == [identity_id], "the principal links to the HR row"

    minted = synthetic_identities([principal], linked, hr, 4)
    assert [r.identity_id for r in minted] == [], "HR already supplies this identity; do not mint a second"


def test_a_service_principal_hr_does_not_know_is_still_minted_once() -> None:
    """The complement: without an HR row there is nothing to own the grant, so the linker mints one."""
    principal = _p(
        "arn:aws:iam::123456789012:user/svc-batch",
        name="svc-batch",
        project_hint="legacy-portal",
        is_service=True,
    )
    hr = _hr()
    linked = link_principals([principal], hr, {})
    minted = synthetic_identities([principal], linked, hr, 4)
    assert [r.identity_id for r in minted] == ["svc:prj-legacy:svc-batch"]
    assert minted[0].identity_id not in hr.by_id


def test_an_ambiguous_email_links_nobody_rather_than_merging_two_identities() -> None:
    """Two service accounts sharing an address must not become one identity (SPEC §6).

    The HR indexes used to keep whichever row came first, so every principal bearing that address
    was handed to it — giving one identity a cloud footprint neither of them has, which is exactly
    the cross-cloud shape R4 fires on. An ambiguous key is dropped instead, the principal falls
    through to the next rule, and an unowned one becomes R10.
    """
    shared = "svc-etl@nda.example"
    hr = HrBundle(
        employees=[
            _emp("svc:prj-a:etl", shared, "etl", employment_type="service", department="Data Services"),
            _emp("svc:prj-b:etl", shared, "etl", employment_type="service", department="Smart Services"),
        ],
        projects=list(_hr().projects),
    )
    assert shared in hr.ambiguous
    assert hr.employee_for_email(shared) is None

    principal = _p("user:svc-etl@nda.example", "gcp", email=shared)
    linked = link_principals([principal], hr, {})
    assert linked[0].link_method != "hr_email", "an ambiguous address is not a link"


def test_an_unambiguous_email_still_links() -> None:
    hr = _hr()
    assert "aisha.almansoori@nda.example" not in hr.ambiguous
    linked = link_principals([_p("user:aisha", "gcp", email="aisha.almansoori@nda.example")], hr, {})
    assert (linked[0].identity_id, linked[0].link_method) == ("emp-1", "hr_email")
