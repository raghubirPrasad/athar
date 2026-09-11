"""Generated estate → normaliser → canonical rows (SPEC §4.6 → §5, §6).

The writers exist to feed the normaliser, so the contract between the two lanes is tested here:
every month of a generated estate parses into identities, principals, grants, activity,
credentials, resources, projects and exceptions; the linker owns every principal except the two
deliberately unowned IAM roles; and an action no mapping table knows surfaces as an
`UnmappedAction` (finding R0) instead of raising.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest
from athar.generator.estate import generate_estate
from athar.normaliser.parsers.hr import parse_employees
from athar.normaliser.pipeline import NormalisedMonth, normalise_month, to_estate_view

from tests.generator.conftest import FULL_IDENTITIES, FULL_MONTHS, FULL_SEED, SMALL_MONTHS

UNLINKED_ROLES = 2  # nda-lambda-exec and nda-ci-deploy (SPEC §6 rule 6 → R10)


@pytest.fixture(scope="module")
def months(small_estate: Path) -> list[NormalisedMonth]:
    return [normalise_month(small_estate, month) for month in range(1, SMALL_MONTHS + 1)]


def test_every_month_yields_every_kind_of_row(months: list[NormalisedMonth]) -> None:
    for normalised in months:
        assert normalised.identities, normalised.month
        assert normalised.principals
        assert normalised.grants
        assert normalised.activity
        assert normalised.credentials
        assert normalised.resources
        assert normalised.projects
        assert normalised.exceptions
        assert normalised.events


def test_nothing_in_the_estate_makes_the_parsers_warn(months: list[NormalisedMonth]) -> None:
    for normalised in months:
        assert normalised.warnings == [], normalised.warnings


def test_linked_identities_are_the_hr_employees(small_estate: Path, months: list[NormalisedMonth]) -> None:
    normalised = months[-1]
    employees = parse_employees(
        (small_estate / f"month-{SMALL_MONTHS:02d}" / "hr" / "employees.csv").read_text(encoding="utf-8")
    )
    hr_ids = {e.employee_id for e in employees}
    assert hr_ids

    linked = {p.identity_id for p in normalised.principals}
    synthetic = {i for i in linked if i.startswith("unlinked:")}
    assert linked - synthetic <= hr_ids, "a principal was linked to an identity HR does not know"
    assert {i.identity_id for i in normalised.identities} >= hr_ids
    assert all(p.identity_id for p in normalised.principals), "every principal has an identity (SPEC §6)"


def test_only_the_unowned_iam_roles_stay_unlinked(months: list[NormalisedMonth]) -> None:
    normalised = months[-1]
    unlinked = sorted({p.identity_id for p in normalised.principals if p.identity_id.startswith("unlinked:")})
    assert len(unlinked) == UNLINKED_ROLES, unlinked
    assert all(":role/nda-" in identity_id for identity_id in unlinked)
    methods = Counter(p.link_method for p in normalised.principals)
    assert methods["hr_email"] and methods["aws_username"] and methods["sa_project"]


def test_grants_cover_the_three_clouds_and_carry_evidence(months: list[NormalisedMonth]) -> None:
    normalised = months[-1]
    assert {g.cloud for g in normalised.grants} == {"aws", "azure", "gcp"}
    for grant in normalised.grants:
        assert grant.raw_snippet, grant.grant_id
        assert grant.source_file and grant.source_pointer
        assert grant.granted_via
    assert {g.scope_level for g in normalised.grants} >= {"resource", "project", "global"}


def test_credentials_activity_and_resources_are_linked(months: list[NormalisedMonth]) -> None:
    normalised = months[-1]
    identities = {i.identity_id for i in normalised.identities}
    assert {c.identity_id for c in normalised.credentials} <= identities
    assert {a.identity_id for a in normalised.activity} <= identities
    assert {c.kind for c in normalised.credentials} >= {"key", "password", "sa_key"}
    assert {r.sensitivity for r in normalised.resources} == {"low", "high"}
    assert all(r.region for r in normalised.resources)


def test_the_estate_view_is_buildable(months: list[NormalisedMonth]) -> None:
    view = to_estate_view(months[-1])
    assert view.identities and view.grants and view.projects
    assert view.exceptions


def test_unknown_actions_never_raise(months: list[NormalisedMonth]) -> None:
    for normalised in months:
        for unmapped in normalised.unmapped:
            assert unmapped.cloud in ("aws", "azure", "gcp")
            assert unmapped.raw and unmapped.source_file


@pytest.mark.slow
def test_the_full_estate_carries_the_r0_bait_and_nothing_else_unmapped(tmp_path: Path) -> None:
    """The catalogue seeds one unmappable action per cloud (SPEC §5.3 → R0). They must reach the
    normaliser as `unmapped`, and nothing else in the estate may be unreadable."""
    estate = generate_estate(FULL_SEED, FULL_MONTHS, FULL_IDENTITIES, tmp_path)
    normalised = normalise_month(estate, FULL_MONTHS)
    clouds = {u.cloud for u in normalised.unmapped}
    assert clouds == {"aws", "azure", "gcp"}, sorted({(u.cloud, u.raw) for u in normalised.unmapped})
    assert normalised.warnings == []
    unlinked = {p.identity_id for p in normalised.principals if p.identity_id.startswith("unlinked:")}
    assert len(unlinked) == UNLINKED_ROLES
    assert len(normalised.grants) > 5000
