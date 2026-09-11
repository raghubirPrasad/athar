"""Permission Half-Life (SPEC §9.3): pairing, Never rule, bands, per-trigger rows, headline."""

from __future__ import annotations

from athar.drift import halflife as hl
from athar.drift.types import HalfLifeRow
from tests import factories as f


def _entry(n: int) -> dict:
    return {
        "grant_id": f"g-{n}",
        "principal_ref": "p",
        "cloud": "aws",
        "service_category": "storage",
        "verb": "write",
        "scope_ref": f"arn:aws:s3:::b{n}",
        "granted_via": "direct",
    }


def _grant(n: int, month: int, identity_id: str = "emp-0001", trigger: str = "new_hire"):
    return f.event(
        f"diff-{month}-g-{n}",
        month,
        "grant",
        identity_id=identity_id,
        trigger=trigger,
        grant_delta={"added": [_entry(n)], "removed": []},
    )


def _revoke(n: int, month: int, identity_id: str = "emp-0001", trigger: str = "departure"):
    return f.event(
        f"diff-{month}-r-{n}",
        month,
        "revoke",
        identity_id=identity_id,
        trigger=trigger,
        grant_delta={"added": [], "removed": [_entry(n)]},
    )


IDS = {
    "emp-0001": f.identity("emp-0001", department="Finance"),
    "emp-0002": f.identity("emp-0002", department="HR"),
}


def _row(rows: list[HalfLifeRow], department: str, trigger: str = "all") -> HalfLifeRow:
    return next(r for r in rows if r.department == department and r.trigger == trigger)


def test_never_when_revocations_below_ten_percent_of_grants():
    events = [_grant(n, 1) for n in range(20)] + [_revoke(0, 3)]
    row = _row(hl.halflife_by_department(events, IDS, 12), "Finance")
    assert (row.grants, row.revocations, row.half_life_months, row.label) == (20, 1, None, "Broken")


def test_never_when_no_grants_at_all():
    row = _row(hl.halflife_by_department([], IDS, 12), "Finance")
    assert row == HalfLifeRow("Finance", "all", 0, 0, None, "Broken")


def test_healthy_when_median_at_most_four_months():
    events = [_grant(1, 1), _grant(2, 1), _revoke(1, 3), _revoke(2, 5)]  # intervals 2, 4 → median 3
    row = _row(hl.halflife_by_department(events, IDS, 12), "Finance")
    assert (row.half_life_months, row.label) == (3.0, "Healthy")


def test_slow_when_median_between_four_and_eight():
    events = [_grant(1, 1), _grant(2, 1), _revoke(1, 5), _revoke(2, 9)]  # intervals 4, 8 → median 6
    row = _row(hl.halflife_by_department(events, IDS, 12), "Finance")
    assert (row.half_life_months, row.label) == (6.0, "Slow")


def test_broken_when_median_above_eight():
    events = [_grant(1, 1), _revoke(1, 11)]
    row = _row(hl.halflife_by_department(events, IDS, 12), "Finance")
    assert (row.half_life_months, row.label) == (10.0, "Broken")


def test_boundaries_four_is_healthy_and_eight_is_slow():
    assert hl.label_for(4.0) == "Healthy" and hl.label_for(4.5) == "Slow"
    assert hl.label_for(8.0) == "Slow" and hl.label_for(8.5) == "Broken" and hl.label_for(None) == "Broken"


def test_revoke_pairs_with_the_earliest_unmatched_grant_of_the_same_key():
    events = [_grant(1, 1), _grant(1, 4), _revoke(1, 6), _revoke(1, 7)]  # same key granted twice
    row = _row(hl.halflife_by_department(events, IDS, 12), "Finance")
    assert row.grants == 2 and row.revocations == 2
    assert row.half_life_months == 4.0  # (6−1)=5 and (7−4)=3 → median 4


def test_revoke_without_a_grant_in_the_window_counts_but_has_no_interval():
    events = [_grant(1, 1), _revoke(1, 3), _revoke(2, 3)]
    row = _row(hl.halflife_by_department(events, IDS, 12), "Finance")
    assert row.revocations == 2 and row.half_life_months == 2.0


def test_per_trigger_rows_share_the_grant_pool_but_count_only_that_triggers_revocations():
    events = [_grant(n, 1) for n in range(4)] + [
        _revoke(0, 3, trigger="departure"),
        _revoke(1, 5, trigger="role_change"),
        _revoke(2, 4, trigger="departure"),
    ]
    rows = hl.halflife_by_department(events, IDS, 12)
    assert {r.trigger for r in rows if r.department == "Finance"} == set(hl.TRIGGERS)
    departure = _row(rows, "Finance", "departure")
    assert (departure.grants, departure.revocations, departure.half_life_months) == (4, 2, 2.5)
    role = _row(rows, "Finance", "role_change")
    assert (role.grants, role.revocations, role.half_life_months) == (4, 1, 4.0)
    assert _row(rows, "Finance", "incident_response").revocations == 0
    assert _row(rows, "Finance").revocations == 3


def test_departments_are_separate_and_identities_outside_hr_are_skipped():
    events = [
        _grant(1, 1),
        _grant(2, 1, identity_id="emp-0002"),
        _revoke(2, 2, identity_id="emp-0002"),
        _grant(3, 1, identity_id="unlinked:aws:x"),
    ]
    rows = hl.halflife_by_department(events, IDS, 12)
    assert _row(rows, "Finance").grants == 1 and _row(rows, "Finance").revocations == 0
    assert _row(rows, "HR").grants == 1 and _row(rows, "HR").half_life_months == 1.0
    assert {r.department for r in rows} == {"Finance", "HR"}


def test_events_after_up_to_month_and_non_grant_kinds_are_ignored():
    events = [
        _grant(1, 1),
        _revoke(1, 9),
        f.event("ev-dep", 2, "departure", grant_delta={"removed": [_entry(1)]}),
    ]
    row = _row(hl.halflife_by_department(events, IDS, 6), "Finance")
    assert (row.grants, row.revocations) == (1, 0)


def test_rows_are_sorted_by_department_then_trigger_order():
    rows = hl.halflife_by_department([], IDS, 12)
    assert [(r.department, r.trigger) for r in rows][:6] == [
        ("Finance", "all"),
        ("Finance", "departure"),
        ("Finance", "role_change"),
        ("Finance", "project_retirement"),
        ("Finance", "incident_response"),
        ("HR", "all"),
    ]


def test_overall_rows_and_offboarding_headline_from_raw_intervals():
    events = [
        _grant(1, 1),
        _grant(2, 1, identity_id="emp-0002"),
        _revoke(1, 3),
        _revoke(2, 9, identity_id="emp-0002"),
    ]
    overall = hl.halflife_overall(events, IDS, 12)
    assert [r.department for r in overall] == ["all"] * len(hl.TRIGGERS)
    headline = hl.offboarding_headline(overall + hl.halflife_by_department(events, IDS, 12))
    assert headline == HalfLifeRow("all", "departure", 2, 2, 5.0, "Slow")


def test_offboarding_headline_aggregates_department_rows_when_no_overall_row():
    rows = [
        HalfLifeRow("Finance", "departure", 10, 2, 3.0, "Healthy"),
        HalfLifeRow("HR", "departure", 10, 1, 9.0, "Broken"),
        HalfLifeRow("HR", "all", 10, 5, 2.0, "Healthy"),
    ]
    headline = hl.offboarding_headline(rows)
    assert headline.department == "all" and headline.trigger == "departure"
    assert (headline.grants, headline.revocations, headline.half_life_months, headline.label) == (
        20,
        3,
        3.0,
        "Healthy",
    )


def test_offboarding_headline_is_never_when_ratio_too_low():
    rows = [
        HalfLifeRow("Finance", "departure", 34, 2, None, "Broken"),
        HalfLifeRow("HR", "departure", 30, 1, 2.0, "Healthy"),
    ]
    assert hl.offboarding_headline(rows).half_life_months is None


def test_half_life_map_for_timeline():
    rows = hl.halflife_by_department([_grant(1, 1), _revoke(1, 2)], IDS, 12)
    assert hl.half_life_map(rows) == {"Finance": 1.0, "HR": None}
