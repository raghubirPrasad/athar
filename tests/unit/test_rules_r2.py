"""R2 Dormant access (SPEC §7, §4.3): idle ≥ dormant_days with standing non-read access."""

from __future__ import annotations

import sys
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from athar.clock import month_end
from athar.detection.facts import missing_slots
from athar.domain import Thresholds
from test_rules_support import AWS_USER, f, run

AS_OF = month_end(12)  # 2026-08-31
DORMANT_EDGE = AS_OF - timedelta(days=90)


def _estate(*grants, activity=(), identities=None, exceptions=()):  # type: ignore[no-untyped-def]
    return f.estate(
        identities=identities or [f.identity()],
        principals=[f.principal(AWS_USER)],
        grants=list(grants),
        activity=list(activity),
        exceptions=list(exceptions),
    )


def test_dormant_with_write_grant_fires_medium() -> None:
    est = _estate(f.grant("g-1", verb="write"), activity=[f.activity(last=date(2026, 2, 1))])
    drafts = run("R2", est)
    assert len(drafts) == 1
    d = drafts[0]
    assert d.severity == "Medium" and d.facts["last_activity_at"] == "2026-02-01"
    assert d.facts["dormant_days"] == (AS_OF - date(2026, 2, 1)).days
    assert d.facts["clouds_with_write"] == ["aws"] and d.facts["grant_ids"] == ["g-1"]
    assert d.facts["exception_expired_on"] is None


def test_recent_activity_in_any_category_does_not_fire() -> None:
    est = _estate(
        f.grant("g-1", verb="write", service_category="storage"),
        activity=[
            f.activity(category="storage", last=date(2026, 1, 1)),
            f.activity(cloud="gcp", category="compute", last=date(2026, 8, 20)),
        ],
    )
    assert run("R2", est) == []


def test_only_read_grants_never_fire() -> None:
    est = _estate(f.grant("g-1", verb="read"), activity=[f.activity(last=date(2025, 10, 1))])
    assert run("R2", est) == []


def test_unknown_verb_is_not_standing_privilege() -> None:
    est = _estate(f.grant("g-1", verb="unknown"), activity=[f.activity(last=date(2025, 10, 1))])
    assert run("R2", est) == []


def test_boundary_exactly_dormant_days_fires() -> None:
    est = _estate(f.grant("g-1", verb="delete"), activity=[f.activity(last=DORMANT_EDGE)])
    assert run("R2", est)[0].facts["dormant_days"] == 90


def test_one_day_under_threshold_does_not_fire() -> None:
    est = _estate(f.grant("g-1", verb="delete"), activity=[f.activity(last=DORMANT_EDGE + timedelta(days=1))])
    assert run("R2", est) == []


def test_threshold_comes_from_argument_not_config() -> None:
    est = _estate(f.grant("g-1", verb="write"), activity=[f.activity(last=date(2026, 2, 1))])
    assert run("R2", est, Thresholds(dormant_days=400)) == []
    assert len(run("R2", est, Thresholds(dormant_days=10))) == 1


def test_no_activity_and_present_long_enough_fires_with_identity_evidence() -> None:
    est = _estate(f.grant("g-1", verb="write"), identities=[f.identity(first_seen_month=1, hire_month=1)])
    drafts = run("R2", est)
    assert len(drafts) == 1
    d = drafts[0]
    assert d.facts["last_activity_at"] is None
    assert d.facts["dormant_days"] == (AS_OF - date(2025, 9, 1)).days
    assert ("identity", "emp-0001") in {(e.kind, e.ref) for e in d.evidence}


def test_no_activity_but_recently_seen_does_not_fire() -> None:
    est = _estate(f.grant("g-1", verb="write"), identities=[f.identity(first_seen_month=12, hire_month=12)])
    assert run("R2", est) == []


def test_valid_dr_failover_entry_suppresses() -> None:
    est = _estate(
        f.grant("g-1", verb="write"),
        activity=[f.activity(last=date(2025, 10, 1))],
        exceptions=[f.exception(exception_type="dr-failover")],
    )
    assert run("R2", est) == []


def test_break_glass_entry_does_not_suppress_r2() -> None:
    est = _estate(
        f.grant("g-1", verb="write"),
        activity=[f.activity(last=date(2025, 10, 1))],
        exceptions=[f.exception(exception_type="break-glass")],
    )
    assert len(run("R2", est)) == 1


def test_expired_dr_failover_fires_with_exception_expired_on() -> None:
    est = _estate(
        f.grant("g-1", verb="write"),
        activity=[f.activity(last=date(2025, 10, 1))],
        exceptions=[
            f.exception(exception_type="dr-failover", review_date=date(2026, 5, 5), exception_id="exc-dr")
        ],
    )
    drafts = run("R2", est)
    assert drafts[0].facts["exception_expired_on"] == "2026-05-05"
    assert ("exception", "exc-dr") in {(e.kind, e.ref) for e in drafts[0].evidence}


def test_cloud_tag_never_suppresses() -> None:
    """tags={'exception': 'dr-failover'} on the identity or grant is not a register entry (SPEC §4.3)."""
    est = _estate(
        f.grant("g-1", verb="write", raw_snippet={"Tags": [{"Key": "exception", "Value": "dr-failover"}]}),
        activity=[f.activity(last=date(2025, 10, 1))],
        identities=[f.identity(tags={"exception": "dr-failover"})],
    )
    drafts = run("R2", est)
    assert len(drafts) == 1 and drafts[0].facts["exception_expired_on"] is None


def test_activity_evidence_cites_activity_keys() -> None:
    est = _estate(
        f.grant("g-1", verb="write"),
        activity=[f.activity(last=date(2026, 1, 3)), f.activity(cloud="gcp", category="data", last=None)],
    )
    refs = {(e.kind, e.ref) for e in run("R2", est)[0].evidence}
    assert ("activity", "emp-0001|aws|storage|12") in refs
    assert ("activity", "emp-0001|gcp|data|12") in refs
    assert ("grant", "g-1") in refs


def test_inactive_and_deny_grants_do_not_count() -> None:
    est = _estate(
        f.grant("g-1", verb="write", active=False),
        f.grant("g-2", verb="write", effect="deny"),
        activity=[f.activity(last=date(2025, 10, 1))],
    )
    assert run("R2", est) == []


def test_identity_without_hr_row_is_not_evaluated() -> None:
    est = f.estate(grants=[f.grant("g-1", identity_id="unlinked:aws:x", verb="write")])
    assert run("R2", est) == []


def test_deterministic_sorted_and_facts_complete() -> None:
    est = f.estate(
        identities=[f.identity("emp-0002"), f.identity("emp-0001")],
        grants=[
            f.grant("g-b", identity_id="emp-0002", verb="write"),
            f.grant("g-a", identity_id="emp-0001", verb="write", cloud="gcp"),
        ],
        activity=[
            f.activity("emp-0001", last=date(2025, 12, 1)),
            f.activity("emp-0002", last=date(2025, 12, 1)),
        ],
    )
    a, b = run("R2", est), run("R2", est)
    assert a == b and [d.identity_id for d in a] == ["emp-0001", "emp-0002"]
    assert all(missing_slots("R2", d.facts) == [] for d in a)
