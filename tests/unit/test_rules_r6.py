"""R6 Stale credential (SPEC §7): older than stale_key_days; SA keys past 365 days are High."""

from __future__ import annotations

import sys
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from athar.clock import month_end
from athar.detection.facts import missing_slots
from athar.domain import Thresholds
from test_rules_support import f, run

AS_OF = month_end(12)  # 2026-08-31
STALE_EDGE = AS_OF - timedelta(days=180)


def _estate(*creds, grants=(), identities=None):  # type: ignore[no-untyped-def]
    return f.estate(identities=identities or [f.identity()], credentials=list(creds), grants=list(grants))


def test_stale_key_fires_medium() -> None:
    est = _estate(f.credential(last_rotated_at=date(2025, 9, 1)), grants=[f.grant("g-1")])
    drafts = run("R6", est)
    assert len(drafts) == 1
    d = drafts[0]
    assert d.severity == "Medium" and d.facts["credential_ref"] == "aws:key:AKIA0001"
    assert d.facts["kind"] == "key" and d.facts["cloud"] == "aws"
    assert d.facts["age_days"] == (AS_OF - date(2025, 9, 1)).days
    assert d.facts["last_rotated_at"] == "2025-09-01" and d.facts["threshold_days"] == 180
    assert [e.ref for e in d.evidence] == ["aws:key:AKIA0001"]


def test_fresh_key_does_not_fire() -> None:
    assert run("R6", _estate(f.credential(last_rotated_at=date(2026, 8, 1)))) == []


def test_boundary_exactly_threshold_does_not_fire() -> None:
    assert run("R6", _estate(f.credential(last_rotated_at=STALE_EDGE))) == []


def test_boundary_one_day_over_threshold_fires() -> None:
    drafts = run("R6", _estate(f.credential(last_rotated_at=STALE_EDGE - timedelta(days=1))))
    assert len(drafts) == 1 and drafts[0].facts["age_days"] == 181


def test_threshold_comes_from_argument() -> None:
    est = _estate(f.credential(last_rotated_at=date(2026, 6, 1)))
    assert run("R6", est) == []
    assert len(run("R6", est, Thresholds(stale_key_days=30))) == 1
    assert run("R6", est, Thresholds(stale_key_days=30))[0].facts["threshold_days"] == 30


def test_inactive_credential_is_ignored() -> None:
    assert run("R6", _estate(f.credential(last_rotated_at=date(2025, 9, 1), active=False))) == []


def test_falls_back_to_created_at_when_never_rotated() -> None:
    drafts = run("R6", _estate(f.credential(last_rotated_at=None, created_at=date(2025, 10, 1))))
    assert len(drafts) == 1 and drafts[0].facts["last_rotated_at"] == "2025-10-01"


def test_credential_without_any_date_cannot_fire() -> None:
    assert run("R6", _estate(f.credential(last_rotated_at=None, created_at=None))) == []


def test_sa_key_over_365_days_is_high() -> None:
    cred = f.credential(
        "gcp:sa_key:k1", cloud="gcp", kind="sa_key", last_rotated_at=AS_OF - timedelta(days=366)
    )
    drafts = run("R6", _estate(cred))
    assert drafts[0].severity == "High" and drafts[0].facts["kind"] == "sa_key"


def test_sa_key_at_exactly_365_days_is_medium() -> None:
    cred = f.credential(
        "gcp:sa_key:k1", cloud="gcp", kind="sa_key", last_rotated_at=AS_OF - timedelta(days=365)
    )
    assert run("R6", _estate(cred))[0].severity == "Medium"


def test_user_key_over_365_days_stays_medium() -> None:
    assert (
        run("R6", _estate(f.credential(last_rotated_at=AS_OF - timedelta(days=400))))[0].severity == "Medium"
    )


def test_one_draft_cites_all_stale_credentials_and_facts_describe_the_worst() -> None:
    est = _estate(
        f.credential("aws:key:old", last_rotated_at=AS_OF - timedelta(days=500)),
        f.credential(
            "gcp:sa_key:k1", cloud="gcp", kind="sa_key", last_rotated_at=AS_OF - timedelta(days=400)
        ),
        f.credential("aws:key:fresh", last_rotated_at=AS_OF - timedelta(days=10)),
    )
    drafts = run("R6", est)
    assert len(drafts) == 1
    d = drafts[0]
    assert d.severity == "High" and d.facts["credential_ref"] == "gcp:sa_key:k1"  # severity driver wins
    assert d.facts["credential_refs"] == ["aws:key:old", "gcp:sa_key:k1"]
    assert sorted(e.ref for e in d.evidence) == ["aws:key:old", "gcp:sa_key:k1"]
    assert d.facts["clouds"] == ["aws", "gcp"]


def test_oldest_credential_drives_facts_when_none_is_high() -> None:
    est = _estate(
        f.credential("aws:key:a", last_rotated_at=AS_OF - timedelta(days=200)),
        f.credential("aws:key:b", last_rotated_at=AS_OF - timedelta(days=300)),
    )
    assert run("R6", est)[0].facts["credential_ref"] == "aws:key:b"


def test_identity_without_grants_still_fires_with_credential_clouds() -> None:
    drafts = run("R6", _estate(f.credential(last_rotated_at=date(2025, 9, 1))))
    assert len(drafts) == 1 and drafts[0].facts["clouds"] == ["aws"]


def test_causal_events_mentioning_the_credential() -> None:
    est = f.estate(
        identities=[f.identity()],
        credentials=[f.credential(last_rotated_at=date(2025, 9, 1))],
        events=[
            f.event(
                "ev-key", 1, "project_launch", grant_delta={"added": [{"credential_ref": "aws:key:AKIA0001"}]}
            ),
            f.event("ev-other", 2, "role_change", grant_delta={"added": [{"grant_id": "g-9"}]}),
        ],
    )
    assert run("R6", est)[0].causal_event_ids == ["ev-key"]


def test_causal_match_is_structural_not_substring() -> None:
    est = f.estate(
        identities=[f.identity()],
        credentials=[f.credential(last_rotated_at=date(2025, 9, 1))],
        events=[
            f.event(
                "ev-list", 1, "project_launch", grant_delta={"keys": [{"credential_ref": "aws:key:AKIA0001"}]}
            ),
            f.event("ev-note", 2, "role_change", grant_delta={"note": "rotated aws:key:AKIA0001"}),
            f.event(
                "ev-partial",
                3,
                "role_change",
                grant_delta={"added": [{"credential_ref": "aws:key:AKIA00011"}]},
            ),
        ],
    )
    assert run("R6", est)[0].causal_event_ids == ["ev-list"]


def test_deterministic_sorted_and_facts_complete() -> None:
    est = f.estate(
        identities=[f.identity("emp-0002"), f.identity("emp-0001")],
        credentials=[
            f.credential("aws:key:b", identity_id="emp-0002", last_rotated_at=date(2025, 9, 1)),
            f.credential("aws:key:a", identity_id="emp-0001", last_rotated_at=date(2025, 9, 1)),
        ],
    )
    a, b = run("R6", est), run("R6", est)
    assert a == b and [d.identity_id for d in a] == ["emp-0001", "emp-0002"]
    assert all(missing_slots("R6", d.facts) == [] for d in a)
