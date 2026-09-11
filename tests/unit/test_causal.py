"""Causal history (SPEC §9.2): ordered steps from cited + state events, activity stop, phrases."""

from __future__ import annotations

from athar.detection.base import EvidenceRef, FindingDraft
from athar.drift import causal
from tests import factories as f

GCP_OWNER = {"cloud": "gcp", "role": "roles/owner", "scope_ref": "nda-analytics-prod", "verb": "admin"}
AWS_ADMIN = {
    "cloud": "aws",
    "grant_id": "g-3",
    "verb": "admin",
    "service_category": "compute",
    "scope_ref": "o-root",
}


def _events():
    return [
        f.event("ev-0011-hr", 11, "departure", cloud=None, trigger="departure"),
        f.event(
            "ev-0007-gcp",
            7,
            "role_change",
            cloud="gcp",
            trigger="role_change",
            grant_delta={"added": [GCP_OWNER]},
        ),
        f.event(
            "diff-3-g-3",
            3,
            "grant",
            cloud="aws",
            trigger="new_hire",
            grant_delta={"added": [AWS_ADMIN], "removed": []},
        ),
        f.event(
            "diff-5-g-9",
            5,
            "grant",
            cloud="azure",
            trigger="unknown",
            grant_delta={"added": [{"role": "Reader"}]},
        ),
        f.event("ev-0002-other", 2, "role_change", identity_id="emp-0002", trigger="role_change"),
        f.event("ev-0009-mfa", 9, "mfa_lapse", cloud="azure", trigger="mfa_lapse"),
    ]


def _draft(**facts) -> FindingDraft:
    return FindingDraft("R3", "emp-0001", "Critical", [EvidenceRef("grant", "g-3")], ["diff-3-g-3"], facts)


def test_steps_are_ordered_by_month_then_event_id():
    estate = f.estate(identities=[f.identity("emp-0001")], events=_events())
    steps = causal.causal_history(estate, _draft())
    assert [(s.month, s.event_id) for s in steps] == [
        (3, "diff-3-g-3"),
        (7, "ev-0007-gcp"),
        (9, "ev-0009-mfa"),
        (11, "ev-0011-hr"),
    ]


def test_only_cited_and_state_changing_events_are_included():
    estate = f.estate(identities=[f.identity("emp-0001")], events=_events())
    ids = {s.event_id for s in causal.causal_history(estate, _draft())}
    assert "diff-5-g-9" not in ids  # a grant the rule did not cite
    assert "ev-0002-other" not in ids  # another identity
    assert {"ev-0007-gcp", "ev-0011-hr", "ev-0009-mfa"} <= ids  # role change, departure, MFA lapse always


def test_activity_stop_step_from_r2_style_facts():
    estate = f.estate(identities=[f.identity("emp-0001")], events=_events())
    steps = causal.causal_history(estate, _draft(last_activity_at="2026-05-14"))  # month 9
    stop = next(s for s in steps if s.kind == "activity_stop")
    assert stop.month == 9 and stop.trigger == "unknown" and stop.cloud is None
    assert stop.event_id == "activity-stop-emp-0001-2026-05-14"
    assert stop.description == "last activity recorded on 2026-05-14"
    months = [s.month for s in steps]
    assert months == sorted(months)


def test_no_activity_stop_without_a_date():
    estate = f.estate(identities=[f.identity("emp-0001")], events=_events())
    kinds = {s.kind for s in causal.causal_history(estate, _draft(last_activity_at=None, dormant_days=200))}
    assert "activity_stop" not in kinds
    kinds = {s.kind for s in causal.causal_history(estate, _draft(last_activity_at="not-a-date"))}
    assert "activity_stop" not in kinds


def test_events_after_the_snapshot_month_are_excluded():
    estate = f.estate(month=6, identities=[f.identity("emp-0001")], events=_events())
    assert [s.month for s in causal.causal_history(estate, _draft())] == [3]


def test_descriptions_are_deterministic_phrases():
    steps = {s.event_id: s for s in causal.causal_history(f.estate(events=_events()), _draft())}
    assert steps["ev-0007-gcp"].description == "role changed; GCP roles/owner on nda-analytics-prod added"
    assert steps["diff-3-g-3"].description == "AWS admin compute on o-root added (new hire)"
    assert steps["ev-0011-hr"].description == "HR status changed to departed"
    assert steps["ev-0009-mfa"].description == "multi-factor authentication flag turned off"
    assert steps["ev-0007-gcp"].grant_delta == {"added": [GCP_OWNER]}


def test_describe_revoke_and_string_entries():
    evt = f.event(
        "diff-11-g-1",
        11,
        "revoke",
        cloud="azure",
        trigger="departure",
        grant_delta={"added": [], "removed": ["Contributor on rg-payments"]},
    )
    assert causal.describe(evt) == "Contributor on rg-payments removed (departure)"
    plain = f.event("ev-x", 4, "incident_response", trigger="incident_response")
    assert causal.describe(plain) == "emergency access granted during incident response"


def test_same_input_yields_identical_steps():
    estate = f.estate(identities=[f.identity("emp-0001")], events=_events())
    assert causal.causal_history(estate, _draft(last_activity_at="2026-05-14")) == causal.causal_history(
        estate, _draft(last_activity_at="2026-05-14")
    )
