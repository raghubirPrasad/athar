"""Snapshot diff (SPEC §9.1): grant/revoke events, deterministic ids, trigger join."""

from __future__ import annotations

from athar.drift import diff
from tests import factories as f

ROLE = "arn:aws:iam::123456789012:role/PlatformAdmin"


def _g(grant_id: str, month: int, **kw):
    return f.grant(grant_id, snapshot_month=month, **kw)


def test_first_snapshot_makes_every_active_row_a_grant_event():
    curr = [_g("g-1", 1), _g("g-2", 1, verb="write"), _g("g-3", 1, active=False)]
    events = diff.diff_snapshots(None, curr, [], 1)
    assert [e.event_id for e in events] == ["diff-1-g-1", "diff-1-g-2"]
    assert {e.kind for e in events} == {"grant"}
    assert all(e.trigger == "unknown" and e.month == 1 and e.identity_id == "emp-0001" for e in events)


def test_added_and_removed_rows_produce_grant_and_revoke():
    prev = [_g("g-1", 4), _g("g-2", 4, verb="write")]
    curr = [_g("g-1b", 5), _g("g-3", 5, verb="delete")]  # g-1b == g-1 on the natural key
    events = diff.diff_snapshots(prev, curr, [], 5)
    assert [(e.kind, e.event_id) for e in events] == [("revoke", "diff-5-g-2"), ("grant", "diff-5-g-3")]
    revoke = events[0]
    assert revoke.grant_delta == {"added": [], "removed": [diff.delta_entry(prev[1])]}
    assert revoke.cloud == "aws" and "removed" in revoke.note


def test_snapshot_month_is_not_part_of_the_comparison():
    prev = [_g("g-1", 4)]
    curr = [_g("g-1", 5)]
    assert diff.diff_snapshots(prev, curr, [], 5) == []


def test_row_that_became_inactive_counts_as_revoked():
    prev = [_g("g-1", 4)]
    curr = [_g("g-1", 5, active=False)]
    events = diff.diff_snapshots(prev, curr, [], 5)
    assert [(e.kind, e.event_id) for e in events] == [("revoke", "diff-5-g-1")]


def test_grant_delta_carries_the_fields_the_causal_history_needs():
    entry = diff.delta_entry(_g("g-9", 3, verb="admin", scope_level="project", scope_ref="123456789012"))
    assert {
        "grant_id",
        "cloud",
        "verb",
        "service_category",
        "scope_ref",
        "granted_via",
        "principal_ref",
    } <= set(entry)
    assert entry["grant_id"] == "g-9" and entry["verb"] == "admin" and entry["scope_level"] == "project"


def test_trigger_is_joined_from_a_generator_event_for_the_same_identity_and_month():
    curr = [_g("g-1", 7, verb="admin", scope_level="project", scope_ref="123456789012")]
    generator = [
        f.event(
            "ev-7-role",
            7,
            "role_change",
            trigger="role_change",
            grant_delta={"grants_added": [{"scope_ref": "123456789012", "verb": "admin"}]},
        ),
        f.event(
            "ev-7-other",
            7,
            "role_change",
            identity_id="emp-0002",
            trigger="role_change",
            grant_delta={"added": [{"scope_ref": "123456789012"}]},
        ),
    ]
    events = diff.diff_snapshots([], curr, generator, 7)
    assert events[0].trigger == "role_change"


def test_trigger_falls_back_to_the_generator_events_kind_when_it_has_none():
    curr = [_g("g-1", 7)]
    generator = [f.event("ev-7", 7, "incident_response", trigger="unknown", grant_delta={"added": ["g-1"]})]
    assert diff.diff_snapshots([], curr, generator, 7)[0].trigger == "incident_response"


def test_revoke_trigger_uses_removed_entries_and_departure():
    prev = [_g("g-1", 10, verb="write")]
    generator = [
        f.event(
            "ev-11-dep",
            11,
            "departure",
            trigger="departure",
            grant_delta={
                "removed": [{"principal_ref": prev[0].principal_ref, "scope_ref": prev[0].scope_ref}]
            },
        ),
    ]
    events = diff.diff_snapshots(prev, [], generator, 11)
    assert events[0].kind == "revoke" and events[0].trigger == "departure"


def test_trigger_unknown_when_month_or_delta_do_not_match():
    curr = [_g("g-1", 7)]
    generator = [
        f.event("ev-6", 6, "role_change", grant_delta={"added": ["g-1"]}),  # wrong month
        f.event(
            "ev-7", 7, "role_change", grant_delta={"added": [{"scope_ref": "somewhere-else"}]}
        ),  # wrong grant
        f.event("ev-7b", 7, "role_change", grant_delta={"added": [{"cloud": "aws"}]}),  # names no grant
    ]
    assert diff.diff_snapshots([], curr, generator, 7)[0].trigger == "unknown"


def test_output_is_sorted_and_stable_across_runs():
    prev = [_g("g-b", 2, verb="write"), _g("g-a", 2)]
    curr = [_g("g-z", 3, verb="delete"), _g("g-y", 3, verb="admin")]
    once = diff.diff_snapshots(prev, curr, [], 3)
    twice = diff.diff_snapshots(list(reversed(prev)), list(reversed(curr)), [], 3)
    assert once == twice
    assert [e.event_id for e in once] == sorted(e.event_id for e in once)


def test_duplicate_natural_keys_in_one_snapshot_are_collapsed():
    curr = [_g("g-2", 1), _g("g-1", 1)]  # same natural key, both active
    events = diff.diff_snapshots(None, curr, [], 1)
    assert [e.event_id for e in events] == ["diff-1-g-1"]
