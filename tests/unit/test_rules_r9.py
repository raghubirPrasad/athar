"""R9 Privileged human without MFA (SPEC §7): human ∧ admin|grant|impersonate ∧ mfa_enforced=false."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from athar.detection.facts import missing_slots
from test_rules_support import AWS_ROLE, AWS_USER, f, run, wide_grant


def _estate(*grants, identity=None, events=()):  # type: ignore[no-untyped-def]
    return f.estate(
        identities=[identity or f.identity(mfa_enforced=False)],
        principals=[f.principal(AWS_USER)],
        grants=list(grants),
        events=list(events),
    )


def test_human_admin_without_mfa_fires_high() -> None:
    drafts = run("R9", _estate(f.grant("g-1", verb="admin")))
    assert len(drafts) == 1
    d = drafts[0]
    assert d.severity == "High"
    assert d.facts["privileged_verbs"] == ["admin"] and d.facts["clouds_privileged"] == ["aws"]
    assert d.facts["grant_ids"] == ["g-1"]
    assert ("identity", "emp-0001") in {(e.kind, e.ref) for e in d.evidence}


def test_grant_verb_counts_as_privileged() -> None:
    assert len(run("R9", _estate(f.grant("g-1", verb="grant")))) == 1


def test_impersonate_verb_counts_as_privileged() -> None:
    drafts = run("R9", _estate(f.grant("g-1", verb="impersonate", scope_ref=AWS_ROLE)))
    assert drafts[0].facts["privileged_verbs"] == ["impersonate"]


def test_admin_at_resource_scope_still_counts() -> None:
    assert len(run("R9", _estate(f.grant("g-1", verb="admin", scope_level="resource")))) == 1


def test_write_delete_billing_are_not_privileged_here() -> None:
    est = _estate(f.grant("g-1", verb="write"), f.grant("g-2", verb="delete"), f.grant("g-3", verb="billing"))
    assert run("R9", est) == []


def test_mfa_enforced_does_not_fire() -> None:
    assert run("R9", _estate(f.grant("g-1", verb="admin"), identity=f.identity(mfa_enforced=True))) == []


def test_service_identity_does_not_fire() -> None:
    svc = f.identity(identity_type="service", employment_type="service", mfa_enforced=False)
    assert run("R9", _estate(f.grant("g-1", verb="admin"), identity=svc)) == []


def test_inactive_and_deny_grants_ignored() -> None:
    est = _estate(f.grant("g-1", verb="admin", active=False), f.grant("g-2", verb="grant", effect="deny"))
    assert run("R9", est) == []


def test_only_privileged_grants_are_cited() -> None:
    est = _estate(
        wide_grant("g-2", "gcp", "grant"),
        f.grant("g-1", verb="admin"),
        f.grant("g-3", verb="read"),
    )
    d = run("R9", est)[0]
    assert d.facts["grant_ids"] == ["g-1", "g-2"]
    assert d.facts["privileged_verbs"] == ["admin", "grant"] and d.facts["clouds_privileged"] == [
        "aws",
        "gcp",
    ]
    assert ("grant", "g-3") not in {(e.kind, e.ref) for e in d.evidence}


def test_mfa_lapse_event_is_cited_and_causal() -> None:
    est = _estate(
        f.grant("g-1", principal_ref=AWS_USER, verb="admin", scope_ref="arn:aws:s3:::x"),
        events=[
            f.event("ev-mfa", 9, "mfa_lapse", cloud=None, trigger="mfa_lapse"),
            f.event(
                "ev-grant",
                5,
                "incident_response",
                grant_delta={"added": [{"principal_ref": AWS_USER, "scope_ref": "arn:aws:s3:::x"}]},
            ),
            f.event("ev-none", 6, "role_change", grant_delta={"added": [{"principal_ref": "other"}]}),
        ],
    )
    d = run("R9", est)[0]
    assert d.causal_event_ids == ["ev-grant", "ev-mfa"]
    assert ("event", "ev-mfa") in {(e.kind, e.ref) for e in d.evidence}


def test_identity_without_hr_row_is_not_evaluated() -> None:
    est = f.estate(grants=[f.grant("g-1", identity_id="unlinked:aws:x", verb="admin")])
    assert run("R9", est) == []


def test_deterministic_sorted_and_facts_complete() -> None:
    est = f.estate(
        identities=[f.identity("emp-0002", mfa_enforced=False), f.identity("emp-0001", mfa_enforced=False)],
        grants=[
            f.grant("g-b", identity_id="emp-0002", verb="admin"),
            f.grant("g-a", identity_id="emp-0001", verb="grant"),
        ],
    )
    a, b = run("R9", est), run("R9", est)
    assert a == b and [d.identity_id for d in a] == ["emp-0001", "emp-0002"]
    assert all(missing_slots("R9", d.facts) == [] for d in a)
