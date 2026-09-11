"""R10 Unowned principal (SPEC §6, §7): the linker fell through; finding on `unlinked:<cloud>:<ref>`."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from athar.detection.facts import missing_slots
from test_rules_support import AWS_USER, f, r10_module, run

LINK_ATTEMPTS = r10_module.LINK_ATTEMPTS
synthetic_identity_id = r10_module.synthetic_identity_id

GHOST = "user:ghost@nda.example"
GHOST_ID = f"unlinked:gcp:{GHOST}"


def _ghost(identity_id: str | None = None, **kw):  # type: ignore[no-untyped-def]
    base = dict(cloud="gcp", identity_id=identity_id, link_method="unlinked", link_confidence="heuristic")
    base.update(kw)
    return f.principal(GHOST, **base)


def test_unlinked_principal_fires_on_synthetic_identity() -> None:
    est = f.estate(principals=[_ghost()])
    drafts = run("R10", est)
    assert len(drafts) == 1
    d = drafts[0]
    assert d.identity_id == GHOST_ID and d.severity == "Medium"
    assert d.facts["cloud"] == "gcp" and d.facts["principal_ref"] == GHOST
    assert d.facts["principal_type"] == "user" and d.facts["grant_ids"] == []
    assert d.facts["link_attempts"] == [
        "hr_email",
        "entra_directory",
        "aws_username",
        "sa_project",
        "tag_owner",
    ]
    assert [(e.kind, e.ref) for e in d.evidence] == [("principal", GHOST)]


def test_link_attempts_follow_the_linker_order_in_spec_6() -> None:
    assert LINK_ATTEMPTS == ("hr_email", "entra_directory", "aws_username", "sa_project", "tag_owner")


def test_linked_principals_do_not_fire() -> None:
    est = f.estate(
        identities=[f.identity()],
        principals=[
            f.principal(AWS_USER),
            f.principal("x", cloud="gcp", identity_id="emp-0001", link_method="tag_owner"),
        ],
    )
    assert run("R10", est) == []


def test_grants_carrying_the_synthetic_identity_are_cited() -> None:
    est = f.estate(
        principals=[_ghost()],
        grants=[
            f.grant("g-2", identity_id=GHOST_ID, principal_ref=GHOST, cloud="gcp", verb="write"),
            f.grant("g-1", identity_id=GHOST_ID, principal_ref=GHOST, cloud="gcp"),
        ],
    )
    d = run("R10", est)[0]
    assert d.facts["grant_ids"] == ["g-1", "g-2"] and d.facts["clouds"] == ["gcp"]
    assert ("grant", "g-1") in {(e.kind, e.ref) for e in d.evidence}


def test_grants_matched_by_principal_ref_are_cited_too() -> None:
    est = f.estate(
        principals=[_ghost()], grants=[f.grant("g-1", identity_id="", principal_ref=GHOST, cloud="gcp")]
    )
    assert run("R10", est)[0].facts["grant_ids"] == ["g-1"]


def test_inactive_grants_are_not_cited() -> None:
    est = f.estate(
        principals=[_ghost()],
        grants=[f.grant("g-1", identity_id=GHOST_ID, principal_ref=GHOST, active=False)],
    )
    assert run("R10", est)[0].facts["grant_ids"] == []


def test_normaliser_assigned_identity_id_is_respected() -> None:
    est = f.estate(principals=[_ghost(identity_id="unlinked:gcp:custom")])
    assert run("R10", est)[0].identity_id == "unlinked:gcp:custom"
    assert synthetic_identity_id(_ghost()) == GHOST_ID


def test_common_facts_for_an_identity_outside_hr() -> None:
    d = run("R10", f.estate(principals=[_ghost(principal_type="service_account")]))[0]
    assert d.facts["department"] is None and d.facts["identity_type"] == "service"
    assert d.facts["display_name"] == GHOST


def test_user_principal_type_is_reported_as_human() -> None:
    assert (
        run("R10", f.estate(principals=[_ghost(principal_type="user")]))[0].facts["identity_type"] == "human"
    )


def test_causal_events_from_grant_delta() -> None:
    est = f.estate(
        principals=[_ghost()],
        grants=[
            f.grant("g-1", identity_id=GHOST_ID, principal_ref=GHOST, cloud="gcp", scope_ref="projects/p")
        ],
        events=[
            f.event(
                "ev-1",
                6,
                "project_launch",
                identity_id=GHOST_ID,
                cloud="gcp",
                grant_delta={"added": [{"principal_ref": GHOST, "scope_ref": "projects/p"}]},
            ),
        ],
    )
    assert run("R10", est)[0].causal_event_ids == ["ev-1"]


def test_deterministic_sorted_and_facts_complete() -> None:
    est = f.estate(
        principals=[
            f.principal("zeta", cloud="aws", identity_id=None, link_method="unlinked"),
            f.principal("alpha", cloud="azure", identity_id=None, link_method="unlinked"),
        ]
    )
    a, b = run("R10", est), run("R10", est)
    assert a == b and [d.identity_id for d in a] == ["unlinked:aws:zeta", "unlinked:azure:alpha"]
    assert all(missing_slots("R10", d.facts) == [] for d in a)
