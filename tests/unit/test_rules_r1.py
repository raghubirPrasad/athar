"""R1 Wildcard / admin privilege (SPEC §7, §4.3): exceptions come from the register only."""

from __future__ import annotations

import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from athar.detection.facts import missing_slots
from test_rules_support import AWS_ACCT, AWS_USER, f, run, wide_grant

WILDCARD_SNIPPET = {"PolicyName": "AdministratorAccess", "Statement": [{"Action": "*", "Resource": "*"}]}


def _estate(*grants, identities=None, exceptions=()):  # type: ignore[no-untyped-def]
    return f.estate(
        identities=identities or [f.identity()],
        principals=[f.principal(AWS_USER)],
        grants=list(grants),
        exceptions=list(exceptions),
    )


def test_admin_at_project_scope_fires_high() -> None:
    drafts = run("R1", _estate(wide_grant("g-1", "aws", "admin")))
    assert len(drafts) == 1
    d = drafts[0]
    assert d.rule_id == "R1" and d.severity == "High"
    assert d.facts["scope_level"] == "project" and d.facts["scope_ref"] == AWS_ACCT
    assert d.facts["wildcard"] is False and d.facts["exception_expired_on"] is None
    assert d.facts["grant_ids"] == ["g-1"]


def test_admin_at_org_and_global_fire() -> None:
    est = _estate(
        wide_grant("g-org", "aws", "admin", scope_level="org", scope_ref="o-nda"),
        wide_grant("g-glob", "gcp", "admin", scope_level="global", scope_ref="*"),
    )
    drafts = run("R1", est)
    assert len(drafts) == 1 and drafts[0].facts["grant_ids"] == ["g-glob", "g-org"]
    assert drafts[0].facts["scope_level"] == "global"  # the worst grant drives the facts


def test_admin_at_resource_scope_does_not_fire() -> None:
    assert run("R1", _estate(f.grant("g-1", verb="admin", scope_level="resource"))) == []


def test_write_at_org_without_wildcard_does_not_fire() -> None:
    assert run("R1", _estate(wide_grant("g-1", "aws", "write", scope_level="org", scope_ref="o-nda"))) == []


def test_unexpanded_wildcard_fires_even_on_read_verb_at_resource_scope() -> None:
    drafts = run("R1", _estate(f.grant("g-1", verb="read", raw_snippet=WILDCARD_SNIPPET)))
    assert len(drafts) == 1 and drafts[0].facts["wildcard"] is True


def test_star_colon_star_is_a_wildcard() -> None:
    drafts = run("R1", _estate(f.grant("g-1", verb="write", raw_snippet={"Action": ["*:*"]})))
    assert len(drafts) == 1 and drafts[0].facts["wildcard"] is True


def test_azure_actions_star_is_a_wildcard() -> None:
    snippet = {"roleDefinitionName": "Owner", "permissions": [{"actions": ["*"], "notActions": []}]}
    drafts = run("R1", _estate(f.grant("g-1", cloud="azure", verb="write", raw_snippet=snippet)))
    assert len(drafts) == 1 and drafts[0].facts["wildcard"] is True


def test_service_wildcard_is_not_a_full_wildcard() -> None:
    assert run("R1", _estate(f.grant("g-1", verb="write", raw_snippet={"Action": ["s3:*"]}))) == []


def test_resource_star_is_not_an_action_wildcard() -> None:
    assert (
        run(
            "R1",
            _estate(f.grant("g-1", verb="write", raw_snippet={"Action": "s3:GetObject", "Resource": "*"})),
        )
        == []
    )


def test_valid_break_glass_entry_suppresses() -> None:
    est = _estate(wide_grant("g-1", "aws", "admin"), exceptions=[f.exception(exception_type="break-glass")])
    assert run("R1", est) == []


def test_valid_approved_privileged_role_entry_suppresses() -> None:
    est = _estate(
        wide_grant("g-1", "aws", "admin"),
        exceptions=[f.exception(exception_type="approved-privileged-role")],
    )
    assert run("R1", est) == []


def test_dr_failover_entry_does_not_suppress_r1() -> None:
    est = _estate(wide_grant("g-1", "aws", "admin"), exceptions=[f.exception(exception_type="dr-failover")])
    assert len(run("R1", est)) == 1


def test_entry_for_another_identity_does_not_suppress() -> None:
    est = _estate(wide_grant("g-1", "aws", "admin"), exceptions=[f.exception(identity_id="emp-0002")])
    assert len(run("R1", est)) == 1


def test_expired_review_date_fires_and_sets_exception_expired_on() -> None:
    est = _estate(
        wide_grant("g-1", "aws", "admin"),
        exceptions=[f.exception(review_date=date(2026, 3, 12), exception_id="exc-7")],
    )
    drafts = run("R1", est)
    assert len(drafts) == 1
    assert drafts[0].facts["exception_expired_on"] == "2026-03-12"
    assert ("exception", "exc-7") in {(e.kind, e.ref) for e in drafts[0].evidence}


def test_expired_expires_on_fires_with_earliest_passed_date() -> None:
    est = _estate(
        wide_grant("g-1", "aws", "admin"),
        exceptions=[f.exception(review_date=date(2026, 8, 1), expires_on=date(2026, 6, 1))],
    )
    assert run("R1", est)[0].facts["exception_expired_on"] == "2026-06-01"


def test_review_date_on_month_end_is_still_valid() -> None:
    est = _estate(wide_grant("g-1", "aws", "admin"), exceptions=[f.exception(review_date=date(2026, 8, 31))])
    assert run("R1", est) == []


def test_review_date_one_day_before_month_end_is_expired() -> None:
    est = _estate(wide_grant("g-1", "aws", "admin"), exceptions=[f.exception(review_date=date(2026, 8, 30))])
    assert run("R1", est)[0].facts["exception_expired_on"] == "2026-08-30"


def test_valid_entry_wins_over_an_expired_one() -> None:
    est = _estate(
        wide_grant("g-1", "aws", "admin"),
        exceptions=[
            f.exception(review_date=date(2026, 1, 1), exception_id="exc-old"),
            f.exception(review_date=date(2027, 1, 1), exception_id="exc-new"),
        ],
    )
    assert run("R1", est) == []


def test_cloud_tag_never_suppresses() -> None:
    """A tag saying 'break-glass' in provider data is evidence, not an exception (SPEC §4.3)."""
    tagged_identity = f.identity(tags={"exception": "break-glass", "break_glass": "true"})
    grant = wide_grant(
        "g-1", "aws", "admin", raw_snippet={"Action": "*", "Tags": {"exception": "break-glass"}}
    )
    est = _estate(grant, identities=[tagged_identity])
    drafts = run("R1", est)
    assert len(drafts) == 1 and drafts[0].facts["exception_expired_on"] is None


def test_deny_grants_are_ignored() -> None:
    assert run("R1", _estate(wide_grant("g-1", "aws", "admin", effect="deny"))) == []


def test_inactive_grants_are_ignored() -> None:
    assert run("R1", _estate(wide_grant("g-1", "aws", "admin", active=False))) == []


def test_causal_events_from_grant_delta_and_incident_response() -> None:
    est = f.estate(
        identities=[f.identity()],
        grants=[wide_grant("g-1", "aws", "admin", granted_via="managed_policy:AdministratorAccess")],
        events=[
            f.event(
                "ev-1",
                5,
                "role_change",
                grant_delta={"added": [{"principal_ref": AWS_USER, "scope_ref": AWS_ACCT}]},
            ),
            f.event("ev-2", 6, "incident_response", trigger="incident_response"),
            f.event(
                "ev-3",
                7,
                "role_change",
                grant_delta={"added": [{"principal_ref": AWS_USER, "scope_ref": "x"}]},
            ),
            f.event("ev-4", 8, "departure", identity_id="emp-0002"),
        ],
    )
    assert run("R1", est)[0].causal_event_ids == ["ev-1", "ev-2"]


def test_one_draft_per_identity_and_sorted() -> None:
    est = f.estate(
        identities=[f.identity("emp-0002"), f.identity("emp-0001")],
        grants=[
            wide_grant("g-b1", "aws", "admin", identity_id="emp-0002"),
            wide_grant("g-b2", "gcp", "admin", identity_id="emp-0002"),
            wide_grant("g-a1", "azure", "admin", identity_id="emp-0001"),
        ],
    )
    drafts = run("R1", est)
    assert [d.identity_id for d in drafts] == ["emp-0001", "emp-0002"]
    assert drafts[1].facts["grant_ids"] == ["g-b1", "g-b2"]


def test_deterministic_and_facts_complete() -> None:
    est = _estate(wide_grant("g-1", "aws", "admin", raw_snippet=WILDCARD_SNIPPET))
    a, b = run("R1", est), run("R1", est)
    assert a == b and missing_slots("R1", a[0].facts) == []
    assert a[0].facts["clouds"] == ["aws"] and a[0].facts["granted_via"] == "direct"
