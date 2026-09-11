"""R0 Unmapped permission (SPEC §5.3, §7): a mapping miss is a Low finding, never a crash."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from athar.detection.facts import missing_slots
from athar.normaliser.pipeline import normalise_provider, provider_rows_to_month, to_estate_view
from athar.normaliser.types import UNMAPPED_ACTIONS_KEY, HrBundle, HrEmployee
from test_rules_support import AWS_USER, f, run


def _estate(*grants):  # type: ignore[no-untyped-def]
    return f.estate(identities=[f.identity()], principals=[f.principal(AWS_USER)], grants=list(grants))


def test_unknown_verb_fires_low_with_grant_ids() -> None:
    est = _estate(
        f.grant("g-1", principal_ref=AWS_USER, verb="unknown", raw_snippet={"Action": "frobnicate:Widgets"})
    )
    drafts = run("R0", est)
    assert len(drafts) == 1
    d = drafts[0]
    assert d.rule_id == "R0" and d.severity == "Low" and d.identity_id == "emp-0001"
    assert d.facts["grant_ids"] == ["g-1"]
    assert d.facts["raw_action"] == "frobnicate:Widgets"
    assert d.facts["principal_ref"] == AWS_USER
    assert [e.ref for e in d.evidence] == ["g-1"]


def test_mapped_verbs_do_not_fire() -> None:
    est = _estate(f.grant("g-1", verb="admin"), f.grant("g-2", verb="read"))
    assert run("R0", est) == []


def test_inactive_unknown_grant_is_ignored() -> None:
    est = _estate(f.grant("g-1", verb="unknown", active=False))
    assert run("R0", est) == []


def test_unknown_deny_still_counts_as_mapping_miss() -> None:
    est = _estate(f.grant("g-1", verb="unknown", effect="deny", raw_snippet={"NotAction": "x:y"}))
    drafts = run("R0", est)
    assert len(drafts) == 1 and drafts[0].facts["raw_action"] == "x:y"


def test_raw_action_falls_back_when_snippet_has_no_action() -> None:
    est = _estate(f.grant("g-1", verb="unknown", raw_snippet={"weird": 1}))
    assert run("R0", est)[0].facts["raw_action"] == "unknown"


def test_raw_action_names_the_recorded_miss_not_the_first_action() -> None:
    """The statement's first action mapped; the recorded miss is the one that did not."""
    est = _estate(
        f.grant(
            "g-1",
            principal_ref=AWS_USER,
            verb="unknown",
            raw_snippet={
                "raw_action": ["s3:GetObject", "s3:PutObject", "mysteryservice:DoThing"],
                UNMAPPED_ACTIONS_KEY: ["mysteryservice:DoThing"],
            },
        )
    )
    assert run("R0", est)[0].facts["raw_action"] == "mysteryservice:DoThing"


def _mixed_statement_export() -> dict[str, bytes]:
    """One AWS user whose inline statement lists a mapped first action and an unmapped third."""
    document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Mixed",
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "mysteryservice:DoThing"],
                "Resource": "arn:aws:s3:::nda-finance-ledger/*",
            }
        ],
    }
    export = {
        "UserDetailList": [
            {
                "UserName": "maryam",
                "UserId": "AIDAEXAMPLE000000001",
                "Arn": AWS_USER,
                "CreateDate": "2025-09-01T08:00:00Z",
                "UserPolicyList": [{"PolicyName": "mixed-statement", "PolicyDocument": document}],
                "GroupList": [],
                "AttachedManagedPolicies": [],
                "Tags": [],
            }
        ],
        "GroupDetailList": [],
        "RoleDetailList": [],
        "Policies": [],
    }
    return {"authorization-details.json": json.dumps(export).encode()}


def _hr() -> HrBundle:
    return HrBundle(
        employees=[
            HrEmployee(
                employee_id="emp-0001",
                email="maryam@nda.example",
                display_name="Maryam",
                department="Finance",
                title="Analyst",
                employment_type="staff",
                status="active",
                start_date=None,
                end_date=None,
                contract_end=None,
                manager_id=None,
            )
        ]
    )


def test_mixed_statement_reports_the_third_action_not_the_first() -> None:
    """End to end: a mapped first action must not be blamed for a third action's mapping miss."""
    rows = normalise_provider("aws", 1, _mixed_statement_export(), _hr())
    assert [u.raw for u in rows.unmapped] == ["mysteryservice:DoThing"]
    nm = provider_rows_to_month(rows, _hr())
    nm.identities.append(f.identity("emp-0001"))
    unknown = [g for g in nm.grants if g.verb == "unknown"]
    assert unknown and all(g.raw_snippet[UNMAPPED_ACTIONS_KEY] == ["mysteryservice:DoThing"] for g in unknown)
    assert all(UNMAPPED_ACTIONS_KEY not in g.raw_snippet for g in nm.grants if g.verb != "unknown")

    drafts = run("R0", to_estate_view(nm))
    assert len(drafts) == 1
    assert drafts[0].facts["raw_action"] == "mysteryservice:DoThing"


def test_one_draft_per_identity_groups_all_unmapped_grants() -> None:
    est = _estate(
        f.grant("g-2", verb="unknown", cloud="gcp"),
        f.grant("g-1", verb="unknown"),
        f.grant("g-3", verb="read"),
    )
    drafts = run("R0", est)
    assert len(drafts) == 1
    assert drafts[0].facts["grant_ids"] == ["g-1", "g-2"]
    assert drafts[0].facts["cloud"] == "aws"  # facts describe the first grant by id
    assert sorted(drafts[0].facts["clouds"]) == ["aws", "gcp"]


def test_unlinked_identity_without_hr_row_still_fires() -> None:
    est = f.estate(grants=[f.grant("g-1", identity_id="unlinked:aws:x", verb="unknown")])
    drafts = run("R0", est)
    assert len(drafts) == 1 and drafts[0].identity_id == "unlinked:aws:x"
    assert drafts[0].facts["department"] is None


def test_causal_events_matched_from_grant_delta() -> None:
    est = f.estate(
        identities=[f.identity()],
        grants=[f.grant("g-1", principal_ref=AWS_USER, verb="unknown", scope_ref="arn:aws:s3:::odd")],
        events=[
            f.event("ev-1", 3, "role_change", grant_delta={"added": [{"grant_id": "g-1"}]}),
            f.event(
                "ev-2",
                4,
                "role_change",
                grant_delta={"added": [{"principal_ref": AWS_USER, "scope_ref": "arn:aws:s3:::odd"}]},
            ),
            f.event("ev-3", 5, "role_change", grant_delta={"added": [{"principal_ref": "other"}]}),
        ],
    )
    assert run("R0", est)[0].causal_event_ids == ["ev-1", "ev-2"]


def test_facts_complete_and_deterministic() -> None:
    est = _estate(f.grant("g-1", verb="unknown"))
    a, b = run("R0", est), run("R0", est)
    assert a == b
    assert missing_slots("R0", a[0].facts) == []


def test_ordered_by_identity_id() -> None:
    est = f.estate(
        identities=[f.identity("emp-0002"), f.identity("emp-0001")],
        grants=[
            f.grant("g-b", identity_id="emp-0002", verb="unknown"),
            f.grant("g-a", identity_id="emp-0001", verb="unknown"),
        ],
    )
    assert [d.identity_id for d in run("R0", est)] == ["emp-0001", "emp-0002"]
