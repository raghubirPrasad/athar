"""Shared rule helpers (lane C1, `athar.detection.common`): row selection, wildcard detection,
scope overlap, evidence ordering, causal-event matching and the governance register (SPEC §4.3, §7, §9.2)."""

from __future__ import annotations

import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from athar.detection import common
from athar.detection.base import EvidenceRef
from test_rules_support import AWS_ACCT, AWS_USER, AZ_SUB, GCP_PROJECT, GCP_PROJECT_REF, f


def test_verify_suffixes_every_reference() -> None:
    assert common.verify("T1078.004", "A.5.18") == ("T1078.004 (verify)", "A.5.18 (verify)")
    assert common.verify() == ()


def test_identity_ids_union_of_rows_and_grant_holders_sorted() -> None:
    est = f.estate(
        identities=[f.identity("emp-0002")],
        grants=[f.grant("g-1", identity_id="unlinked:aws:x"), f.grant("g-2", identity_id="")],
    )
    assert common.identity_ids(est) == ["emp-0002", "unlinked:aws:x"]


def test_active_allow_grants_filters_and_sorts() -> None:
    est = f.estate(
        identities=[f.identity()],
        grants=[
            f.grant("g-c"),
            f.grant("g-a", effect="deny"),
            f.grant("g-b", active=False),
            f.grant("g-0"),
        ],
    )
    assert [g.grant_id for g in common.active_allow_grants(est, "emp-0001")] == ["g-0", "g-c"]


def test_raw_actions_collects_nested_action_keys_in_order() -> None:
    snippet = {
        "PolicyName": "Custom",
        "Statement": [
            {"Action": ["s3:GetObject", "s3:PutObject"], "Resource": "*"},
            {"NotAction": "iam:*"},
        ],
        "permissions": [{"actions": ["*"]}],
    }
    assert common.raw_actions(snippet) == ["Custom", "s3:GetObject", "s3:PutObject", "iam:*", "*"]
    assert common.raw_actions("*") == [] and common.raw_actions(None) == []


def test_has_wildcard_only_for_full_wildcards() -> None:
    assert common.has_wildcard(f.grant("g", raw_snippet={"Action": "*"}))
    assert common.has_wildcard(f.grant("g", raw_snippet={"Action": ["s3:Get*", "*:*"]}))
    assert not common.has_wildcard(f.grant("g", raw_snippet={"Action": "s3:*", "Resource": "*"}))
    assert not common.has_wildcard(f.grant("g", raw_snippet={}))


def test_scope_root_per_cloud() -> None:
    assert common.scope_root("aws", f"arn:aws:iam::{AWS_ACCT}:role/x") == AWS_ACCT
    assert common.scope_root("aws", "arn:aws:s3:::bucket/*") == "arn:aws:s3:::bucket/*"
    assert common.scope_root("aws", AWS_ACCT) == AWS_ACCT
    assert common.scope_root("azure", f"{AZ_SUB}/resourceGroups/rg-1") == AZ_SUB
    assert common.scope_root("gcp", f"{GCP_PROJECT_REF}/buckets/b") == GCP_PROJECT_REF
    assert common.scope_root("gcp", GCP_PROJECT) == GCP_PROJECT


def test_project_ref_matches_exact_root_and_last_segment_only() -> None:
    assert common.project_ref_matches("gcp", GCP_PROJECT_REF, GCP_PROJECT)
    assert common.project_ref_matches("gcp", f"{GCP_PROJECT_REF}/buckets/b", GCP_PROJECT_REF)
    assert common.project_ref_matches("aws", f"arn:aws:iam::{AWS_ACCT}:user/u", AWS_ACCT)
    assert common.project_ref_matches("azure", f"{AZ_SUB}/resourceGroups/rg", AZ_SUB)
    assert not common.project_ref_matches("gcp", GCP_PROJECT_REF, "prod")  # substring is not a match
    assert not common.project_ref_matches("gcp", GCP_PROJECT_REF, None)
    assert not common.project_ref_matches("gcp", GCP_PROJECT_REF, "")


def test_scopes_overlap_cases() -> None:
    same = f.grant("a", scope_ref="arn:aws:s3:::b")
    assert common.scopes_overlap(same, f.grant("b", scope_ref="arn:aws:s3:::b"))
    assert common.scopes_overlap(same, f.grant("b", scope_ref="arn:aws:s3:::b/*"))  # prefix
    assert common.scopes_overlap(same, f.grant("b", scope_level="global", scope_ref="*"))
    wide = f.grant("w", scope_level="project", scope_ref=AWS_ACCT)
    assert common.scopes_overlap(wide, f.grant("b", scope_ref=f"arn:aws:iam::{AWS_ACCT}:role/r"))
    assert not common.scopes_overlap(wide, f.grant("b", scope_ref="arn:aws:iam::999999999999:role/r"))
    assert not common.scopes_overlap(same, f.grant("b", cloud="gcp", scope_ref="arn:aws:s3:::b"))
    assert not common.scopes_overlap(same, f.grant("b", scope_ref="arn:aws:s3:::other"))


def test_worst_grant_prefers_scope_then_admin_then_id() -> None:
    rows = [
        f.grant("g-3", verb="admin", scope_level="resource"),
        f.grant("g-2", verb="write", scope_level="project"),
        f.grant("g-1", verb="admin", scope_level="project"),
        f.grant("g-0", verb="admin", scope_level="project"),
    ]
    assert common.worst_grant(rows).grant_id == "g-0"
    assert common.worst_grant(rows[:2]).grant_id == "g-2"


def test_present_days_uses_first_seen_then_hire_month() -> None:
    est = f.estate(identities=[f.identity(first_seen_month=10, hire_month=3)])
    assert common.present_days(est, "emp-0001") == (est.as_of - date(2026, 6, 1)).days
    est = f.estate(identities=[f.identity(first_seen_month=1)])
    assert common.present_days(est, "emp-0001") == (est.as_of - date(2025, 9, 1)).days
    assert common.present_days(f.estate(), "ghost") == (f.estate().as_of - date(2025, 9, 1)).days


def test_sort_evidence_deduplicates_and_orders() -> None:
    out = common.sort_evidence(
        [
            EvidenceRef("grant", "g-2"),
            EvidenceRef("activity", "k"),
            EvidenceRef("grant", "g-2"),
            EvidenceRef("grant", "g-1"),
        ]
    )
    assert [(e.kind, e.ref) for e in out] == [("activity", "k"), ("grant", "g-1"), ("grant", "g-2")]


def test_activity_refs_use_the_activity_key_format() -> None:
    est = f.estate(identities=[f.identity()], activity=[f.activity(cloud="gcp", category="data", last=None)])
    refs = common.activity_refs(est, "emp-0001")
    assert [(e.kind, e.ref, e.note) for e in refs] == [
        ("activity", "emp-0001|gcp|data|12", "last activity never")
    ]


def test_causal_event_ids_by_grant_id_fields_kind_and_grants_added_key() -> None:
    g = f.grant("g-1", principal_ref=AWS_USER, scope_ref="arn:aws:s3:::x", granted_via="direct")
    est = f.estate(
        identities=[f.identity()],
        grants=[g],
        events=[
            f.event("ev-id", 1, "role_change", grant_delta={"added": [{"grant_id": "g-1"}]}),
            f.event(
                "ev-fields",
                2,
                "new_hire",
                grant_delta={
                    "grants_added": [
                        {
                            "principal_ref": AWS_USER,
                            "scope_ref": "arn:aws:s3:::x",
                            "granted_via": "direct",
                            "cloud": "aws",
                        }
                    ]
                },
            ),
            f.event(
                "ev-via",
                3,
                "role_change",
                grant_delta={
                    "added": [
                        {"principal_ref": AWS_USER, "scope_ref": "arn:aws:s3:::x", "granted_via": "group:g"}
                    ]
                },
            ),
            f.event("ev-kind", 4, "departure", cloud=None),
            f.event("ev-other-id", 5, "departure", identity_id="emp-0002"),
            f.event("ev-removed", 6, "role_change", grant_delta={"removed": [{"grant_id": "g-1"}]}),
            f.event("ev-str", 7, "role_change", grant_delta={"added": ["g-1"]}),
        ],
    )
    assert common.causal_event_ids(est, "emp-0001", [g], "departure") == ["ev-fields", "ev-id", "ev-kind"]
    assert common.causal_event_ids(est, "emp-0001", [g]) == ["ev-fields", "ev-id"]


def test_causal_event_ids_for_refs_matches_any_list_key() -> None:
    est = f.estate(
        identities=[f.identity()],
        events=[
            f.event("ev-a", 1, "project_launch", grant_delta={"credentials": [{"credential_ref": "k-1"}]}),
            f.event("ev-b", 2, "project_launch", grant_delta={"added": [{"credential_ref": "k-2"}]}),
            f.event("ev-c", 3, "project_launch", grant_delta={"added": [{"credential_ref": 7}]}),
        ],
    )
    assert common.causal_event_ids_for_refs(est, "emp-0001", "credential_ref", ["k-1"]) == ["ev-a"]
    assert common.causal_event_ids_for_refs(est, "emp-0001", "credential_ref", ["k-9"]) == []


def test_register_exception_valid_expired_none() -> None:
    valid = f.estate(identities=[f.identity()], exceptions=[f.exception(exception_type="break-glass")])
    assert common.register_exception(valid, "emp-0001", "break-glass") == (True, None, [])
    assert common.register_exception(valid, "emp-0001", "dr-failover") == (False, None, [])
    expired = f.estate(
        identities=[f.identity()],
        exceptions=[
            f.exception(review_date=date(2026, 7, 1), expires_on=date(2026, 5, 1), exception_id="exc-x")
        ],
    )
    suppressed, when, evidence = common.register_exception(expired, "emp-0001", "break-glass")
    assert (suppressed, when) == (False, "2026-05-01")
    assert [(e.kind, e.ref) for e in evidence] == [("exception", "exc-x")]
    assert "expired on 2026-05-01" in evidence[0].note


def test_register_exception_ignores_cloud_tags() -> None:
    tagged = f.estate(identities=[f.identity(tags={"exception": "break-glass", "approved": "yes"})])
    assert common.register_exception(tagged, "emp-0001", "break-glass") == (False, None, [])


def test_expired_on_returns_earliest_passed_date() -> None:
    as_of = date(2026, 8, 31)
    exc = f.exception(review_date=date(2026, 9, 1), expires_on=date(2026, 1, 1))
    assert common.expired_on(exc, as_of) == date(2026, 1, 1)
    assert common.expired_on(f.exception(review_date=date(2026, 8, 31)), as_of) is None
    assert common.expired_on(f.exception(review_date=None, expires_on=None), as_of) is None


def test_common_facts_with_and_without_hr_row() -> None:
    est = f.estate(
        identities=[f.identity(display_name="Maryam", department="Finance")],
        grants=[f.grant("g-1", cloud="gcp"), f.grant("g-2", identity_id="unlinked:aws:x")],
    )
    facts = common.common_facts(est, "emp-0001", extra_clouds={"aws"})
    assert facts == {
        "identity_id": "emp-0001",
        "display_name": "Maryam",
        "department": "Finance",
        "identity_type": "human",
        "clouds": ["aws", "gcp"],
    }
    ghost = f.principal("x", identity_id=None, principal_type="service_account", link_method="unlinked")
    facts = common.common_facts(est, "unlinked:aws:x", principal=ghost)
    assert facts["department"] is None and facts["identity_type"] == "service"
    assert facts["display_name"] == "x" and facts["clouds"] == ["aws"]
    assert common.common_facts(est, "nobody")["identity_type"] == "unknown"


def test_draft_sorts_evidence_and_causal_ids() -> None:
    d = common.draft(
        "R1",
        "emp-0001",
        "High",
        [EvidenceRef("grant", "g-2"), EvidenceRef("grant", "g-1")],
        ["ev-2", "ev-1", "ev-2"],
        {"identity_id": "emp-0001"},
    )
    assert [e.ref for e in d.evidence] == ["g-1", "g-2"] and d.causal_event_ids == ["ev-1", "ev-2"]
    assert d.evidence_keys() == ["grant:g-1", "grant:g-2"]
