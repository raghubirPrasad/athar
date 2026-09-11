"""Example facts for every rule (SPEC §10.2) — synthetic, deterministic, nda.example only.

Used by the narrative tests and reusable by the API mock (ATHAR_API_MOCK) and the PDF
appendix. Every dict satisfies athar.detection.facts.required_slots(rule).
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from athar.drift.types import CausalStep, HalfLifeRow
from athar.scoring.types import LineItem, PathEdge, ScoreResult

_AWS_ROLE = "arn:aws:iam::123456789012:role/finance-admin"
_AZ_SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-finance"
_GCP_SA = "serviceAccount:svc-etl@nda-analytics-prod.nda.example"

_COMMON: dict[str, Any] = {
    "identity_id": "emp-0042",
    "display_name": "Maryam Al Falasi",
    "department": "Finance",
    "identity_type": "human",
    "clouds": ["aws", "azure", "gcp"],
}

EXAMPLE_FACTS: dict[str, dict[str, Any]] = {
    "R0": {
        **_COMMON,
        "cloud": "azure",
        "raw_action": "Microsoft.Contoso/widgets/frobnicate/action",
        "principal_ref": "00000000-0000-0000-0000-00000000a042",
        "grant_ids": ["g-az-0042-07"],
    },
    "R1": {
        **_COMMON,
        "cloud": "aws",
        "scope_level": "org",
        "scope_ref": "arn:aws:organizations::123456789012:root",
        "granted_via": "policy:AdministratorAccess",
        "grant_ids": ["g-aws-0042-01", "g-aws-0042-02"],
        "wildcard": True,
        "exception_expired_on": "2026-03-12",
    },
    "R2": {
        **_COMMON,
        "dormant_days": 124,
        "last_activity_at": "2026-04-28",
        "clouds_with_write": ["aws", "gcp"],
        "grant_ids": ["g-aws-0042-01", "g-gcp-0042-03", "g-gcp-0042-04"],
        "exception_expired_on": None,
    },
    "R3": {
        **_COMMON,
        "orphan_kind": "departed",
        "departure_month": 9,
        "months_since_departure": 3,
        "project_id": None,
        "retired_month": None,
        "grant_ids": ["g-aws-0042-01", "g-az-0042-07"],
    },
    "R4": {
        **_COMMON,
        "power": "admin",
        "per_cloud": {
            "aws": [_AWS_ROLE, "arn:aws:iam::123456789012:root"],
            "azure": [_AZ_SCOPE],
            "gcp": ["nda-analytics-prod"],
        },
        "grant_ids": ["g-aws-0042-01", "g-az-0042-07", "g-gcp-0042-03"],
    },
    "R5": {
        **_COMMON,
        "combination": "write_identity+grant",
        "path": [
            {"src": "id:emp-0042", "verb": "grant", "dst": f"p:{_AWS_ROLE}", "grant_id": "g-aws-0042-05"},
            {
                "src": f"p:{_AWS_ROLE}",
                "verb": "admin",
                "dst": "r:arn:aws:s3:::nda-finance-ledger",
                "grant_id": "g-aws-0042-06",
            },
        ],
        "path_len": 2,
        "grant_ids": ["g-aws-0042-05", "g-aws-0042-06"],
        "exception_expired_on": None,
    },
    "R6": {
        **_COMMON,
        "credential_ref": "aws:key:AKIA0000000000000042",
        "cloud": "aws",
        "kind": "key",
        "age_days": 412,
        "last_rotated_at": "2025-07-15",
        "threshold_days": 180,
    },
    "R7": {
        **_COMMON,
        "grant_count": 23,
        "department_median": 6,
        "department_mad": 2,
        "categories_over": 3,
        "peer_categories": ["storage", "data"],
        "grant_ids": [f"g-aws-0042-{i:02d}" for i in range(1, 24)],
    },
    "R8": {
        **_COMMON,
        "cloud": "gcp",
        "region": "europe-west1",
        "approved_regions": ["me-central-1", "uaenorth", "uaecentral", "me-central1"],
        "resource_ref": "projects/nda-analytics-prod/datasets/citizen_records",
        "resource_sensitivity": "high",
        "grant_ids": ["g-gcp-0042-08"],
    },
    "R9": {
        **_COMMON,
        "privileged_verbs": ["admin", "grant"],
        "clouds_privileged": ["aws", "azure"],
        "grant_ids": ["g-aws-0042-01", "g-az-0042-07"],
    },
    "R10": {
        "identity_id": "unlinked:gcp:svc-etl",
        "display_name": "svc-etl (unlinked)",
        "department": None,
        "identity_type": "service",
        "clouds": ["gcp"],
        "cloud": "gcp",
        "principal_ref": _GCP_SA,
        "principal_type": "service_account",
        "link_attempts": ["hr_email", "employee_id_tag", "display_name"],
        "grant_ids": ["g-gcp-9001-01"],
    },
}
EXAMPLE_FACTS["R3"]["identity_type"] = "human"

EXAMPLE_GRANTS: list[dict[str, Any]] = [
    {
        "grant_id": "g-aws-0042-01",
        "identity_id": "emp-0042",
        "principal_ref": _AWS_ROLE,
        "cloud": "aws",
        "service_category": "identity",
        "verb": "admin",
        "scope_level": "org",
        "scope_ref": "arn:aws:organizations::123456789012:root",
        "region": None,
        "effect": "allow",
        "granted_via": "policy:AdministratorAccess",
        "snapshot_month": 12,
        "raw_snippet": {"PolicyName": "AdministratorAccess", "Statement": [{"Action": "*", "Resource": "*"}]},
        "source_file": "aws/authorization-details.json",
        "source_pointer": "/RoleDetailList/3/AttachedManagedPolicies/0",
        "active": True,
    },
    {
        "grant_id": "g-az-0042-07",
        "identity_id": "emp-0042",
        "principal_ref": "00000000-0000-0000-0000-00000000a042",
        "cloud": "azure",
        "service_category": "compute",
        "verb": "admin",
        "scope_level": "project",
        "scope_ref": _AZ_SCOPE,
        "region": "uaenorth",
        "effect": "allow",
        "granted_via": "roleAssignment:Owner",
        "snapshot_month": 12,
        "raw_snippet": {"roleDefinitionName": "Owner", "scope": _AZ_SCOPE},
        "source_file": "azure/role-assignments.json",
        "source_pointer": "/value/17",
        "active": True,
    },
]


def example_facts(rule_id: str) -> dict[str, Any]:
    return deepcopy(EXAMPLE_FACTS[rule_id])


def example_score(identity_id: str = "emp-0042") -> ScoreResult:
    """The SPEC §8.3 worked example: reach 0.76 × exploitability 1.8 × controls 1.0 = 68, floor R3 → 75."""
    return ScoreResult(
        identity_id=identity_id,
        blast_radius=0.19,
        reachable_resources=41,
        high_sensitivity_reached=6,
        reach=0.76,
        exploitability=1.8,
        compensating=0.0,
        formula_score=68.4,
        rule_floor=75,
        score=75,
        severity="Critical",
        line_items=[
            LineItem("reach", "blast radius 19% of estate", 0.76, {"high_sensitivity": 6}),
            LineItem("exploitability", "base", 1.0),
            LineItem("exploitability", "departed +0.5", 0.5),
            LineItem("exploitability", "dormant +0.3", 0.3),
            LineItem("compensating", "none", 0.0),
            LineItem("formula", "100 × reach × exploitability × controls", 68.4),
            LineItem("floor", "R3", 75.0),
            LineItem("final", "Critical", 75.0),
        ],
        escalation_paths=[
            [
                PathEdge(f"id:{identity_id}", "grant", f"p:{_AWS_ROLE}", "g-aws-0042-05"),
                PathEdge(f"p:{_AWS_ROLE}", "admin", "r:arn:aws:s3:::nda-finance-ledger", "g-aws-0042-06"),
            ]
        ],
    )


def example_causal() -> list[CausalStep]:
    """The SPEC §9.2 worked example as steps."""
    return [
        CausalStep(
            3,
            "ev-0003-aws-0042",
            "grant",
            "role_change",
            "aws",
            "AWS administrator on org root added (role change)",
            {"added": ["AWS administrator"], "removed": []},
        ),
        CausalStep(
            7,
            "ev-0007-gcp-0042",
            "role_change",
            "role_change",
            "gcp",
            "GCP roles/owner on nda-analytics-prod added (role change)",
            {"added": ["GCP Owner"], "removed": []},
        ),
        CausalStep(9, "ev-0009-act-0042", "activity_stop", "unknown", None, "last activity recorded", {}),
        CausalStep(
            11, "ev-0011-hr-0042", "departure", "departure", None, "HR status changed to departed", {}
        ),
    ]


def example_halflife() -> HalfLifeRow:
    return HalfLifeRow("Finance", "departure", 34, 2, None, "Broken")
