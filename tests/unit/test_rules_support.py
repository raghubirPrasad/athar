"""Shared helpers for the detection-rule tests (lane C1, SPEC §7). No tests live here.

Every test module does `from test_rules_support import ...`; pytest puts tests/unit on
sys.path (prepend import mode) and this module puts tests/ there for `factories`.
"""

from __future__ import annotations

import importlib
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

_TESTS_DIR = Path(__file__).resolve().parents[1]
if str(_TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTS_DIR))

from athar.detection import registry  # noqa: E402
from athar.detection.base import FindingDraft  # noqa: E402
from athar.domain import EstateView, GrantRow, Thresholds  # noqa: E402
from athar.scoring import graph as access_graph  # noqa: E402, F401  (re-exported for monkeypatching)
from athar.scoring.types import PathEdge  # noqa: E402

import factories as f  # noqa: E402

# The frozen registry loads rule modules only while `_RULES` is empty; a direct import of one
# rule module before the first `get_rule` call would leave the others unregistered. Importing
# every module here is idempotent and makes the registry complete whatever the import order.
for _mod in ("r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"):
    importlib.import_module(f"athar.detection.{_mod}")
r5_module = importlib.import_module("athar.detection.r5")
r7_module = importlib.import_module("athar.detection.r7")
r10_module = importlib.import_module("athar.detection.r10")
get_rule = registry.get_rule

AWS_ACCT = "123456789012"
AWS_USER = f"arn:aws:iam::{AWS_ACCT}:user/maryam"
AWS_ROLE = f"arn:aws:iam::{AWS_ACCT}:role/finance-admin"
AWS_BUCKET = "arn:aws:s3:::nda-finance-ledger"
AZ_SUB = "/subscriptions/00000000-0000-0000-0000-000000000001"
AZ_PRINCIPAL = "00000000-0000-0000-0000-00000000a001"
GCP_PROJECT = "nda-analytics-prod"
GCP_PROJECT_REF = f"projects/{GCP_PROJECT}"
GCP_SA = f"serviceAccount:svc-etl@{GCP_PROJECT}.iam.gserviceaccount.com"
GCP_USER = "user:maryam@nda.example"

PROJECT_SCOPE: dict[str, str] = {"aws": AWS_ACCT, "azure": AZ_SUB, "gcp": GCP_PROJECT_REF}
PRINCIPAL_OF: dict[str, str] = {"aws": AWS_USER, "azure": AZ_PRINCIPAL, "gcp": GCP_USER}


def run(rule_id: str, estate: EstateView, thresholds: Thresholds | None = None) -> list[FindingDraft]:
    return get_rule(rule_id).run(estate, thresholds or Thresholds())


def wide_grant(grant_id: str, cloud: str, verb: str, identity_id: str = "emp-0001", **kw: Any) -> GrantRow:
    """A grant at project scope in the given cloud (the R1/R4 'scope ≥ project' shape)."""
    base: dict[str, Any] = dict(
        identity_id=identity_id,
        principal_ref=PRINCIPAL_OF[cloud],
        cloud=cloud,
        service_category="compute",
        verb=verb,
        scope_level="project",
        scope_ref=PROJECT_SCOPE[cloud],
    )
    base.update(kw)
    return f.grant(grant_id, **base)


class FakeGraph:
    """Stands in for athar.scoring.graph.AccessGraph in R5 tests (lane B is mocked out)."""

    def __init__(self, paths: dict[str, list[list[PathEdge]]]) -> None:
        self.paths = paths
        self.calls: list[tuple[str, int]] = []

    def escalation_paths(self, identity_id: str, max_len: int = 3) -> list[list[PathEdge]]:
        self.calls.append((identity_id, max_len))
        return [list(p) for p in self.paths.get(identity_id, [])]


def fake_build_graph(paths: dict[str, list[list[PathEdge]]]) -> Callable[[EstateView], FakeGraph]:
    graph = FakeGraph(paths)

    def build(estate: EstateView) -> FakeGraph:
        return graph

    build.graph = graph  # type: ignore[attr-defined]
    return build


def grant_path(identity_id: str, grant_id: str, target: str = AWS_ROLE) -> list[PathEdge]:
    return [PathEdge(f"id:{identity_id}", "grant", f"p:{target}", grant_id)]


def full_estate() -> tuple[EstateView, dict[str, list[list[PathEdge]]]]:
    """One month-12 estate on which every rule R0–R10 fires at least once.

    Returns the estate and the fake escalation paths R5 needs (lane B mocked).
    """
    peers = [f.identity(f"peer-{i:02d}", display_name=f"Peer {i}", department="Finance") for i in range(1, 6)]
    identities = [
        f.identity("emp-0001", display_name="Maryam Al Falasi", department="Finance", mfa_enforced=False),
        f.identity(
            "emp-0002",
            display_name="Omar Departed",
            department="Finance",
            employment_status="departed",
            departure_month=10,
        ),
        f.identity(
            "svc:prj-001:etl",
            display_name="svc-etl",
            identity_type="service",
            employment_type="service",
            department="Data Services",
        ),
        *peers,
    ]
    principals = [
        f.principal(AWS_USER, identity_id="emp-0001"),
        f.principal(AZ_PRINCIPAL, cloud="azure", identity_id="emp-0001"),
        f.principal(GCP_USER, cloud="gcp", identity_id="emp-0001"),
        f.principal(AWS_ROLE, identity_id="emp-0002", principal_type="role"),
        f.principal(GCP_SA, cloud="gcp", identity_id="svc:prj-001:etl", principal_type="service_account"),
        f.principal(
            "user:ghost@nda.example",
            cloud="gcp",
            identity_id=None,
            link_method="unlinked",
            link_confidence="heuristic",
        ),
    ]
    grants = [
        # R1 (wildcard + admin), R4 (admin everywhere), R9 (no MFA)
        wide_grant("g-0001-01", "aws", "admin", raw_snippet={"Action": "*", "Resource": "*"}),
        wide_grant("g-0001-02", "azure", "admin", service_category="identity"),
        wide_grant("g-0001-03", "gcp", "admin", service_category="data"),
        # R5 write on identity + grant at overlapping scope
        wide_grant("g-0001-04", "aws", "write", service_category="identity"),
        wide_grant("g-0001-05", "aws", "grant", service_category="identity"),
        # R0 mapping miss
        f.grant(
            "g-0001-06",
            principal_ref=AWS_USER,
            verb="unknown",
            service_category="unknown",
            raw_snippet={"Action": "frobnicate:Widgets"},
        ),
        # R8 high-sensitivity resource outside the approved regions
        f.grant(
            "g-0001-07",
            principal_ref=AWS_USER,
            verb="write",
            service_category="data",
            scope_ref="arn:aws:s3:::nda-citizen-records",
            region="eu-west-1",
        ),
        f.grant("g-0001-08", principal_ref=AWS_USER, verb="read", service_category="network"),
        f.grant("g-0001-09", principal_ref=AWS_USER, verb="delete", service_category="storage"),
        # R3 departed human still holding access
        f.grant("g-0002-01", identity_id="emp-0002", principal_ref=AWS_ROLE, verb="write"),
        # R3 service account of a retired project
        f.grant(
            "g-svc-01",
            identity_id="svc:prj-001:etl",
            principal_ref=GCP_SA,
            cloud="gcp",
            verb="write",
            scope_level="project",
            scope_ref=GCP_PROJECT_REF,
        ),
        # R10 unlinked principal's grant on its synthetic identity
        f.grant(
            "g-ghost-01",
            identity_id="unlinked:gcp:user:ghost@nda.example",
            principal_ref="user:ghost@nda.example",
            cloud="gcp",
            verb="read",
        ),
        # R7 peers: two read grants each
        *[
            f.grant(f"g-peer-{i:02d}-{c}", identity_id=f"peer-{i:02d}", verb="read", service_category=cat)
            for i in range(1, 6)
            for c, cat in (("a", "storage"), ("b", "compute"))
        ],
    ]
    estate = f.estate(
        identities=identities,
        principals=principals,
        grants=grants,
        # peers are active; emp-0001 has no activity at all → R2
        activity=[f.activity(f"peer-{i:02d}") for i in range(1, 6)],
        credentials=[f.credential("aws:key:AKIA0001", last_rotated_at=None, created_at=None)],
        resources=[
            f.resource(
                "arn:aws:s3:::nda-citizen-records", region="eu-west-1", sensitivity="high", category="data"
            )
        ],
        projects=[f.project("prj-001", status="retired", retired_month=9, project_ref=GCP_PROJECT)],
        events=[
            f.event(
                "ev-0010-hr-0002", 10, "departure", identity_id="emp-0002", cloud=None, trigger="departure"
            ),
            f.event(
                "ev-0009-prj-001",
                9,
                "project_retirement",
                identity_id="svc:prj-001:etl",
                cloud="gcp",
                trigger="project_retirement",
            ),
            f.event(
                "ev-0007-aws-0001",
                7,
                "role_change",
                grant_delta={"added": [{"principal_ref": AWS_USER, "scope_ref": AWS_ACCT, "role": "Admin"}]},
            ),
        ],
    )
    # the stale credential above has no dates at all; give R6 a real one
    estate.credentials = [
        f.credential("aws:key:AKIA0001", created_at=None, last_rotated_at=None),
        f.credential("gcp:sa_key:svc-etl-1", identity_id="svc:prj-001:etl", cloud="gcp", kind="sa_key"),
    ]
    estate.reindex()
    paths = {"emp-0001": [grant_path("emp-0001", "g-0001-05")]}
    return estate, paths
