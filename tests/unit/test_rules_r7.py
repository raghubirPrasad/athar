"""R7 Peer outlier (SPEC §7): count > department median + 2·MAD and ≥ 2 categories over peers."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from athar.detection.facts import missing_slots
from test_rules_support import f, run
from test_rules_support import r7_module as r7

CATEGORIES = ("storage", "compute", "network", "identity", "data", "security", "billing")


def _peers(n: int = 5, department: str = "Finance", grants_each: int = 2):  # type: ignore[no-untyped-def]
    """n identities with `grants_each` read grants, one per category, all in one department."""
    identities = [
        f.identity(f"peer-{department[:3]}-{i:02d}", department=department) for i in range(1, n + 1)
    ]
    grants = [
        f.grant(
            f"g-{ident.identity_id}-{k}",
            identity_id=ident.identity_id,
            verb="read",
            service_category=CATEGORIES[k],
        )
        for ident in identities
        for k in range(grants_each)
    ]
    return identities, grants


def _outlier(identity_id: str = "emp-0001", count: int = 8, categories: int = 5, department: str = "Finance"):  # type: ignore[no-untyped-def]
    ident = f.identity(identity_id, department=department)
    grants = [
        f.grant(
            f"g-{identity_id}-{k:02d}",
            identity_id=identity_id,
            verb="read",
            service_category=CATEGORIES[k % categories],
        )
        for k in range(count)
    ]
    return ident, grants


def test_outlier_fires_low_with_statistics() -> None:
    peers, peer_grants = _peers()
    ident, grants = _outlier()
    est = f.estate(identities=[*peers, ident], grants=[*peer_grants, *grants])
    drafts = run("R7", est)
    assert len(drafts) == 1
    d = drafts[0]
    assert d.identity_id == "emp-0001" and d.severity == "Low"
    assert d.facts["grant_count"] == 8
    assert d.facts["department_median"] == 2.0 and d.facts["department_mad"] == 1.0  # MAD 0 → 1
    assert d.facts["categories_over"] == 3 and d.facts["peer_category_count"] == 2.0
    assert d.facts["peer_categories"] == ["compute", "storage"]
    assert len(d.facts["grant_ids"]) == 8 and len(d.evidence) == 8


def test_department_with_fewer_than_five_identities_never_fires() -> None:
    peers, peer_grants = _peers(n=3)
    ident, grants = _outlier(count=40, categories=7)
    est = f.estate(identities=[*peers, ident], grants=[*peer_grants, *grants])
    assert run("R7", est) == []


def test_five_identities_including_the_outlier_is_enough() -> None:
    peers, peer_grants = _peers(n=4)
    ident, grants = _outlier()
    est = f.estate(identities=[*peers, ident], grants=[*peer_grants, *grants])
    assert len(run("R7", est)) == 1


def test_high_count_but_few_categories_does_not_fire() -> None:
    peers, peer_grants = _peers()
    ident, grants = _outlier(count=8, categories=1)
    est = f.estate(identities=[*peers, ident], grants=[*peer_grants, *grants])
    assert run("R7", est) == []


def test_one_category_over_is_not_enough() -> None:
    peers, peer_grants = _peers()
    ident, grants = _outlier(count=8, categories=3)
    est = f.estate(identities=[*peers, ident], grants=[*peer_grants, *grants])
    assert run("R7", est) == []


def test_many_categories_but_count_at_threshold_does_not_fire() -> None:
    peers, peer_grants = _peers()  # median 2, MAD → 1, threshold 4
    ident, grants = _outlier(count=4, categories=4)
    est = f.estate(identities=[*peers, ident], grants=[*peer_grants, *grants])
    assert run("R7", est) == []


def test_count_one_over_threshold_fires() -> None:
    peers, peer_grants = _peers()
    ident, grants = _outlier(count=5, categories=4)
    est = f.estate(identities=[*peers, ident], grants=[*peer_grants, *grants])
    assert len(run("R7", est)) == 1


def test_nonzero_mad_is_used() -> None:
    identities = [f.identity(f"p-{i}", department="Finance") for i in range(1, 6)]
    grants = [
        f.grant(f"g-p-{i}-{k}", identity_id=f"p-{i}", verb="read", service_category="storage")
        for i in range(1, 6)
        for k in range(i)  # counts 1..5
    ]
    ident, out_grants = _outlier(count=20, categories=5)
    est = f.estate(identities=[*identities, ident], grants=[*grants, *out_grants])
    d = run("R7", est)[0]
    assert d.facts["department_median"] == 3.5 and d.facts["department_mad"] == 1.5


def test_median_and_mad_helpers() -> None:
    assert r7.median([1, 2, 3, 4]) == 2.5
    assert r7.mad([2, 2, 2], 2.0) == 1.0
    assert r7.mad([1, 2, 3, 4, 5, 20], 3.5) == 1.5


def test_departments_are_evaluated_independently() -> None:
    fin, fin_grants = _peers(department="Finance")
    hr, hr_grants = _peers(department="HR", grants_each=6)
    ident, grants = _outlier(count=8, categories=5, department="Finance")
    est = f.estate(identities=[*fin, *hr, ident], grants=[*fin_grants, *hr_grants, *grants])
    drafts = run("R7", est)
    assert [d.identity_id for d in drafts] == ["emp-0001"]
    assert drafts[0].facts["department"] == "Finance"


def test_inactive_grants_do_not_count() -> None:
    peers, peer_grants = _peers()
    ident, grants = _outlier()
    est = f.estate(
        identities=[*peers, ident],
        grants=[
            *peer_grants,
            *[
                f.grant(
                    g.grant_id,
                    identity_id=g.identity_id,
                    verb=g.verb,
                    service_category=g.service_category,
                    active=False,
                )
                for g in grants
            ],
        ],
    )
    assert run("R7", est) == []


def test_facts_are_json_serialisable_and_complete() -> None:
    peers, peer_grants = _peers()
    ident, grants = _outlier()
    est = f.estate(identities=[*peers, ident], grants=[*peer_grants, *grants])
    d = run("R7", est)[0]
    assert missing_slots("R7", d.facts) == []
    json.dumps(d.facts)
    assert isinstance(d.facts["categories_over"], int)


def test_saturated_department_cannot_fire() -> None:
    """Why R7 finds nothing on the generated estate (README known limitations, PRD §7 F16).

    Every peer already holds all seven service categories, so the department median category
    count is the maximum and no identity — however many grants it piles up — can hold
    CATEGORY_MARGIN more. This pins the measured behaviour: if someone changes the second term,
    this test fails and they know which claim in the docs they have just invalidated.
    """
    peers, peer_grants = _peers(n=6, grants_each=len(CATEGORIES))
    ident, grants = _outlier(count=60, categories=len(CATEGORIES))
    est = f.estate(identities=[*peers, ident], grants=[*peer_grants, *grants])
    assert run("R7", est) == []


def test_deterministic_and_sorted_by_identity() -> None:
    peers, peer_grants = _peers(n=6)
    b, b_grants = _outlier("emp-0002")
    a, a_grants = _outlier("emp-0001")
    est = f.estate(identities=[*peers, b, a], grants=[*peer_grants, *b_grants, *a_grants])
    x, y = run("R7", est), run("R7", est)
    assert x == y and [d.identity_id for d in x] == ["emp-0001", "emp-0002"]
