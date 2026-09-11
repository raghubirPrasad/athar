"""Acceptance test on the shape of the estate (SPEC §4.1, §4.3, §4.4).

SPEC §4.1 fixes the outcome the event rates are tuned for and then frozen: 500 identities at month
12, ~380 human and ~120 service, present in the three clouds with enough overlap for R4, and
40–70 ground-truth positives against exactly 11 decoys. This test is what "tuned, then frozen"
means — change a rate in `catalogue.py` and it tells you.
"""

from __future__ import annotations

import pytest
from athar.domain import CLOUDS, DEPARTMENTS
from athar.generator import decoys as dec
from athar.generator.ground_truth import build_ground_truth
from athar.generator.state import EstateState

from tests.generator.conftest import FULL_IDENTITIES

POSITIVE_RANGE = (40, 70)  # SPEC §4.1
SPEC_CLOUD_PRINCIPALS = {"aws": 340, "azure": 280, "gcp": 190}  # "roughly", SPEC §4.1
CLOUD_TOLERANCE = 0.25


# ---------------------------------------------------------------------------
# Fast checks — the decoy set is seeded, so it does not depend on estate size
# ---------------------------------------------------------------------------


def test_eleven_decoys_and_one_injection_identity(small_state: EstateState) -> None:
    identities = small_state.final.identities.values()
    decoys = [i for i in identities if dec.is_decoy(i)]
    assert len(decoys) == dec.DECOY_TOTAL == 11
    counts = {kind: sum(1 for i in decoys if i.decoy == kind) for kind in dec.DECOY_KINDS}
    assert counts == dec.DECOY_COUNTS
    injections = [i for i in identities if i.decoy == dec.INJECTION]
    assert len(injections) == 1


def test_every_register_decoy_has_an_exception_entry(small_state: EstateState) -> None:
    """A break-glass, DR or sanctioned-admin decoy is legitimate ONLY through the register; the
    time-boxed contractors are legitimate through the HR feed's `contract_end` (SPEC §4.3)."""
    registered = {e.identity_id for e in small_state.exceptions}
    for ident in small_state.final.identities.values():
        if ident.decoy in (dec.DECOY_BREAK_GLASS, dec.DECOY_DR_FAILOVER, dec.DECOY_SANCTIONED):
            assert ident.identity_id in registered
        if ident.decoy == dec.DECOY_CONTRACTOR:
            assert ident.contract_end is not None and ident.contract_end > small_state.final.as_of


# ---------------------------------------------------------------------------
# The SPEC §4.1 estate
# ---------------------------------------------------------------------------


@pytest.mark.slow
def test_population_matches_the_target(full_state: EstateState) -> None:
    identities = list(full_state.final.identities.values())
    humans = [i for i in identities if i.is_human]
    services = [i for i in identities if not i.is_human]
    assert len(identities) == pytest.approx(FULL_IDENTITIES, abs=25)
    assert len(humans) == pytest.approx(380, abs=40)
    assert len(services) == pytest.approx(120, abs=40)
    assert {i.department for i in humans} == set(DEPARTMENTS)


@pytest.mark.slow
def test_cloud_footprints_overlap_enough_for_cross_cloud_correlation(full_state: EstateState) -> None:
    identities = list(full_state.final.identities.values())
    per_cloud = {cloud: sum(1 for i in identities if cloud in i.clouds) for cloud in CLOUDS}
    for cloud, target in SPEC_CLOUD_PRINCIPALS.items():
        assert per_cloud[cloud] == pytest.approx(target, rel=CLOUD_TOLERANCE), per_cloud
    assert per_cloud["aws"] > per_cloud["azure"] > per_cloud["gcp"]
    two = sum(1 for i in identities if len(i.clouds) == 2)
    three = sum(1 for i in identities if len(i.clouds) == 3)
    assert two >= 100, f"only {two} identities in two clouds; R4 needs candidates"
    assert three >= 20, f"only {three} identities in all three clouds; R4 needs candidates"


@pytest.mark.slow
def test_ground_truth_positives_and_decoys(full_ground_truth: dict) -> None:
    low, high = POSITIVE_RANGE
    positives = full_ground_truth["positives"]
    assert low <= len(positives) <= high, f"{len(positives)} positives, SPEC §4.1 wants {low}–{high}"
    assert len(full_ground_truth["decoys"]) == dec.DECOY_TOTAL == 11
    assert full_ground_truth["seed"] == 42
    assert full_ground_truth["months"] == 12


@pytest.mark.slow
def test_every_positive_carries_rules_and_a_reason(full_ground_truth: dict) -> None:
    for positive in full_ground_truth["positives"]:
        assert positive["rules"], positive
        assert positive["reason"].strip(), positive
        assert positive["since_month"] >= 1


@pytest.mark.slow
def test_every_decoy_says_why_it_is_legitimate(full_ground_truth: dict) -> None:
    """Each register-backed decoy would fire without the register; the time-boxed contractors look
    risky to a naïve "external identity with write access" detector, which ATHAR does not model, so
    `looks_like` is legitimately empty for them (SPEC §4.3)."""
    register_backed = 0
    for decoy in full_ground_truth["decoys"]:
        assert decoy["why_legitimate"].strip()
        if decoy["why_legitimate"].startswith("register entry"):
            register_backed += 1
            assert decoy["looks_like"], decoy
    assert register_backed == dec.DECOY_TOTAL - dec.DECOY_COUNTS[dec.DECOY_CONTRACTOR]


@pytest.mark.slow
def test_the_injection_identity_is_a_genuine_positive(
    full_state: EstateState, full_ground_truth: dict
) -> None:
    """SPEC §11.3's hostile tag rides on an over-privileged account with a stale key: it is bait for
    the agent guardrails, never a decoy the register excuses."""
    injection = full_ground_truth["injection_decoy"]
    assert injection
    assert injection not in {d["identity_id"] for d in full_ground_truth["decoys"]}
    positives = {p["identity_id"]: p for p in full_ground_truth["positives"]}
    assert injection in positives, "the injection identity must also be a genuine finding"
    assert not dec.is_decoy(full_state.final.identities[injection])


@pytest.mark.slow
def test_expected_halflife_covers_every_department(full_ground_truth: dict) -> None:
    halflife = full_ground_truth["expected_halflife"]
    assert set(halflife) == set(DEPARTMENTS)
    assert any(value is not None for value in halflife.values())


@pytest.mark.slow
def test_ground_truth_is_stable_for_the_same_state(full_state: EstateState) -> None:
    assert build_ground_truth(full_state) == build_ground_truth(full_state)
