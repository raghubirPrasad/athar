"""Two-register evaluation sentences (SPEC §17)."""

from __future__ import annotations

import pytest
from athar.export.summary import build_director_sentence, build_engineer_sentence


def test_director_sentence_matches_spec_example() -> None:
    assert (
        build_director_sentence(41, 6, 6)
        == "Of 47 accounts flagged, 41 are verified genuine risks; 6 are known exceptions the system now recognises."
    )


def test_director_sentence_reports_unrecognised_false_positives() -> None:
    assert build_director_sentence(41, 6, 4) == (
        "Of 47 accounts flagged, 41 are verified genuine risks; 4 are known exceptions the system now "
        "recognises; 2 are still under analyst review."
    )


def test_director_sentence_singulars() -> None:
    assert build_director_sentence(1, 0, 0) == "Of 1 account flagged, 1 is a verified genuine risk."
    assert build_director_sentence(0, 1, 1) == (
        "Of 1 account flagged, 0 are verified genuine risks; 1 is a known exception the system now recognises."
    )


def test_director_sentence_zero_flagged() -> None:
    assert build_director_sentence(0, 0, 0) == "No accounts were flagged at High or above."


@pytest.mark.parametrize("args", [(-1, 0, 0), (0, -1, 0), (0, 0, -1), (1, 2, 3)])
def test_director_sentence_rejects_inconsistent_counts(args: tuple[int, int, int]) -> None:
    with pytest.raises(ValueError):
        build_director_sentence(*args)


def test_engineer_sentence_matches_spec_example() -> None:
    assert (
        build_engineer_sentence(0.87, 0.95, seed=7, held_out=True)
        == "precision 0.87 / recall 0.95 at High+ on held-out seed 7"
    )


def test_engineer_sentence_never_calls_the_tuning_seed_held_out() -> None:
    """SPEC §8.3: constants are tuned on 42 and reported on 7; the sentence must not blur that.

    `held_out` used to be hard-coded True, so `eval/results-42.json` read "on held-out seed 42" —
    the tuning estate described as one the constants never saw. Provenance now comes from the
    caller, and the harness takes it from `ATHAR_EVAL_SEED`.
    """
    assert (
        build_engineer_sentence(0.96, 1.0, seed=42, held_out=False)
        == "precision 0.96 / recall 1.00 at High+ on tuning seed 42"
    )
    # Unstated provenance names the seed and claims nothing about it.
    assert build_engineer_sentence(0.96, 1.0, seed=42) == "precision 0.96 / recall 1.00 at High+ on seed 42"


def test_engineer_sentence_without_seed_and_custom_threshold() -> None:
    assert (
        build_engineer_sentence(1.0, 0.5, threshold="Critical") == "precision 1.00 / recall 0.50 at Critical+"
    )


@pytest.mark.parametrize("p,r", [(-0.1, 0.5), (0.5, 1.5)])
def test_engineer_sentence_rejects_out_of_range(p: float, r: float) -> None:
    with pytest.raises(ValueError):
        build_engineer_sentence(p, r)
