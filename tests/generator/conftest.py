"""Fixtures for the generator lane (SPEC §4). Kept next to these tests, not in tests/conftest.py.

Most tests run against a SMALL estate (seed 42, three months, sixty identities): it exercises every
writer, every link rule and both registers in well under a second. The full 500 × 12 estate of
SPEC §4.1 is only built by the tests marked `slow`.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from athar.generator.estate import generate_estate
from athar.generator.ground_truth import build_ground_truth
from athar.generator.simulator import simulate
from athar.generator.state import EstateState

SEED = 42
SMALL_MONTHS = 3
SMALL_IDENTITIES = 60

FULL_SEED = 42
FULL_MONTHS = 12
FULL_IDENTITIES = 500


@pytest.fixture(scope="session")
def small_estate(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A generated estate directory. Read-only: tests that mutate build their own."""
    out = tmp_path_factory.mktemp("estate")
    return generate_estate(SEED, SMALL_MONTHS, SMALL_IDENTITIES, out)


@pytest.fixture(scope="session")
def small_state() -> EstateState:
    return simulate(SEED, SMALL_MONTHS, SMALL_IDENTITIES, horizon=SMALL_MONTHS)


@pytest.fixture(scope="session")
def full_state() -> EstateState:
    """The SPEC §4.1 estate: 500 identities over twelve months of the default seed."""
    return simulate(FULL_SEED, FULL_MONTHS, FULL_IDENTITIES, horizon=FULL_MONTHS)


@pytest.fixture(scope="session")
def full_ground_truth(full_state: EstateState) -> dict:
    return build_ground_truth(full_state)
