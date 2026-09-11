"""Same seed → byte-identical estate (SPEC §4.5, CLAUDE.md non-negotiable 4).

The acceptance test is the one SPEC names: two runs of the generator produce the same tree, hashed
over the concatenation of every file. A different seed must produce a different one — otherwise the
"deterministic" claim would be satisfied by a generator that ignores the seed.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from athar.generator.estate import generate_estate
from athar.generator.manifest import read_manifest, verify_manifest
from athar.generator.simulator import simulate

from tests.generator.conftest import SEED, SMALL_IDENTITIES, SMALL_MONTHS


def tree_digest(root: Path) -> str:
    """sha256 over every file in the tree: relative path, then bytes, in sorted order."""
    digest = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _generate(root: Path, seed: int = SEED) -> Path:
    return generate_estate(seed, SMALL_MONTHS, SMALL_IDENTITIES, root)


def test_two_runs_of_the_same_seed_produce_identical_trees(tmp_path: Path) -> None:
    first = _generate(tmp_path / "a")
    second = _generate(tmp_path / "b")
    assert tree_digest(first) == tree_digest(second)


def test_a_different_seed_produces_a_different_tree(tmp_path: Path) -> None:
    first = _generate(tmp_path / "a", seed=SEED)
    other = _generate(tmp_path / "b", seed=SEED + 1)
    assert tree_digest(first) != tree_digest(other)
    assert read_manifest(other).seed == SEED + 1


def test_every_file_matches_its_manifest_hash(tmp_path: Path) -> None:
    estate = _generate(tmp_path / "a")
    assert verify_manifest(estate) == []


def test_the_manifest_records_the_inputs(tmp_path: Path) -> None:
    manifest = read_manifest(_generate(tmp_path / "a"))
    assert (manifest.seed, manifest.months, manifest.identities) == (SEED, SMALL_MONTHS, SMALL_IDENTITIES)
    assert manifest.generator_version
    assert manifest.design_horizon == SMALL_MONTHS
    assert f"month-{SMALL_MONTHS:02d}/hr/employees.csv" in manifest.files


def test_the_simulation_itself_is_reproducible() -> None:
    """The writers can only be deterministic if the state they render is."""
    left = simulate(SEED, SMALL_MONTHS, SMALL_IDENTITIES, horizon=SMALL_MONTHS)
    right = simulate(SEED, SMALL_MONTHS, SMALL_IDENTITIES, horizon=SMALL_MONTHS)
    assert [g.grant_ref for g in left.all_grants] == [g.grant_ref for g in right.all_grants]
    assert [e.as_json() for e in left.events] == [e.as_json() for e in right.events]
    assert sorted(left.final.identities) == sorted(right.final.identities)
