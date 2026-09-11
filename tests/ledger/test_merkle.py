"""Merkle construction (SPEC §12.3): OZ-compatible, double-hashed leaves, sorted pairs."""

from __future__ import annotations

import random

import pytest
from athar.hashing import canonical_json, finding_instance, instance_hash
from athar.ledger import merkle
from eth_utils import keccak
from hypothesis import given, settings
from hypothesis import strategies as st

_leaf = st.binary(min_size=32, max_size=32)
_leaf_sets = st.lists(_leaf, min_size=1, max_size=64)


def _pair(a: bytes, b: bytes) -> bytes:
    """Independent reference: keccak256(min || max) using eth_utils directly, not the module."""
    lo, hi = sorted((a, b))
    return bytes(keccak(lo + hi))


# ---------------------------------------------------------------- known vectors


def test_empty_tree_root_is_zero_bytes32() -> None:
    assert merkle.root([]) == b"\x00" * 32
    assert merkle.root([]) == merkle.ZERO_ROOT


def test_single_leaf_root_is_the_leaf_and_proof_is_empty() -> None:
    leaf = merkle.leaf_from_bytes(b"one")
    assert merkle.root([leaf]) == leaf
    assert merkle.proof([leaf], leaf) == []
    assert merkle.verify(leaf, leaf, [])


def test_two_leaves_known_vector() -> None:
    a, b = merkle.leaf_from_bytes(b"a"), merkle.leaf_from_bytes(b"b")
    expected = _pair(a, b)
    assert merkle.root([a, b]) == expected
    assert merkle.root([b, a]) == expected  # order-independent
    assert merkle.proof([a, b], a) == [b]
    assert merkle.proof([a, b], b) == [a]


def test_three_leaves_known_vector_odd_node_promoted() -> None:
    leaves = [merkle.leaf_from_bytes(x) for x in (b"x", b"y", b"z")]
    s0, s1, s2 = sorted(leaves)
    expected = _pair(_pair(s0, s1), s2)  # [s0,s1,s2] -> [H(s0,s1), s2] -> H(H(s0,s1), s2)
    assert merkle.root(leaves) == expected
    assert merkle.proof(leaves, s0) == [s1, s2]
    assert merkle.proof(leaves, s2) == [_pair(s0, s1)]  # promoted leaf has a one-node proof


def test_leaf_is_double_keccak_of_canonical_json() -> None:
    inst = finding_instance(
        finding_key="k" * 32,
        identity_id="emp-0001",
        rule_id="R1",
        severity="High",
        score=61,
        snapshot_month=3,
        first_seen_month=1,
        evidence_refs=["grant:g2", "grant:g1"],
        causal_event_ids=[],
    )
    raw = canonical_json(inst)
    expected = bytes(keccak(bytes(keccak(raw))))
    assert merkle.leaf_from_bytes(raw) == expected
    assert merkle.leaf_from_instance_hash(instance_hash(inst)) == expected


def test_leaf_from_instance_hash_rejects_wrong_length() -> None:
    with pytest.raises(ValueError):
        merkle.leaf_from_instance_hash("0xdead")


# ---------------------------------------------------------------- properties


@settings(max_examples=150, deadline=None)
@given(_leaf_sets)
def test_property_every_leaf_verifies_with_its_proof(leaves: list[bytes]) -> None:
    r = merkle.root(leaves)
    for leaf in leaves:
        assert merkle.verify(r, leaf, merkle.proof(leaves, leaf))


@settings(max_examples=100, deadline=None)
@given(_leaf_sets, st.integers(0, 255))
def test_property_modified_leaf_fails(leaves: list[bytes], flip: int) -> None:
    r = merkle.root(leaves)
    leaf = leaves[0]
    p = merkle.proof(leaves, leaf)
    tampered = bytes([leaf[0] ^ (flip or 1)]) + leaf[1:]
    assert not merkle.verify(r, tampered, p)


@settings(max_examples=100, deadline=None)
@given(_leaf_sets, _leaf_sets)
def test_property_proof_from_a_different_tree_fails(a: list[bytes], b: list[bytes]) -> None:
    if merkle.root(a) == merkle.root(b):
        return  # identical trees; nothing to distinguish
    leaf = a[0]
    p_a = merkle.proof(a, leaf)
    # folding a valid proof always yields root(a), so it verifies against root(b) iff the roots agree
    assert not merkle.verify(merkle.root(b), leaf, p_a)


@settings(max_examples=100, deadline=None)
@given(_leaf_sets)
def test_property_root_is_order_independent(leaves: list[bytes]) -> None:
    shuffled = list(leaves)
    random.Random(1).shuffle(shuffled)
    assert merkle.root(shuffled) == merkle.root(leaves)


def test_duplicate_leaves_still_verify() -> None:
    leaf = merkle.leaf_from_bytes(b"dup")
    other = merkle.leaf_from_bytes(b"other")
    leaves = [leaf, leaf, other]
    r = merkle.root(leaves)
    assert merkle.verify(r, leaf, merkle.proof(leaves, leaf))
    assert merkle.verify(r, other, merkle.proof(leaves, other))


def test_proof_for_missing_leaf_raises() -> None:
    leaves = [merkle.leaf_from_bytes(b"a")]
    with pytest.raises(ValueError):
        merkle.proof(leaves, merkle.leaf_from_bytes(b"missing"))
    with pytest.raises(ValueError):
        merkle.proof([], merkle.leaf_from_bytes(b"missing"))


def test_truncated_proof_fails() -> None:
    leaves = [merkle.leaf_from_bytes(bytes([i])) for i in range(9)]
    r = merkle.root(leaves)
    p = merkle.proof(leaves, leaves[4])
    assert len(p) >= 2
    assert not merkle.verify(r, leaves[4], p[:-1])
    assert not merkle.verify(r, leaves[4], [*p, p[0]])


# ---------------------------------------------------------------- hex helpers


def test_hex_round_trip() -> None:
    b = merkle.leaf_from_bytes(b"hex")
    assert merkle.to_hex(b).startswith("0x")
    assert merkle.from_hex(merkle.to_hex(b)) == b
    assert merkle.from_hex(b.hex()) == b
    assert merkle.bytes32_from_hex(merkle.to_hex(b)) == b
    with pytest.raises(ValueError):
        merkle.from_hex("0xzz")
    with pytest.raises(ValueError):
        merkle.bytes32_from_hex("0x00")
