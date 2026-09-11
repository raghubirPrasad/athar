"""Merkle construction compatible with OpenZeppelin `MerkleProof.verify` (SPEC §12.3). Pure.

- ``leaf = keccak256(keccak256(canonical_json_bytes))`` — double-hashed leaves give domain
  separation from internal nodes (which hash 64 bytes once), closing the second-preimage
  class of attacks. `athar.hashing.instance_hash` is already the first keccak, so
  :func:`leaf_from_instance_hash` applies only the second.
- ``node = keccak256(min(a, b) || max(a, b))`` — sorted pairs, as OZ expects.
- Leaves are sorted ascending before building; an odd node at a level is promoted unchanged.
- The root of an empty leaf set is ``bytes32(0)`` (:data:`ZERO_ROOT`); a scan with no
  findings is still anchored with a zero root and ``findingCount == 0``.
"""

from __future__ import annotations

from athar.hashing import keccak256

ZERO_ROOT: bytes = b"\x00" * 32
"""Root of the empty tree. Documented, not a hash of anything."""


# ---------------------------------------------------------------------------
# hex helpers
# ---------------------------------------------------------------------------


def to_hex(b: bytes) -> str:
    """bytes -> ``0x``-prefixed lowercase hex."""
    return "0x" + b.hex()


def from_hex(s: str) -> bytes:
    """``0x``-prefixed or bare hex -> bytes. Raises ``ValueError`` on malformed input."""
    text = s[2:] if s.startswith(("0x", "0X")) else s
    return bytes.fromhex(text)


def bytes32_from_hex(s: str) -> bytes:
    """Like :func:`from_hex` but insists on exactly 32 bytes (leaves, roots, proof nodes)."""
    b = from_hex(s)
    if len(b) != 32:
        raise ValueError(f"expected 32 bytes, got {len(b)}")
    return b


# ---------------------------------------------------------------------------
# leaves and nodes
# ---------------------------------------------------------------------------


def leaf_from_bytes(canonical_json_bytes: bytes) -> bytes:
    """``keccak256(keccak256(canonical_json_bytes))``."""
    return keccak256(keccak256(canonical_json_bytes))


def leaf_from_instance_hash(instance_hash_hex: str) -> bytes:
    """Second keccak over an ``instance_hash`` (which is already ``keccak256(canonical_json)``).

    Equivalent to ``leaf_from_bytes(canonical_json(instance))``.
    """
    return keccak256(bytes32_from_hex(instance_hash_hex))


def hash_pair(a: bytes, b: bytes) -> bytes:
    """Commutative node hash: ``keccak256(min(a, b) || max(a, b))``."""
    return keccak256(a + b) if a <= b else keccak256(b + a)


def _next_level(level: list[bytes]) -> list[bytes]:
    out: list[bytes] = []
    for i in range(0, len(level), 2):
        if i + 1 < len(level):
            out.append(hash_pair(level[i], level[i + 1]))
        else:
            out.append(level[i])  # odd node promoted unchanged
    return out


def _layers(leaves: list[bytes]) -> list[list[bytes]]:
    """All levels bottom-up, starting from the sorted leaves. ``[]`` for no leaves."""
    if not leaves:
        return []
    level = sorted(leaves)
    layers = [level]
    while len(level) > 1:
        level = _next_level(level)
        layers.append(level)
    return layers


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------


def root(leaves: list[bytes]) -> bytes:
    """Merkle root of ``leaves`` (order-independent). Empty input -> :data:`ZERO_ROOT`."""
    layers = _layers(leaves)
    return layers[-1][0] if layers else ZERO_ROOT


def proof(leaves: list[bytes], leaf: bytes) -> list[bytes]:
    """Sibling path from ``leaf`` to the root, bottom-up, in OZ order.

    Raises ``ValueError`` if ``leaf`` is not in ``leaves``. With duplicate leaves the proof
    for the first occurrence is returned; it verifies for the value regardless.
    """
    layers = _layers(leaves)
    if not layers:
        raise ValueError("leaf not in tree")
    try:
        index = layers[0].index(leaf)
    except ValueError:
        raise ValueError("leaf not in tree") from None
    path: list[bytes] = []
    for level in layers[:-1]:
        sibling = index ^ 1
        if sibling < len(level):
            path.append(level[sibling])
        index //= 2
    return path


def verify(root_hash: bytes, leaf: bytes, proof_path: list[bytes]) -> bool:
    """Mirror of ``MerkleProof.verify``: fold the proof with :func:`hash_pair` and compare."""
    computed = leaf
    for node in proof_path:
        computed = hash_pair(computed, node)
    return computed == root_hash
