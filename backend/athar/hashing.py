"""Canonical JSON and hashes (SPEC §10.1, §12.3). Pure."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from eth_utils import keccak as _keccak

FINDING_KEY_VERSION = "v1"


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def keccak256(data: bytes) -> bytes:
    return bytes(_keccak(data))


def keccak256_hex(data: bytes) -> str:
    return "0x" + keccak256(data).hex()


def finding_key(identity_id: str, rule_id: str) -> str:
    """Stable across scans: sha256("v1|" + identity_id + "|" + rule_id)[:32]."""
    return sha256_hex(f"{FINDING_KEY_VERSION}|{identity_id}|{rule_id}".encode())[:32]


def finding_instance(
    *,
    finding_key: str,
    identity_id: str,
    rule_id: str,
    severity: str,
    score: int,
    snapshot_month: int,
    first_seen_month: int,
    evidence_refs: list[str],
    causal_event_ids: list[str],
) -> dict[str, Any]:
    """The committed instance. Narratives and status are excluded on purpose (SPEC §10.1)."""
    return {
        "finding_key": finding_key,
        "identity_id": identity_id,
        "rule_id": rule_id,
        "severity": severity,
        "score": score,
        "snapshot_month": snapshot_month,
        "first_seen_month": first_seen_month,
        "evidence_refs": sorted(evidence_refs),
        "causal_event_ids": sorted(causal_event_ids),
    }


def instance_hash(instance: dict[str, Any]) -> str:
    """keccak256(canonical_json(instance)) as 0x-hex. This is what becomes a Merkle leaf (after double hashing)."""
    return keccak256_hex(canonical_json(instance))


def ruleset_hash(rule_versions: dict[str, str], thresholds: dict[str, Any]) -> str:
    return keccak256_hex(canonical_json({"rules": rule_versions, "thresholds": thresholds}))


def snapshot_hash(file_hashes: dict[str, str]) -> str:
    """keccak256 over the sorted (path, sha256) pairs of a month's manifest."""
    return keccak256_hex(canonical_json(sorted(file_hashes.items())))
