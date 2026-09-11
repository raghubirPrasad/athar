"""Row identity helpers for the normaliser (SPEC §5.1, §6). Pure.

Every canonical row has a deterministic id derived from its natural key so that
re-ingesting the same files is idempotent (CLAUDE.md non-negotiable 2).
"""

from __future__ import annotations

from datetime import date
from typing import Any

from athar.hashing import sha256_hex


def grant_id(
    principal_ref: str,
    cloud: str,
    service_category: str,
    verb: str,
    scope_ref: str,
    granted_via: str,
    snapshot_month: int,
) -> str:
    """sha256 hex[:32] of the grant natural key (SPEC §5.1 UNIQUE constraint)."""
    key = "|".join(
        [principal_ref, cloud, service_category, verb, scope_ref, granted_via, str(snapshot_month)]
    )
    return sha256_hex(key.encode())[:32]


def credential_ref(cloud: str, kind: str, native_id: str) -> str:
    """`<cloud>:<kind>:<native id>` (brief)."""
    return f"{cloud}:{kind}:{native_id}"


def svc_identity_id(project: str, name: str) -> str:
    """Synthetic service identity `svc:<project>:<name>` (SPEC §6 rule 4)."""
    return f"svc:{project}:{name}"


def unlinked_identity_id(cloud: str, principal_ref: str) -> str:
    """Synthetic identity for a principal the linker could not place (SPEC §6 rule 6)."""
    return f"unlinked:{cloud}:{principal_ref}"


def exception_id(identity_id: str, exception_type: str, *dates: date | None) -> str:
    parts = [identity_id, exception_type, *(d.isoformat() if d else "" for d in dates)]
    return sha256_hex("|".join(parts).encode())[:32]


def event_id(month: int, index: int) -> str:
    """Deterministic id for an events.jsonl line that carries none (line index is stable: the
    file is append-only, SPEC §4.7)."""
    return f"ev-{month:02d}-{index:05d}"


def json_pointer(*parts: Any) -> str:
    """RFC 6901 JSON pointer from path segments (`~` → `~0`, `/` → `~1`)."""
    return "/" + "/".join(str(p).replace("~", "~0").replace("/", "~1") for p in parts)


def csv_pointer(row_number: int) -> str:
    """`row:<n>` for CSV sources (1-based, header excluded)."""
    return f"row:{row_number}"


def normalise_email(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = value.strip().lower()
    return cleaned if "@" in cleaned else None


def local_part(email: str) -> str:
    return email.split("@", 1)[0]
