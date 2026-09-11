"""The judge path, in miniature: generate → ingest → scan → scan again (SPEC §17, §18.4).

These are the rubric's own checks (CLAUDE.md non-negotiables 1, 2 and 4): the pipeline runs end to
end, a second run is clean, and the same seed produces the same answer. A small estate keeps it
fast; `make demo` exercises the full 500 × 12 one.

Needs Postgres (the `db_url` fixture skips otherwise). The module owns a private schema, so
running the tests never touches a seeded demo database: `make test` after `make demo` leaves the
dashboard's data alone. The ledger is deliberately not used here — `writer=None` makes every scan
`unanchored`, which is the documented degraded path (SPEC §12.4); anchoring has its own tests in
tests/ledger/.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

import pytest
from athar.config import Settings, get_settings
from athar.db import models as m
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.orm import Session

pytestmark = pytest.mark.integration

# Per-process so two test runs against one Postgres cannot drop each other's schema.
SCHEMA = f"athar_test_e2e_{os.getpid()}"
SEED = 42
MONTHS = 3
IDENTITIES = 60


@pytest.fixture(scope="module")
def settings() -> Settings:
    return get_settings()


@pytest.fixture(scope="module")
def estate(tmp_path_factory: pytest.TempPathFactory) -> Path:
    generate = pytest.importorskip(
        "athar.generator.estate", reason="the generator lane is not on disk yet"
    ).generate_estate
    out = tmp_path_factory.mktemp("estate")
    return Path(generate(seed=SEED, months=MONTHS, identities=IDENTITIES, out_dir=out))


@pytest.fixture(scope="module")
def engine(db_url: str) -> Any:
    """A private schema, created and dropped by this module. Never the demo database's tables."""
    admin = create_engine(db_url, future=True)
    with admin.begin() as conn:
        conn.execute(text(f"DROP SCHEMA IF EXISTS {SCHEMA} CASCADE"))
        conn.execute(text(f"CREATE SCHEMA {SCHEMA}"))
    admin.dispose()
    scoped = create_engine(db_url, future=True, connect_args={"options": f"-csearch_path={SCHEMA}"})
    m.Base.metadata.create_all(scoped)
    yield scoped
    scoped.dispose()
    admin = create_engine(db_url, future=True)
    with admin.begin() as conn:
        conn.execute(text(f"DROP SCHEMA IF EXISTS {SCHEMA} CASCADE"))
    admin.dispose()


@pytest.fixture()
def session(engine: Any) -> Any:
    with Session(engine) as s:
        yield s
        s.rollback()


def tree_digest(root: Path) -> str:
    """One hash over every generated file, so determinism is a single comparison."""
    h = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        h.update(str(path.relative_to(root)).encode())
        h.update(path.read_bytes())
    return h.hexdigest()


def counts(session: Session) -> dict[str, int]:
    return {
        name: int(session.scalar(select(func.count()).select_from(model)) or 0)
        for name, model in {
            "identities": m.Identity,
            "principals": m.Principal,
            "grants": m.Grant,
            "activity": m.Activity,
            "credentials": m.Credential,
            "resources": m.Resource,
            "projects": m.Project,
            "exceptions": m.GovernanceException,
            "events": m.Event,
            "snapshots": m.Snapshot,
            "scans": m.Scan,
            "findings": m.Finding,
            "identity_scores": m.IdentityScore,
        }.items()
    }


def test_generate_is_deterministic_and_idempotent(estate: Path, tmp_path: Path) -> None:
    from athar.generator.estate import generate_estate

    before = tree_digest(estate)
    again = Path(generate_estate(seed=SEED, months=MONTHS, identities=IDENTITIES, out_dir=tmp_path))
    assert tree_digest(again) == before, "the same seed must produce a byte-identical tree"

    # Re-running into the same directory changes nothing (SPEC §4.7).
    generate_estate(seed=SEED, months=MONTHS, identities=IDENTITIES, out_dir=estate.parent)
    assert tree_digest(estate) == before


def test_pipeline_runs_end_to_end_and_a_second_run_is_clean(
    session: Session, settings: Settings, estate: Path
) -> None:
    from athar.services.ingest import ingest_all
    from athar.services.scan import run_scan

    ingested = ingest_all(session, estate)
    assert [r.month for r in ingested] == list(range(1, MONTHS + 1))
    assert counts(session)["identities"] > 0
    assert counts(session)["grants"] > 0

    first = [run_scan(session, settings, month, writer=None) for month in range(1, MONTHS + 1)]
    assert all(o.finding_count >= 0 for o in first)
    assert any(o.finding_count > 0 for o in first), "a drifting estate must produce findings"
    after_first = counts(session)

    # --- second run: same files, same rules ----------------------------------
    ingest_all(session, estate)
    second = [run_scan(session, settings, month, writer=None) for month in range(1, MONTHS + 1)]
    after_second = counts(session)

    assert after_second == after_first, "a second run must not duplicate a single row"
    assert [o.scan_id for o in second] == [o.scan_id for o in first], "scans are re-used, not re-created"
    assert [o.merkle_root for o in second] == [o.merkle_root for o in first], "the root must be stable"
    assert all(not o.created for o in second)


def test_findings_carry_evidence_and_a_stable_key(session: Session, settings: Settings, estate: Path) -> None:
    from athar.hashing import finding_key
    from athar.services.ingest import ingest_all
    from athar.services.scan import run_scan

    ingest_all(session, estate)
    outcome = run_scan(session, settings, MONTHS, writer=None)
    rows = list(session.scalars(select(m.Finding).where(m.Finding.scan_id == outcome.scan_id)))
    assert rows, "the final month should have findings"
    for row in rows:
        assert row.finding_key == finding_key(row.identity_id, row.rule_id)
        assert row.evidence_refs, f"{row.rule_id} fired without citing a row"
        assert row.instance_hash.startswith("0x")
        assert row.severity in {"Low", "Medium", "High", "Critical"}
        assert 0 <= row.score <= 100


def test_every_finding_verifies_against_the_recomputed_root(
    session: Session, settings: Settings, estate: Path
) -> None:
    from athar.ledger import merkle
    from athar.ledger import verify as ledger_verify
    from athar.services.ingest import ingest_all
    from athar.services.scan import run_scan

    ingest_all(session, estate)
    outcome = run_scan(session, settings, MONTHS, writer=None)
    rows = list(session.scalars(select(m.Finding).where(m.Finding.scan_id == outcome.scan_id)))
    root = ledger_verify.compute_root([r.instance_hash for r in rows])
    assert root == outcome.merkle_root
    for row in rows:
        leaf = merkle.leaf_from_instance_hash(row.instance_hash)
        proof = [merkle.from_hex(p) for p in (row.leaf_proof or [])]
        assert merkle.verify(merkle.from_hex(root), leaf, proof), row.finding_key


def test_a_tampered_severity_breaks_the_root(session: Session, settings: Settings, estate: Path) -> None:
    """The demo's tamper beat, without the chain: the recomputed root must move (SPEC §12.6)."""
    from athar.hashing import finding_instance, instance_hash
    from athar.ledger import verify as ledger_verify
    from athar.services.ingest import ingest_all
    from athar.services.scan import run_scan

    ingest_all(session, estate)
    outcome = run_scan(session, settings, MONTHS, writer=None)
    rows = list(session.scalars(select(m.Finding).where(m.Finding.scan_id == outcome.scan_id)))
    assert rows

    # Pick a victim whose severity actually changes, or the instance hash would not move.
    victim = next((r for r in rows if r.severity != "Low"), rows[0])
    assert victim.severity != "Low", "the estate should produce at least one finding above Low"
    tampered = finding_instance(
        finding_key=victim.finding_key,
        identity_id=victim.identity_id,
        rule_id=victim.rule_id,
        severity="Low",  # the edit an insider would make
        score=victim.score,
        snapshot_month=outcome.month,
        first_seen_month=victim.first_seen_month,
        evidence_refs=list(victim.evidence_refs or []),
        causal_event_ids=list(victim.causal_event_ids or []),
    )
    hashes = [instance_hash(tampered) if r is victim else r.instance_hash for r in rows]
    assert ledger_verify.compute_root(hashes) != outcome.merkle_root
