"""Ingest: native provider files → canonical rows → Postgres (SPEC §2, §5, §15.2).

`normalise_month` is pure and `upsert_month` is idempotent on the natural keys, so ingesting the
same month twice writes the same rows and changes no counts (CLAUDE.md non-negotiable 2).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy.orm import Session

from athar.config import Settings
from athar.log import get_logger
from athar.normaliser.pipeline import NormaliserError, normalise_month
from athar.normaliser.upsert import UpsertStats, upsert_month

log = get_logger(__name__)


@dataclass
class IngestResult:
    month: int
    stats: UpsertStats
    unmapped: int = 0
    warnings: list[str] = field(default_factory=list)


def months_on_disk(estate_dir: Path) -> list[int]:
    """Every `month-NN` directory present, ascending."""
    if not estate_dir.is_dir():
        return []
    months: list[int] = []
    for child in sorted(estate_dir.iterdir()):
        if child.is_dir() and child.name.startswith("month-"):
            suffix = child.name.removeprefix("month-")
            if suffix.isdigit():
                months.append(int(suffix))
    return sorted(months)


def ingest_month(session: Session, estate_dir: Path, month: int) -> IngestResult:
    nm = normalise_month(estate_dir, month)
    stats = upsert_month(session, nm)
    session.commit()
    log.info(
        "ingested month",
        extra={
            "month": month,
            "identities": stats.identities,
            "grants": stats.grants,
            "unmapped": len(nm.unmapped),
        },
    )
    return IngestResult(
        month=month, stats=stats, unmapped=len(nm.unmapped), warnings=list(nm.warnings) + stats.warnings
    )


def ingest_all(session: Session, estate_dir: Path, *, months: list[int] | None = None) -> list[IngestResult]:
    """Ingest every month directory present (or the given subset), oldest first."""
    wanted = months if months is not None else months_on_disk(estate_dir)
    if not wanted:
        raise NormaliserError(f"no month directories under {estate_dir}")
    return [ingest_month(session, estate_dir, month) for month in wanted]


def estate_dir_for(settings: Settings, seed: int | None = None) -> Path:
    """`<ATHAR_DATA_DIR>/estate/seed-<seed>` — the layout the generator writes (SPEC §4.7)."""
    return Path(settings.data_dir) / "estate" / f"seed-{seed if seed is not None else settings.athar_seed}"
