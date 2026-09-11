"""Overview KPIs (SPEC §13 `/estate/summary`, §14 Overview page)."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from athar.api.routers.common import READ_LIST, RepoDep
from athar.api.schemas import EstateSummary
from athar.security.rbac import require_viewer

router = APIRouter(prefix="/estate", tags=["estate"], dependencies=[Depends(require_viewer)])


@router.get("/summary", response_model=EstateSummary, responses=READ_LIST)
def estate_summary(repo: RepoDep) -> EstateSummary:
    """Counts by severity / cloud / department, current month, ledger badge, executive summary."""
    return repo.estate_summary()
