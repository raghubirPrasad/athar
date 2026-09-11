"""Per-month series for the timeline replay (SPEC §9, §13, §14)."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from athar.api.routers.common import READ_LIST, RepoDep
from athar.api.schemas import TimelineOut
from athar.security.rbac import require_viewer

router = APIRouter(prefix="/timeline", tags=["timeline"], dependencies=[Depends(require_viewer)])


@router.get("", response_model=TimelineOut, responses=READ_LIST)
def timeline(repo: RepoDep) -> TimelineOut:
    """Identity count, findings by severity, median score and half-life per department, per month."""
    return repo.timeline()
