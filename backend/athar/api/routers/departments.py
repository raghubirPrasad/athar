"""Department half-life table (SPEC §9.3, §13)."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from athar.api.routers.common import READ_LIST, RepoDep
from athar.api.schemas import HalfLifeTable
from athar.security.rbac import require_viewer

router = APIRouter(prefix="/departments", tags=["departments"], dependencies=[Depends(require_viewer)])


@router.get("/halflife", response_model=HalfLifeTable, responses=READ_LIST)
def department_halflife(repo: RepoDep) -> HalfLifeTable:
    """Offboarding half-life per department and trigger; `null` months means Never."""
    return repo.halflife()
