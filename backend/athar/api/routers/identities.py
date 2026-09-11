"""Identity table and drill-down (SPEC §13, §14)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Path

from athar.api.problem import NotFoundError
from athar.api.routers.common import READ_LIST, READ_ONE, FiltersDep, RepoDep
from athar.api.schemas import IdentityDetail, IdentityRow, Page
from athar.security.rbac import require_viewer

router = APIRouter(prefix="/identities", tags=["identities"], dependencies=[Depends(require_viewer)])

IdentityId = Annotated[str, Path(min_length=1, max_length=128)]


@router.get("", response_model=Page[IdentityRow], responses=READ_LIST)
def list_identities(repo: RepoDep, filters: FiltersDep) -> Page[IdentityRow]:
    """Table rows with score, severity, clouds and top rule; server-side sort/filter/pagination."""
    return repo.list_identities(filters)


@router.get("/{identity_id}", response_model=IdentityDetail, responses=READ_ONE)
def identity_detail(identity_id: IdentityId, repo: RepoDep) -> IdentityDetail:
    """Grants, activity, credentials, findings, score line items, escalation chain, causal history,
    12-month risk history, exceptions and the three altitudes of the top finding."""
    detail = repo.identity_detail(identity_id)
    if detail is None:
        raise NotFoundError("identity", code="identity.not_found")
    return detail
