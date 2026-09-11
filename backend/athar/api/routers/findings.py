"""Findings with evidence refs, leaf hash and proof; exception grants (SPEC §13, §10.3)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Path

from athar.api.problem import NotFoundError
from athar.api.routers.common import DECIDE, READ_LIST, READ_ONE, ApproverDep, FiltersDep, RepoDep
from athar.api.schemas import ExceptionRequest, FindingOut, Page
from athar.security.rbac import require_viewer

router = APIRouter(prefix="/findings", tags=["findings"], dependencies=[Depends(require_viewer)])

FindingKey = Annotated[str, Path(pattern=r"^[0-9a-f]{32}$", description="sha256('v1|identity|rule')[:32]")]


@router.get("", response_model=Page[FindingOut], responses=READ_LIST)
def list_findings(repo: RepoDep, filters: FiltersDep) -> Page[FindingOut]:
    """Flat finding list with filters (cloud, department, rule, severity, month, status, q)."""
    return repo.list_findings(filters)


@router.get("/{finding_key}", response_model=FindingOut, responses=READ_ONE)
def get_finding(finding_key: FindingKey, repo: RepoDep) -> FindingOut:
    """One finding with evidence refs, three altitudes, leaf hash and Merkle proof."""
    finding = repo.finding(finding_key)
    if finding is None:
        raise NotFoundError("finding", code="finding.not_found")
    return finding


@router.post("/{finding_key}/exception", response_model=FindingOut, responses=DECIDE)
def grant_exception(
    finding_key: FindingKey, body: ExceptionRequest, user: ApproverDep, repo: RepoDep
) -> FindingOut:
    """Approver only: record a governance exception (register + ledger `exception_granted`).
    The next scan suppresses the rule for this identity with an explanation (SPEC §4.3, §10.3)."""
    finding = repo.grant_exception(finding_key, user, body)
    if finding is None:
        raise NotFoundError("finding", code="finding.not_found")
    return finding
