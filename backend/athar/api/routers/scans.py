"""Scan runs and history (SPEC §13). Each scan carries its root, tx and ledger status."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Path

from athar.api.problem import NotFoundError
from athar.api.routers.common import READ_LIST, READ_ONE, RUN, AnalystDep, FiltersDep, RepoDep
from athar.api.schemas import Page, ScanOut, ScanRunRequest
from athar.security.rbac import require_viewer

run_router = APIRouter(tags=["scans"])
router = APIRouter(prefix="/scans", tags=["scans"], dependencies=[Depends(require_viewer)])

ScanId = Annotated[int, Path(ge=1)]


@run_router.post("/scan", response_model=ScanOut, responses=RUN)
def run_scan(user: AnalystDep, repo: RepoDep, body: ScanRunRequest | None = None) -> ScanOut:
    """Analyst: diff + rules + score + attest for `month` (default: current). Idempotent —
    the same snapshot, root and ruleset never commits twice (SPEC §12.4)."""
    return repo.run_scan(body.month if body else None, user)


@router.get("", response_model=Page[ScanOut], responses=READ_LIST)
def list_scans(repo: RepoDep, filters: FiltersDep) -> Page[ScanOut]:
    """Scan history, newest first by default."""
    return repo.list_scans(filters)


@router.get("/{scan_id}", response_model=ScanOut, responses=READ_ONE)
def get_scan(scan_id: ScanId, repo: RepoDep) -> ScanOut:
    scan = repo.scan(scan_id)
    if scan is None:
        raise NotFoundError("scan", code="scan.not_found")
    return scan
