"""Ledger view and verification (SPEC §12.1, §12.6, §13)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Path
from fastapi.concurrency import run_in_threadpool

from athar.api.problem import NotFoundError
from athar.api.routers.common import READ_LIST, READ_ONE, FiltersDep, RepoDep
from athar.api.schemas import LedgerDecisionOut, LedgerInfo, LedgerScanOut, LedgerVerifyOut, Page
from athar.security.rbac import require_viewer

router = APIRouter(prefix="/ledger", tags=["ledger"], dependencies=[Depends(require_viewer)])

ScanId = Annotated[int, Path(ge=1)]


@router.get("", response_model=LedgerInfo, responses=READ_LIST)
def ledger_info(repo: RepoDep) -> LedgerInfo:
    """Contract address, chain id, writer, and the honest statement of what the ledger does and
    does not protect against (SPEC §12.1)."""
    return repo.ledger_info()


@router.get("/scans", response_model=Page[LedgerScanOut], responses=READ_LIST)
def ledger_scans(repo: RepoDep, filters: FiltersDep) -> Page[LedgerScanOut]:
    """Commits: scan, month, root, tx, block, status."""
    return repo.ledger_scans(filters)


@router.get("/scans/{scan_id}/verify", response_model=LedgerVerifyOut, responses=READ_ONE)
async def ledger_verify(scan_id: ScanId, repo: RepoDep) -> LedgerVerifyOut:
    """Recompute leaves from the database, rebuild the root, compare with `getCommit(scanIndex)`."""
    result = await run_in_threadpool(repo.ledger_verify, scan_id)
    if result is None:
        raise NotFoundError("scan", code="scan.not_found")
    return result


@router.get("/decisions", response_model=Page[LedgerDecisionOut], responses=READ_LIST)
def ledger_decisions(repo: RepoDep, filters: FiltersDep) -> Page[LedgerDecisionOut]:
    """Decisions recorded on chain with actor hash, evidence hash and finding leaf."""
    return repo.ledger_decisions(filters)
