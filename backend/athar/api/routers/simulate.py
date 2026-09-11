"""Simulated-month advance (SPEC §4.7, §11.6 `/simulate/advance`)."""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.concurrency import run_in_threadpool

from athar.api.routers.common import RUN, AnalystDep, RepoDep
from athar.api.schemas import AdvanceResult

router = APIRouter(prefix="/simulate", tags=["simulate"])


@router.post("/advance", response_model=AdvanceResult, responses=RUN)
async def advance(user: AnalystDep, repo: RepoDep) -> AdvanceResult:
    """Analyst: generate the next month of the estate, ingest it and run the scan loop.
    Generated estates only — the demo's "watch drift happen" button."""
    return await run_in_threadpool(repo.advance, user)
