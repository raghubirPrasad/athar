"""Agent endpoints (SPEC §11, §13). Cache-aware; `?regenerate=true` bypasses the cache.

Agents explain; they never create findings, change severities or scores, or pick an action
outside `allowed_actions` (CLAUDE.md non-negotiable 5). Rate limited to 20/min/IP.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Path, Query
from fastapi.concurrency import run_in_threadpool

from athar.api.problem import NotFoundError
from athar.api.routers.common import RUN, RUN_ONE, AnalystDep, RepoDep
from athar.api.schemas import InvestigationOut, RemediationPlanOut, SummaryOut

router = APIRouter(prefix="/agent", tags=["agent"])

FindingKey = Annotated[str, Path(pattern=r"^[0-9a-f]{32}$")]
Regenerate = Annotated[bool, Query(description="Bypass the LLM cache and call the provider again")]


@router.post("/investigate/{finding_key}", response_model=InvestigationOut, responses=RUN_ONE)
async def investigate(
    finding_key: FindingKey, user: AnalystDep, repo: RepoDep, regenerate: Regenerate = False
) -> InvestigationOut:
    """Hypothesis, expected-for-role verdict, cited evidence and a recommended action from `allowed_actions`."""
    result = await run_in_threadpool(repo.investigate, finding_key, regenerate, user)
    if result is None:
        raise NotFoundError("finding", code="finding.not_found")
    return result


@router.post("/plan/{finding_key}", response_model=RemediationPlanOut, responses=RUN_ONE)
async def plan_remediation(
    finding_key: FindingKey, user: AnalystDep, repo: RepoDep, regenerate: Regenerate = False
) -> RemediationPlanOut:
    """Least-privilege remediation plan with provider-native before/after policy diff (SPEC §11.5)."""
    result = await run_in_threadpool(repo.plan, finding_key, regenerate, user)
    if result is None:
        raise NotFoundError("finding", code="finding.not_found")
    return result


@router.post("/summary", response_model=SummaryOut, responses=RUN)
async def executive_summary(user: AnalystDep, repo: RepoDep, regenerate: Regenerate = False) -> SummaryOut:
    """Executive paragraph from aggregate statistics only (no identities leave the estate)."""
    return await run_in_threadpool(repo.summary, regenerate, user)
