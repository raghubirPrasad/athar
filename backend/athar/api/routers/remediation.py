"""Remediation queue and decisions (SPEC §11.5, §13, §15.1).

Separation of duties and the state machine are enforced HERE, server-side, before the
repository is asked to do anything:
- approve: plan must be `proposed`; a human proposer may not approve their own plan
  (model-proposed plans may be approved by any approver);
- reject: plan must be `proposed` or `approved`;
- apply: plan must be `approved`.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Path
from fastapi.concurrency import run_in_threadpool

from athar.api.deps import Repo
from athar.api.problem import ConflictError, ForbiddenError, NotFoundError
from athar.api.routers.common import DECIDE, READ_LIST, READ_ONE, ApproverDep, FiltersDep, RepoDep
from athar.api.schemas import ApplyResult, Page, RejectRequest, RemediationPlanOut
from athar.security.auth import AuthUser
from athar.security.rbac import require_viewer

router = APIRouter(prefix="/remediation", tags=["remediation"])

PlanId = Annotated[str, Path(min_length=1, max_length=64)]


def _load_plan(repo: Repo, plan_id: str, *expected: str) -> RemediationPlanOut:
    plan = repo.get_plan(plan_id)
    if plan is None:
        raise NotFoundError("plan", code="plan.not_found")
    if plan.status not in expected:
        raise ConflictError(
            "plan.invalid_state", f"Plan is '{plan.status}'; this decision needs one of {sorted(expected)}"
        )
    return plan


def assert_separation_of_duties(plan: RemediationPlanOut, user: AuthUser) -> None:
    """SPEC §15.1: a plan cannot be approved by the user who proposed it."""
    if plan.proposed_by != "model" and plan.proposer_user_id == user.user_id:
        raise ForbiddenError(
            "rbac.separation_of_duties", "A plan cannot be approved by the user who proposed it"
        )


# SPEC? §13 lists the whole /remediation row as approver; the queue itself is read-only, so it
# is served to viewers (role ordering for reads) while every decision stays approver-only.
@router.get(
    "", response_model=Page[RemediationPlanOut], responses=READ_LIST, dependencies=[Depends(require_viewer)]
)
def list_plans(repo: RepoDep, filters: FiltersDep) -> Page[RemediationPlanOut]:
    """Queue of proposed plans with rationale, confidence, model id and decision trail."""
    return repo.list_plans(filters)


@router.get(
    "/{plan_id}",
    response_model=RemediationPlanOut,
    responses=READ_ONE,
    dependencies=[Depends(require_viewer)],
)
def get_plan(plan_id: PlanId, repo: RepoDep) -> RemediationPlanOut:
    plan = repo.get_plan(plan_id)
    if plan is None:
        raise NotFoundError("plan", code="plan.not_found")
    return plan


@router.post("/{plan_id}/approve", response_model=RemediationPlanOut, responses=DECIDE)
async def approve_plan(plan_id: PlanId, user: ApproverDep, repo: RepoDep) -> RemediationPlanOut:
    """Approver only. Records `approved` on the ledger with the finding's proof."""
    plan = _load_plan(repo, plan_id, "proposed")
    assert_separation_of_duties(plan, user)
    return await run_in_threadpool(repo.approve, plan_id, user)


@router.post("/{plan_id}/reject", response_model=RemediationPlanOut, responses=DECIDE)
async def reject_plan(
    plan_id: PlanId, body: RejectRequest, user: ApproverDep, repo: RepoDep
) -> RemediationPlanOut:
    """Approver only. The finding returns to `open`; a new plan can be proposed (SPEC §10.3)."""
    _load_plan(repo, plan_id, "proposed", "approved")
    return await run_in_threadpool(repo.reject, plan_id, user, body.reason)


@router.post("/{plan_id}/apply", response_model=ApplyResult, responses=DECIDE)
async def apply_plan(plan_id: PlanId, user: ApproverDep, repo: RepoDep) -> ApplyResult:
    """Approver only; requires a prior approve. Appends the remediation event, re-ingests,
    re-scans, anchors `remediation_applied` and returns before/after scores."""
    _load_plan(repo, plan_id, "approved")
    return await run_in_threadpool(repo.apply, plan_id, user)
