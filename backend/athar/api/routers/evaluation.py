"""Evaluation results on the held-out seed (SPEC §17)."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from athar.api.routers.common import READ_LIST, RepoDep
from athar.api.schemas import EvalOut
from athar.security.rbac import require_viewer

router = APIRouter(prefix="/eval", tags=["eval"], dependencies=[Depends(require_viewer)])


@router.get("", response_model=EvalOut, responses=READ_LIST)
def eval_result(repo: RepoDep) -> EvalOut:
    """Precision / recall / F1 at High+, per-rule confusion, decoy table, two-register sentences."""
    return repo.eval_result()
