"""Runtime settings (SPEC §13, §15.1). `auto_remediate_departed` is approver-only."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from athar.api.problem import ForbiddenError
from athar.api.routers.common import READ_LIST, RUN, AnalystDep, RepoDep
from athar.api.schemas import SettingsOut, SettingsUpdate
from athar.security.rbac import has_role, require_viewer

router = APIRouter(prefix="/settings", tags=["settings"])


# SPEC? §13 lists GET /settings as analyst; the page only displays thresholds and LLM status,
# so it is readable by viewers. Writes stay analyst (approver for the auto-remediation flag).
@router.get("", response_model=SettingsOut, responses=READ_LIST, dependencies=[Depends(require_viewer)])
def get_settings(repo: RepoDep) -> SettingsOut:
    """Thresholds, approved regions, auto-remediation flag and LLM provider status."""
    return repo.get_settings()


@router.put("", response_model=SettingsOut, responses=RUN)
def put_settings(body: SettingsUpdate, user: AnalystDep, repo: RepoDep) -> SettingsOut:
    """Analyst may change thresholds and approved regions; only an approver may touch
    `auto_remediate_departed` (SPEC §15.1)."""
    if body.auto_remediate_departed is not None and not has_role(user.role, "approver"):
        raise ForbiddenError("rbac.approver_required", "Only an approver may change auto_remediate_departed")
    return repo.put_settings(body, user)
