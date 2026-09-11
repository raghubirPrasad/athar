"""Dependency aliases and OpenAPI response documentation shared by the routers (SPEC §13)."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Query

from athar.api.deps import Repo, get_repo, get_settings_dep
from athar.api.problem import problem_responses
from athar.api.schemas import ListFilters
from athar.config import Settings
from athar.security.auth import AuthUser
from athar.security.rbac import require_analyst, require_approver, require_viewer

RepoDep = Annotated[Repo, Depends(get_repo)]
SettingsDep = Annotated[Settings, Depends(get_settings_dep)]
# Query-parameter model: unknown parameters are rejected (extra="forbid") and limit ≤ 500 is
# enforced by the model, so a bad page request is a 422 problem before any handler runs.
FiltersDep = Annotated[ListFilters, Query()]
ViewerDep = Annotated[AuthUser, Depends(require_viewer)]
AnalystDep = Annotated[AuthUser, Depends(require_analyst)]
ApproverDep = Annotated[AuthUser, Depends(require_approver)]

READ_LIST = problem_responses(401, 403, 422, 503)
READ_ONE = problem_responses(401, 403, 404, 422, 503)
RUN = problem_responses(401, 403, 422, 503)
RUN_ONE = problem_responses(401, 403, 404, 422, 503)
DECIDE = problem_responses(401, 403, 404, 409, 422, 503)
