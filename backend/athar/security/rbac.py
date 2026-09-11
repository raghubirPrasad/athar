"""Roles and role-gated dependencies (SPEC §13, §15.1).

Ordering for reads and runs: viewer < analyst < approver. Decisions are approver-only.
Separation of duties (a proposer cannot approve their own plan) is enforced in the
remediation router, where the plan is known.
"""

from __future__ import annotations

from collections.abc import Callable

from fastapi import Depends, Request

from athar.api.problem import ForbiddenError, UnauthorizedError
from athar.config import Settings, get_settings
from athar.security.auth import COOKIE_NAME, AuthUser, Role, decode_token

ROLE_RANK: dict[str, int] = {"viewer": 0, "analyst": 1, "approver": 2}


def has_role(user_role: str, minimum: Role) -> bool:
    return ROLE_RANK.get(user_role, -1) >= ROLE_RANK[minimum]


def settings_for(request: Request) -> Settings:
    """The app's Settings (set by create_app), falling back to the process-wide settings."""
    settings = getattr(request.app.state, "settings", None)
    return settings if isinstance(settings, Settings) else get_settings()


def user_from_request(request: Request) -> AuthUser | None:
    """Decode the session cookie without raising (used by logging and optional auth)."""
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    return decode_token(token, settings_for(request))


def get_current_user(request: Request) -> AuthUser:
    user = user_from_request(request)
    if user is None:
        raise UnauthorizedError()
    return user


def require_role(minimum: Role) -> Callable[..., AuthUser]:
    def dependency(user: AuthUser = Depends(get_current_user)) -> AuthUser:
        if not has_role(user.role, minimum):
            raise ForbiddenError("rbac.role_required", f"Requires role {minimum} or higher")
        return user

    dependency.__name__ = f"require_{minimum}"
    return dependency


# Shared instances so OpenAPI shows one dependency per role and routers stay terse.
require_viewer = require_role("viewer")
require_analyst = require_role("analyst")
require_approver = require_role("approver")
