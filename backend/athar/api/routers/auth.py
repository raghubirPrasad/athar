"""Session endpoints (SPEC §13, §15.1). The JWT lives only in the httpOnly cookie."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Response

from athar.api.deps import get_user_store
from athar.api.problem import UnauthorizedError, problem_responses
from athar.api.routers.common import SettingsDep
from athar.api.schemas import LoginRequest, LogoutOut, UserOut
from athar.security.auth import AuthUser, clear_session_cookie, create_token, set_session_cookie
from athar.security.rbac import get_current_user
from athar.security.users import UserStore, authenticate

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=UserOut, responses=problem_responses(401, 403, 422, 429))
def login(
    body: LoginRequest,
    response: Response,
    store: Annotated[UserStore, Depends(get_user_store)],
    settings: SettingsDep,
) -> UserOut:
    """Exchange email + password for the `athar_session` cookie. Rate limited to 5/min/IP."""
    user = authenticate(store, body.email, body.password)
    if user is None:
        raise UnauthorizedError("Invalid email or password", code="auth.invalid_credentials")
    set_session_cookie(response, create_token(user, settings), settings)
    return UserOut(user_id=user.user_id, email=user.email, role=user.role)


@router.post("/logout", response_model=LogoutOut, responses=problem_responses(403))
def logout(response: Response, settings: SettingsDep) -> LogoutOut:
    """Clear the session cookie. Safe to call without a session."""
    clear_session_cookie(response, settings)
    return LogoutOut()


@router.get("/me", response_model=UserOut, responses=problem_responses(401))
def me(user: Annotated[AuthUser, Depends(get_current_user)]) -> UserOut:
    """The user behind the current session cookie."""
    return UserOut(user_id=user.user_id, email=user.email, role=user.role)
