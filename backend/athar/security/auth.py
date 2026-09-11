"""JWT (HS256, PyJWT) + argon2id password hashing + session cookie (SPEC §13, §15.1).

The token lives only in the `athar_session` httpOnly cookie; it is never returned in a body.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal, cast

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import Response

from athar.config import Settings

COOKIE_NAME = "athar_session"
JWT_ALGORITHM = "HS256"
Role = Literal["viewer", "analyst", "approver"]
ROLES: tuple[Role, ...] = ("viewer", "analyst", "approver")

_hasher = PasswordHasher()  # argon2id, library defaults (t=3, m=64 MiB, p=4)


@dataclass(frozen=True)
class AuthUser:
    user_id: str
    email: str
    role: Role


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def create_token(user: AuthUser, settings: Settings, *, now: datetime | None = None) -> str:
    issued = now or datetime.now(UTC)
    payload = {
        "sub": user.user_id,
        "email": user.email,
        "role": user.role,
        "iat": int(issued.timestamp()),
        "exp": int((issued + timedelta(hours=settings.jwt_ttl_hours)).timestamp()),
        "iss": "athar",
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=JWT_ALGORITHM)


def decode_token(token: str, settings: Settings, *, now: datetime | None = None) -> AuthUser | None:
    """Return the user carried by a valid, unexpired token; None for anything else.

    `now` replaces the wall clock for the exp/iat checks (tests only); production callers omit it.
    """
    injected = now is not None
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[JWT_ALGORITHM],
            issuer="athar",
            options={
                "require": ["exp", "iat", "sub"],
                "verify_exp": not injected,
                "verify_iat": not injected,
            },
            leeway=0,
        )
    except jwt.PyJWTError:
        return None
    if now is not None:
        ts = int(now.timestamp())
        if int(payload["exp"]) <= ts or int(payload["iat"]) > ts:
            return None
    role = payload.get("role")
    sub = payload.get("sub")
    email = payload.get("email")
    if role not in ROLES or not isinstance(sub, str) or not isinstance(email, str):
        return None
    return AuthUser(user_id=sub, email=email, role=cast(Role, role))


def set_session_cookie(response: Response, token: str, settings: Settings) -> None:
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=settings.jwt_ttl_hours * 3600,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        path="/",
    )


def clear_session_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        key=COOKIE_NAME, path="/", httponly=True, secure=settings.cookie_secure, samesite="strict"
    )
