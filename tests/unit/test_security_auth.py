"""JWT + argon2id + session cookie (SPEC §13, §15.1). Pure `athar.security.auth` behaviour."""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt
import pytest

sys.path.insert(0, str(Path(__file__).parent))
from _api_support import make_settings
from athar.security.auth import (
    COOKIE_NAME,
    JWT_ALGORITHM,
    AuthUser,
    clear_session_cookie,
    create_token,
    decode_token,
    hash_password,
    set_session_cookie,
    verify_password,
)
from athar.security.rbac import ROLE_RANK, has_role
from fastapi import Response

USER = AuthUser(user_id="usr-analyst", email="analyst@athar.local", role="analyst")
NOW = datetime(2026, 9, 1, 9, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def settings():
    return make_settings()


# ----------------------------------------------------------------- passwords


def test_hash_password_is_argon2id_and_verifies() -> None:
    digest = hash_password("correct horse")
    assert digest.startswith("$argon2id$")
    assert verify_password(digest, "correct horse")
    assert not verify_password(digest, "correct horsE")


def test_hash_password_is_salted() -> None:
    assert hash_password("same") != hash_password("same")


def test_verify_password_handles_garbage_hash() -> None:
    assert verify_password("not-a-hash", "anything") is False
    assert verify_password("", "anything") is False


# -------------------------------------------------------------------- tokens


def test_token_roundtrip_carries_user(settings) -> None:
    token = create_token(USER, settings, now=NOW)
    assert decode_token(token, settings, now=NOW + timedelta(hours=1)) == USER


def test_token_expires_after_ttl(settings) -> None:
    token = create_token(USER, settings, now=NOW)
    assert decode_token(token, settings, now=NOW + timedelta(hours=settings.jwt_ttl_hours - 1)) == USER
    assert decode_token(token, settings, now=NOW + timedelta(hours=settings.jwt_ttl_hours)) is None


def test_token_ttl_is_twelve_hours_by_default(settings) -> None:
    payload = jwt.decode(
        create_token(USER, settings, now=NOW),
        settings.jwt_secret,
        algorithms=[JWT_ALGORITHM],
        issuer="athar",
        options={"verify_exp": False},  # NOW is a fixed past instant; only the claim arithmetic matters
    )
    assert payload["exp"] - payload["iat"] == 12 * 3600
    assert payload["sub"] == USER.user_id and payload["role"] == "analyst" and payload["iss"] == "athar"


def test_token_wrong_secret_rejected(settings) -> None:
    other = make_settings(JWT_SECRET="another-secret-that-is-also-long-enough-for-hs256-xx")
    assert decode_token(create_token(USER, other), settings) is None


def test_token_tampered_payload_rejected(settings) -> None:
    header, _payload, signature = create_token(USER, settings).split(".")
    forged = jwt.encode({"sub": "usr-judge", "role": "approver"}, "x", algorithm="HS256").split(".")[1]
    assert decode_token(f"{header}.{forged}.{signature}", settings) is None


def test_token_alg_none_rejected(settings) -> None:
    unsigned = jwt.encode(
        {
            "sub": "usr-judge",
            "email": "judge@athar.local",
            "role": "approver",
            "iss": "athar",
            "iat": 1,
            "exp": 2**31,
        },
        key="",
        algorithm="none",
    )
    assert decode_token(unsigned, settings) is None


def test_token_unknown_role_rejected(settings) -> None:
    payload = {
        "sub": "usr-x",
        "email": "x@athar.local",
        "role": "root",
        "iss": "athar",
        "iat": int(NOW.timestamp()),
        "exp": int((NOW + timedelta(hours=1)).timestamp()),
    }
    token = jwt.encode(payload, settings.jwt_secret, algorithm=JWT_ALGORITHM)
    assert decode_token(token, settings, now=NOW) is None


def test_token_missing_claims_rejected(settings) -> None:
    token = jwt.encode(
        {"sub": "usr-x", "role": "viewer", "iss": "athar"}, settings.jwt_secret, algorithm="HS256"
    )
    assert decode_token(token, settings) is None


def test_decode_garbage_returns_none(settings) -> None:
    assert decode_token("", settings) is None
    assert decode_token("not.a.jwt", settings) is None


# ------------------------------------------------------------------- cookies


def _cookie(response: Response) -> str:
    return response.headers["set-cookie"].lower()


def test_session_cookie_is_httponly_strict_path_root(settings) -> None:
    response = Response()
    set_session_cookie(response, "tok", settings)
    cookie = _cookie(response)
    assert cookie.startswith(f"{COOKIE_NAME}=tok;")
    assert "httponly" in cookie
    assert "samesite=strict" in cookie
    assert "path=/" in cookie
    assert f"max-age={settings.jwt_ttl_hours * 3600}" in cookie
    assert "secure" not in cookie  # COOKIE_SECURE=false on plain http dev


def test_session_cookie_secure_when_configured() -> None:
    response = Response()
    set_session_cookie(response, "tok", make_settings(COOKIE_SECURE=True))
    assert "secure" in _cookie(response)


def test_clear_session_cookie_expires_it(settings) -> None:
    response = Response()
    clear_session_cookie(response, settings)
    cookie = _cookie(response)
    assert cookie.startswith(f'{COOKIE_NAME}=""') or cookie.startswith(f"{COOKIE_NAME}=;")
    assert "max-age=0" in cookie
    assert "httponly" in cookie and "samesite=strict" in cookie


# ---------------------------------------------------------------------- rbac


def test_role_ordering_viewer_analyst_approver() -> None:
    assert ROLE_RANK["viewer"] < ROLE_RANK["analyst"] < ROLE_RANK["approver"]
    assert has_role("approver", "analyst") and has_role("approver", "viewer")
    assert has_role("analyst", "viewer") and not has_role("analyst", "approver")
    assert not has_role("viewer", "analyst")
    assert not has_role("root", "viewer")  # unknown role never satisfies anything
