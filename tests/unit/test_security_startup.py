"""`Settings.assert_startable()` — what the app refuses to start with (SPEC §15.1).

`ATHAR_DEV=true` is the demo path and allows every example value. `ATHAR_DEV=false` says the
process is hosted, and then each published credential in `.env.example` is a live one: the demo
passwords are written by `seed_users` on every start, a short `JWT_SECRET` weakens HS256, and
`COOKIE_SECURE=false` puts the session cookie on plain HTTP.
"""

from __future__ import annotations

from typing import Any

import pytest
from athar.config import (
    EXAMPLE_ANALYST_PASSWORD,
    EXAMPLE_APPROVER_PASSWORD,
    EXAMPLE_JUDGE_PASSWORD,
    EXAMPLE_JWT_SECRET,
    MIN_JWT_SECRET_CHARS,
    Settings,
)

REAL_SECRET = "b8a1f0c2d3e4f5a60718293a4b5c6d7e8f90a1b2c3d4e5f6"  # 48 chars, not the example
HOSTED: dict[str, Any] = {
    "ATHAR_DEV": False,
    "JWT_SECRET": REAL_SECRET,
    "DEMO_ANALYST_PASSWORD": "analyst-real-8f21",
    "DEMO_APPROVER_PASSWORD": "approver-real-3c07",
    "DEMO_JUDGE_PASSWORD": "judge-real-5b44",
    "COOKIE_SECURE": True,
}


def settings(**overrides: Any) -> Settings:
    return Settings(_env_file=None, **{**HOSTED, **overrides})


def refusal(**overrides: Any) -> str:
    with pytest.raises(RuntimeError) as exc:
        settings(**overrides).assert_startable()
    return str(exc.value)


def test_a_fully_configured_hosted_process_starts() -> None:
    settings().assert_startable()  # no raise


def test_dev_mode_allows_every_example_value() -> None:
    Settings(
        _env_file=None,
        ATHAR_DEV=True,
        JWT_SECRET=EXAMPLE_JWT_SECRET,
        DEMO_ANALYST_PASSWORD=EXAMPLE_ANALYST_PASSWORD,
        DEMO_APPROVER_PASSWORD=EXAMPLE_APPROVER_PASSWORD,
        DEMO_JUDGE_PASSWORD=EXAMPLE_JUDGE_PASSWORD,
        COOKIE_SECURE=False,
    ).assert_startable()  # `make demo` must keep working


def test_example_jwt_secret_is_refused() -> None:
    assert "JWT_SECRET" in refusal(JWT_SECRET=EXAMPLE_JWT_SECRET)


@pytest.mark.parametrize("secret", ["x", "short-secret", "a" * (MIN_JWT_SECRET_CHARS - 1)])
def test_short_jwt_secret_is_refused(secret: str) -> None:
    message = refusal(JWT_SECRET=secret)
    assert "JWT_SECRET" in message and str(MIN_JWT_SECRET_CHARS) in message


def test_jwt_secret_of_exactly_the_minimum_length_is_accepted() -> None:
    settings(JWT_SECRET="a" * MIN_JWT_SECRET_CHARS).assert_startable()


@pytest.mark.parametrize(
    ("alias", "example"),
    [
        ("DEMO_ANALYST_PASSWORD", EXAMPLE_ANALYST_PASSWORD),
        ("DEMO_APPROVER_PASSWORD", EXAMPLE_APPROVER_PASSWORD),
        ("DEMO_JUDGE_PASSWORD", EXAMPLE_JUDGE_PASSWORD),
    ],
)
def test_each_default_demo_password_is_refused_and_named(alias: str, example: str) -> None:
    message = refusal(**{alias: example})
    assert alias in message
    assert example not in message  # the refusal names the variable, never prints the credential


def test_insecure_cookie_is_refused() -> None:
    assert "COOKIE_SECURE" in refusal(COOKIE_SECURE=False)


def test_every_offending_variable_is_named_at_once() -> None:
    message = refusal(
        JWT_SECRET="tiny",
        DEMO_ANALYST_PASSWORD=EXAMPLE_ANALYST_PASSWORD,
        DEMO_APPROVER_PASSWORD=EXAMPLE_APPROVER_PASSWORD,
        DEMO_JUDGE_PASSWORD=EXAMPLE_JUDGE_PASSWORD,
        COOKIE_SECURE=False,
    )
    for alias in (
        "JWT_SECRET",
        "DEMO_ANALYST_PASSWORD",
        "DEMO_APPROVER_PASSWORD",
        "DEMO_JUDGE_PASSWORD",
        "COOKIE_SECURE",
    ):
        assert alias in message, alias
    assert "ATHAR_DEV=true" in message  # tell the operator how to run the demo instead


def test_create_app_refuses_to_build_with_demo_credentials() -> None:
    from athar.api.app import create_app

    with pytest.raises(RuntimeError, match="DEMO_APPROVER_PASSWORD"):
        create_app(settings(DEMO_APPROVER_PASSWORD=EXAMPLE_APPROVER_PASSWORD, ATHAR_API_MOCK=True))
