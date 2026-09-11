"""Demo users against Postgres (SPEC §15.1): idempotent seeding and a real login round trip.

Needs DATABASE_URL reachable with the schema migrated; otherwise the `db_url` fixture skips.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "unit"))
from _api_support import CSRF, assert_problem, make_app
from athar.db.models import User
from athar.security.auth import COOKIE_NAME
from athar.security.users import DbUserStore, authenticate, demo_users, seed_users
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, select
from sqlalchemy.orm import Session

pytestmark = pytest.mark.integration

DEMO_IDS = ("usr-analyst", "usr-approver", "usr-judge")


@pytest.fixture(scope="module")
def app(db_url: str):
    """Real (non-mock) app; its user store opens sessions on the process-wide DATABASE_URL == db_url."""
    return make_app(ATHAR_API_MOCK=False)


@pytest.fixture(scope="module")
def session(db_url: str):
    engine = create_engine(db_url, future=True)
    if not inspect(engine).has_table("users"):
        pytest.fail("users table missing: the schema must be migrated (`uv run alembic upgrade head`)")
    with Session(engine) as s:
        yield s
    engine.dispose()


def _demo_rows(session: Session) -> list[User]:
    return list(session.scalars(select(User).where(User.user_id.in_(DEMO_IDS)).order_by(User.user_id)))


def test_seed_users_twice_is_idempotent(session, app) -> None:
    settings = app.state.settings
    seed_users(session, settings)  # inserts, or repairs rows left by an earlier run with other passwords
    first = {u.user_id: u.password_hash for u in _demo_rows(session)}
    assert set(first) == set(DEMO_IDS)
    assert seed_users(session, settings) == 0  # second run: nothing to change
    rows = _demo_rows(session)
    assert [(u.user_id, u.email, u.role) for u in rows] == [
        ("usr-analyst", "analyst@athar.local", "analyst"),
        ("usr-approver", "approver@athar.local", "approver"),
        ("usr-judge", "judge@athar.local", "viewer"),
    ]
    assert {u.user_id: u.password_hash for u in rows} == first  # hashes untouched
    assert all(u.password_hash.startswith("$argon2id$") for u in rows)


def test_db_store_authenticates_seeded_users(session, app) -> None:
    settings = app.state.settings
    seed_users(session, settings)
    store = DbUserStore(session)
    for demo in demo_users(settings):
        user = authenticate(store, demo.email, demo.password)
        assert user is not None and (user.user_id, user.role) == (demo.user_id, demo.role)
        assert authenticate(store, demo.email, demo.password + "x") is None


def test_login_against_database_users(session, app) -> None:
    settings = app.state.settings
    seed_users(session, settings)
    client = TestClient(app)  # no lifespan on purpose: seeding is exercised explicitly above
    approver = next(u for u in demo_users(settings) if u.role == "approver")
    ok = client.post(
        "/api/v1/auth/login", json={"email": approver.email, "password": approver.password}, headers=CSRF
    )
    assert ok.status_code == 200, ok.text
    assert ok.json() == {"user_id": "usr-approver", "email": approver.email, "role": "approver"}
    assert COOKIE_NAME in client.cookies and "httponly" in ok.headers["set-cookie"].lower()
    me = client.get("/api/v1/auth/me")
    assert me.status_code == 200 and me.json()["role"] == "approver"
    bad = client.post("/api/v1/auth/login", json={"email": approver.email, "password": "wrong"}, headers=CSRF)
    assert_problem(bad, 401, "auth.invalid_credentials")
