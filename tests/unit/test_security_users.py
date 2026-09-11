"""Demo users: seeding, stores and authentication (SPEC §15.1). Postgres path is covered by
tests/integration/test_api_auth_db.py; here an in-memory SQLite table proves idempotency."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from _api_support import make_settings
from athar.db.models import User
from athar.security.users import (
    DEMO_EMAIL_DOMAIN,
    DbUserStore,
    InMemoryUserStore,
    authenticate,
    demo_users,
    seed_users,
)
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session


@pytest.fixture(scope="module")
def settings():
    return make_settings()


def test_demo_users_cover_the_three_roles_on_a_reserved_domain(settings) -> None:
    users = demo_users(settings)
    assert [u.user_id for u in users] == ["usr-analyst", "usr-approver", "usr-judge"]
    assert [u.role for u in users] == ["analyst", "approver", "viewer"]
    assert DEMO_EMAIL_DOMAIN == "athar.local"
    assert all(u.email.endswith("@athar.local") for u in users)
    assert {u.password for u in users} == {
        settings.demo_analyst_password,
        settings.demo_approver_password,
        settings.demo_judge_password,
    }


def test_in_memory_store_authenticates_demo_accounts_case_insensitively(settings) -> None:
    store = InMemoryUserStore(settings)
    user = authenticate(store, "  Analyst@ATHAR.local ", settings.demo_analyst_password)
    assert user is not None and user.user_id == "usr-analyst" and user.role == "analyst"


def test_authenticate_rejects_wrong_password_and_unknown_email(settings) -> None:
    store = InMemoryUserStore(settings)
    assert authenticate(store, "analyst@athar.local", "nope") is None
    assert authenticate(store, "ghost@athar.local", settings.demo_analyst_password) is None


def _sqlite_session() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    User.__table__.create(engine)
    return Session(engine)


def test_seed_users_is_idempotent(settings) -> None:
    with _sqlite_session() as session:
        assert seed_users(session, settings) == 3
        first = {u.user_id: u.password_hash for u in session.scalars(select(User))}
        assert seed_users(session, settings) == 0
        rows = session.scalars(select(User).order_by(User.user_id)).all()
        assert [(u.user_id, u.email, u.role) for u in rows] == [
            ("usr-analyst", "analyst@athar.local", "analyst"),
            ("usr-approver", "approver@athar.local", "approver"),
            ("usr-judge", "judge@athar.local", "viewer"),
        ]
        assert {u.user_id: u.password_hash for u in rows} == first  # hashes untouched on a clean rerun


def test_seed_users_rehashes_only_when_the_password_changed(settings) -> None:
    with _sqlite_session() as session:
        seed_users(session, settings)
        changed = make_settings(DEMO_JUDGE_PASSWORD="new-judge-pass")
        assert seed_users(session, changed) == 1
        store = DbUserStore(session)
        assert authenticate(store, "judge@athar.local", "new-judge-pass") is not None
        assert authenticate(store, "judge@athar.local", settings.demo_judge_password) is None
        assert authenticate(store, "analyst@athar.local", settings.demo_analyst_password) is not None


def test_db_store_ignores_rows_with_unknown_roles(settings) -> None:
    with _sqlite_session() as session:
        seed_users(session, settings)
        row = session.get(User, "usr-judge")
        assert row is not None
        row.role = "root"
        session.commit()
        assert DbUserStore(session).find_by_email("judge@athar.local") is None
