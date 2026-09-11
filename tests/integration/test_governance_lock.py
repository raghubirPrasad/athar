"""The continuous-governance advisory lock is released when the tick ends (SPEC §11.6).

A PostgreSQL session-level advisory lock belongs to the connection that took it, and returning a
connection to SQLAlchemy's pool does not release one. The tick commits repeatedly, and every commit
hands the session's connection back to the pool, so taking and releasing the lock *through the
session* could unlock a different connection than the one holding it. Postgres only warns about
that, so the tick would look healthy while leaving the lock held on an idle pooled connection —
and every later tick would find it taken and skip. Continuous governance would run exactly once.

That is the whole failure mode, and it only shows up against a real Postgres with a real pool, so
these are integration tests. They use their own schema and never touch the demo database's rows.
"""

from __future__ import annotations

import os
from typing import Any

import pytest
from athar.db import models as m
from athar.services.wiring import SCHEDULER_LOCK_KEY, governance_lock
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

pytestmark = pytest.mark.integration

SCHEMA = f"athar_test_lock_{os.getpid()}"


@pytest.fixture(scope="module")
def engine(db_url: str) -> Any:
    admin = create_engine(db_url, future=True)
    with admin.begin() as conn:
        conn.execute(text(f"DROP SCHEMA IF EXISTS {SCHEMA} CASCADE"))
        conn.execute(text(f"CREATE SCHEMA {SCHEMA}"))
    admin.dispose()
    scoped = create_engine(db_url, future=True, connect_args={"options": f"-csearch_path={SCHEMA}"})
    m.Base.metadata.create_all(scoped)
    yield scoped
    scoped.dispose()
    admin = create_engine(db_url, future=True)
    with admin.begin() as conn:
        conn.execute(text(f"DROP SCHEMA IF EXISTS {SCHEMA} CASCADE"))
    admin.dispose()


def _locks_held(engine: Any) -> int:
    """How many backends hold this advisory lock right now, across the whole database."""
    with engine.connect() as conn:
        return int(
            conn.scalar(
                text(
                    "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' "
                    "AND ((classid::bigint << 32) | objid::bigint) = :key AND granted"
                ),
                {"key": SCHEDULER_LOCK_KEY},
            )
            or 0
        )


def test_the_lock_is_taken_and_then_released(engine: Any) -> None:
    session = Session(engine)
    try:
        assert _locks_held(engine) == 0, "a previous test left the lock held"
        with governance_lock(session) as held:
            assert held is True
            assert _locks_held(engine) == 1
        assert _locks_held(engine) == 0, "the lock outlived the tick"
    finally:
        session.close()


def test_it_survives_the_commits_the_tick_performs(engine: Any) -> None:
    """The real shape of a tick: the session commits several times while the lock is held.

    Each commit returns the session's connection to the pool. If the lock lived on that connection
    it would be unlocked on whichever one came back later, and this assertion would fail.
    """
    session = Session(engine)
    try:
        with governance_lock(session) as held:
            assert held is True
            for _ in range(5):
                session.execute(text("SELECT 1"))
                session.commit()  # hands this session's connection back to the pool
                assert _locks_held(engine) == 1, "the lock was lost part-way through the tick"
        assert _locks_held(engine) == 0
    finally:
        session.close()


def test_a_second_tick_can_take_it_again(engine: Any) -> None:
    """The consequence that matters: governance must not stop after one run."""
    for _ in range(3):
        session = Session(engine)
        try:
            with governance_lock(session) as held:
                assert held is True, "a leaked lock would make every tick after the first skip"
        finally:
            session.close()
    assert _locks_held(engine) == 0


def test_a_second_holder_is_refused_while_the_first_holds_it(engine: Any) -> None:
    """One holder across replicas: that is what the lock is for."""
    first, second = Session(engine), Session(engine)
    try:
        with governance_lock(first) as held_first:
            assert held_first is True
            with governance_lock(second) as held_second:
                assert held_second is False, "two workers would scan the same month twice"
            assert _locks_held(engine) == 1, "the refused attempt must not release the holder's lock"
        assert _locks_held(engine) == 0
    finally:
        first.close()
        second.close()


def test_the_body_raising_still_releases_it(engine: Any) -> None:
    session = Session(engine)
    try:
        with pytest.raises(RuntimeError), governance_lock(session) as held:
            assert held is True
            raise RuntimeError("the tick failed")
        assert _locks_held(engine) == 0, "a failed tick must not wedge the scheduler"
    finally:
        session.close()
