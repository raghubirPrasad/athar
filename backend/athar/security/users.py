"""Demo users (SPEC §15.1): seeded from env, argon2id hashes, deterministic ids.

`seed_users` is idempotent: a second run changes nothing unless a password or role changed.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from athar.config import Settings
from athar.db.models import User
from athar.security.auth import AuthUser, Role, hash_password, verify_password

DEMO_EMAIL_DOMAIN = "athar.local"  # reserved mDNS TLD (RFC 6762), never routable


@dataclass(frozen=True)
class StoredUser:
    user_id: str
    email: str
    role: Role
    password_hash: str


@dataclass(frozen=True)
class DemoUser:
    user_id: str
    email: str
    role: Role
    password: str


def demo_users(settings: Settings) -> tuple[DemoUser, ...]:
    return (
        DemoUser("usr-analyst", f"analyst@{DEMO_EMAIL_DOMAIN}", "analyst", settings.demo_analyst_password),
        DemoUser(
            "usr-approver", f"approver@{DEMO_EMAIL_DOMAIN}", "approver", settings.demo_approver_password
        ),
        DemoUser("usr-judge", f"judge@{DEMO_EMAIL_DOMAIN}", "viewer", settings.demo_judge_password),
    )


class UserStore(Protocol):
    def find_by_email(self, email: str) -> StoredUser | None: ...


class InMemoryUserStore:
    """Mock-mode store: the three demo users, hashed at construction."""

    def __init__(self, settings: Settings) -> None:
        self._users = {
            u.email: StoredUser(u.user_id, u.email, u.role, hash_password(u.password))
            for u in demo_users(settings)
        }

    def find_by_email(self, email: str) -> StoredUser | None:
        return self._users.get(email.strip().lower())


class DbUserStore:
    def __init__(self, session: Session) -> None:
        self._session = session

    def find_by_email(self, email: str) -> StoredUser | None:
        row = self._session.scalar(select(User).where(User.email == email.strip().lower()))
        if row is None or row.role not in ("viewer", "analyst", "approver"):
            return None
        return StoredUser(row.user_id, row.email, row.role, row.password_hash)  # type: ignore[arg-type]


def authenticate(store: UserStore, email: str, password: str) -> AuthUser | None:
    user = store.find_by_email(email)
    if user is None:
        # Burn comparable time so a missing account is not distinguishable by latency.
        verify_password(_DUMMY_HASH, password)
        return None
    if not verify_password(user.password_hash, password):
        return None
    return AuthUser(user_id=user.user_id, email=user.email, role=user.role)


def seed_users(session: Session, settings: Settings) -> int:
    """Upsert the demo users. Returns how many rows were inserted or updated (0 on a clean second run)."""
    changed = 0
    for demo in demo_users(settings):
        row = session.get(User, demo.user_id)
        if row is None:
            session.add(
                User(
                    user_id=demo.user_id,
                    email=demo.email,
                    role=demo.role,
                    password_hash=hash_password(demo.password),
                    created_at=datetime.now(UTC),
                )
            )
            changed += 1
            continue
        dirty = False
        if row.email != demo.email or row.role != demo.role:
            row.email, row.role = demo.email, demo.role
            dirty = True
        if not verify_password(row.password_hash, demo.password):
            row.password_hash = hash_password(demo.password)
            dirty = True
        if dirty:
            changed += 1
    session.commit()
    return changed


_DUMMY_HASH = hash_password("athar-dummy-timing-hash")
