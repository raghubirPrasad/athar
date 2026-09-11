"""LLM response cache (SPEC §11.2).

`key = sha256(prompt_version|model|input_hash)`, `input_hash = sha256(canonical_json(payload))`.
A cache hit means no network call; the demo runs warm. `DbCacheStore` is the only
side-effectful piece (operational table `llm_cache`, so `datetime.now(UTC)` is allowed).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from sqlalchemy.orm import Session

from athar.db.models import LlmCache
from athar.hashing import canonical_json, sha256_hex


@dataclass(frozen=True)
class CacheEntry:
    provider: str
    model: str
    prompt_version: str
    input_hash: str
    output: dict[str, Any]


class CacheStore(Protocol):
    def get(self, key: str) -> CacheEntry | None: ...

    def put(self, key: str, entry: CacheEntry) -> None: ...


def input_hash(user_payload: dict[str, Any]) -> str:
    return sha256_hex(canonical_json(user_payload))


def cache_key(prompt_version: str, model: str, payload_hash: str) -> str:
    return sha256_hex(f"{prompt_version}|{model}|{payload_hash}".encode())


class InMemoryCacheStore:
    """Dict-backed store for tests and one-off CLI runs."""

    def __init__(self) -> None:
        self._entries: dict[str, CacheEntry] = {}

    def get(self, key: str) -> CacheEntry | None:
        return self._entries.get(key)

    def put(self, key: str, entry: CacheEntry) -> None:
        self._entries[key] = entry

    def __len__(self) -> int:
        return len(self._entries)


class DbCacheStore:
    """Store over `llm_cache`. Commits each put when `autocommit` (default) so a
    long agent run leaves warm entries behind even if a later step fails."""

    def __init__(self, session: Session, *, autocommit: bool = True) -> None:
        self._session = session
        self._autocommit = autocommit

    def get(self, key: str) -> CacheEntry | None:
        row = self._session.get(LlmCache, key)
        if row is None:
            return None
        return CacheEntry(
            provider=row.provider,
            model=row.model,
            prompt_version=row.prompt_version,
            input_hash=row.input_hash,
            output=dict(row.output or {}),
        )

    def put(self, key: str, entry: CacheEntry) -> None:
        self._session.merge(
            LlmCache(
                key=key,
                provider=entry.provider,
                model=entry.model,
                prompt_version=entry.prompt_version,
                input_hash=entry.input_hash,
                output=entry.output,
                created_at=datetime.now(UTC),
            )
        )
        if self._autocommit:
            self._session.commit()
        else:
            self._session.flush()
