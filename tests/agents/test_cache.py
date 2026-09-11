"""LLM cache (SPEC §11.2): key derivation, in-memory store, and the `llm_cache` table."""

from __future__ import annotations

import pytest
from athar.agents.cache import CacheEntry, DbCacheStore, InMemoryCacheStore, cache_key, input_hash
from athar.db.models import LlmCache
from athar.hashing import canonical_json, sha256_hex
from sqlalchemy import create_engine, delete
from sqlalchemy.orm import Session


def _entry(output: dict[str, object] | None = None) -> CacheEntry:
    return CacheEntry(
        provider="gemini",
        model="fake-gemini",
        prompt_version="inv-v1",
        input_hash=input_hash({"a": 1}),
        output=output or {"hypothesis": "h", "recommended_action": "revoke_grant"},
    )


def test_input_hash_is_sha256_of_canonical_json_and_order_independent() -> None:
    a = input_hash({"b": 2, "a": [1, {"y": 1, "x": 2}]})
    b = input_hash({"a": [1, {"x": 2, "y": 1}], "b": 2})
    assert a == b == sha256_hex(canonical_json({"a": [1, {"x": 2, "y": 1}], "b": 2}))


def test_cache_key_is_sha256_of_version_model_and_input_hash() -> None:
    h = input_hash({"a": 1})
    assert cache_key("inv-v1", "m", h) == sha256_hex(f"inv-v1|m|{h}".encode())
    assert cache_key("inv-v2", "m", h) != cache_key("inv-v1", "m", h)
    assert cache_key("inv-v1", "other", h) != cache_key("inv-v1", "m", h)


def test_in_memory_store_round_trips_and_overwrites() -> None:
    store = InMemoryCacheStore()
    assert store.get("k") is None
    store.put("k", _entry())
    assert store.get("k") == _entry()
    store.put("k", _entry({"hypothesis": "new"}))
    assert store.get("k") is not None
    assert store.get("k").output == {"hypothesis": "new"}  # type: ignore[union-attr]
    assert len(store) == 1


@pytest.mark.integration
def test_db_cache_store_round_trips_and_is_idempotent(db_url: str) -> None:
    engine = create_engine(db_url, future=True)
    key = cache_key("test-v1", "fake-model", input_hash({"lane": "e2", "case": "roundtrip"}))
    with Session(engine) as session:
        session.execute(delete(LlmCache).where(LlmCache.key == key))
        session.commit()
        store = DbCacheStore(session)
        assert store.get(key) is None
        store.put(key, _entry())
        store.put(key, _entry({"hypothesis": "second"}))  # merge on the natural key: no duplicate row
        got = store.get(key)
        assert got is not None
        assert got.output == {"hypothesis": "second"}
        assert got.provider == "gemini"
        assert got.prompt_version == "inv-v1"
    with Session(engine) as session:
        row = session.get(LlmCache, key)
        assert row is not None
        assert row.created_at is not None
        session.execute(delete(LlmCache).where(LlmCache.key == key))
        session.commit()
    engine.dispose()
