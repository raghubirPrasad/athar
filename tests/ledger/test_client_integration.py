"""LedgerClient against Anvil and ensure_deployed against Postgres (SPEC §12.5)."""

from __future__ import annotations

import pytest
from athar.config import get_settings
from athar.db.models import LedgerMeta
from athar.ledger.client import LedgerClient, UnknownScanIndex, ensure_deployed
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from ._anvil import fresh_client, process_key


@pytest.mark.integration
def test_deploy_fresh_contract_and_read_back(rpc_url: str) -> None:
    client = fresh_client(rpc_url)
    assert client.chain_id == 31337
    assert client.contract_address and client.has_code(client.contract_address)
    assert client.commit_count() == 0
    assert client.has_code("0x0000000000000000000000000000000000000001") is False
    with pytest.raises(UnknownScanIndex):
        client.get_commit(0)


@pytest.mark.integration
def test_ensure_deployed_persists_meta_and_second_run_reuses(rpc_url: str, db_url: str) -> None:
    engine = create_engine(db_url, future=True)
    with Session(engine) as s:
        saved = s.get(LedgerMeta, 1)
        backup = (
            None
            if saved is None
            else dict(
                contract_address=saved.contract_address,
                chain_id=saved.chain_id,
                deployed_block=saved.deployed_block,
                writer_address=saved.writer_address,
            )
        )
        if saved is not None:
            s.delete(saved)
        s.commit()
    settings = get_settings().model_copy(update={"ledger_contract_address": ""})
    try:
        client1 = LedgerClient(rpc_url, process_key(rpc_url))
        with Session(engine) as s:
            meta1 = ensure_deployed(client1, s, settings)
        assert meta1.id == 1 and meta1.chain_id == 31337
        assert meta1.writer_address == client1.writer_address
        assert client1.contract_address == meta1.contract_address and client1.has_code(meta1.contract_address)

        client2 = LedgerClient(rpc_url, process_key(rpc_url))  # second run: nothing configured, row exists
        with Session(engine) as s:
            meta2 = ensure_deployed(client2, s, settings)
        assert meta2.contract_address == meta1.contract_address
        assert meta2.deployed_block == meta1.deployed_block
        assert client2.contract_address == meta1.contract_address

        other = LedgerClient(rpc_url, process_key(rpc_url)).deploy()  # configured address with code wins
        configured = settings.model_copy(update={"ledger_contract_address": other.address})
        client3 = LedgerClient(rpc_url, process_key(rpc_url))
        with Session(engine) as s:
            meta3 = ensure_deployed(client3, s, configured)
        assert meta3.contract_address == other.address == client3.contract_address

        dead = settings.model_copy(
            update={"ledger_contract_address": "0x00000000000000000000000000000000000000AA"}
        )
        client4 = LedgerClient(rpc_url, process_key(rpc_url))  # configured address without code -> the row
        with Session(engine) as s:
            meta4 = ensure_deployed(client4, s, dead)
        assert meta4.contract_address == other.address
        with Session(engine) as s:
            assert s.get(LedgerMeta, 1).contract_address == other.address

        garbage = settings.model_copy(update={"ledger_contract_address": "# empty = deploy on first start"})
        client5 = LedgerClient(rpc_url, process_key(rpc_url))  # malformed config -> ignored, row reused
        with Session(engine) as s:
            meta5 = ensure_deployed(client5, s, garbage)
        assert meta5.contract_address == other.address == client5.contract_address
    finally:
        with Session(engine) as s:
            row = s.get(LedgerMeta, 1)
            if row is not None:
                s.delete(row)
            if backup is not None:
                s.add(LedgerMeta(id=1, **backup))
            s.commit()
        engine.dispose()
