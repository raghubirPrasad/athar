"""LedgerClient unit behaviour that needs no node (SPEC §12.4 failure handling)."""

from __future__ import annotations

import pytest
from athar.config import ANVIL_DEV_KEY_0
from athar.ledger import client as ledger_client
from athar.ledger.client import LedgerClient, LedgerNotDeployed, LedgerUnavailable

# A closed port: connection refused immediately, so the test is fast.
_DEAD_URL = "http://127.0.0.1:9"


def test_unreachable_node_raises_ledger_unavailable_without_leaking_url() -> None:
    c = LedgerClient(_DEAD_URL, ANVIL_DEV_KEY_0, timeout=1.0)
    with pytest.raises(LedgerUnavailable) as info:
        _ = c.chain_id
    assert "127.0.0.1" not in str(info.value) and ":9" not in str(info.value)
    assert not c.is_reachable()
    with pytest.raises(LedgerUnavailable):
        c.pending_nonce()


def test_writer_address_derives_from_key_without_network() -> None:
    c = LedgerClient(_DEAD_URL, ANVIL_DEV_KEY_0)
    assert c.writer_address == "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"  # Anvil dev account #0
    assert c.contract_address is None


def test_calls_before_deploy_raise_not_deployed() -> None:
    c = LedgerClient(_DEAD_URL, ANVIL_DEV_KEY_0)
    with pytest.raises(LedgerNotDeployed):
        c.commit_count()


def test_has_code_rejects_malformed_and_empty_addresses_without_network() -> None:
    c = LedgerClient(_DEAD_URL, ANVIL_DEV_KEY_0)
    assert c.has_code(None) is False
    assert c.has_code("") is False
    assert c.has_code("not-an-address") is False


@pytest.mark.parametrize(
    "configured",
    ["", "   ", "# empty = deploy on first API start", "0xdead", "not-an-address"],
)
def test_malformed_configured_address_is_ignored_not_fatal(configured: str) -> None:
    """`.env` parsing quirks or typos must not kill the process (CLAUDE.md non-negotiable 3)."""
    c = LedgerClient(_DEAD_URL, ANVIL_DEV_KEY_0, configured)
    assert c.contract_address is None
    c.contract_address = configured
    assert c.contract_address is None
    assert ledger_client.checksum_or_none(configured) is None


def test_configured_address_is_checksummed() -> None:
    lower = "0x5fbdb2315678afecb367f032d93f642f64180aa3"
    c = LedgerClient(_DEAD_URL, ANVIL_DEV_KEY_0, f"  {lower}  ")
    assert c.contract_address == "0x5FbDB2315678afecb367f032d93F642f64180aa3"
    assert ledger_client.checksum_or_none(lower) == c.contract_address


def test_artifact_error_selectors_cover_contract_errors() -> None:
    selectors = ledger_client._error_selectors(ledger_client.load_artifact()["abi"])
    assert {"InvalidProof", "UnknownScan", "InvalidDecision"} <= set(selectors.values())
    assert all(k.startswith("0x") and len(k) == 10 for k in selectors)
