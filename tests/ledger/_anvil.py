"""Shared helpers for the ledger integration tests (Anvil). Not a test module.

Every test process signs with its own throw-away key, funded through Anvil's `anvil_setBalance`
cheat, so concurrent pytest runs (other lanes run the full suite against the same node) never
race each other for a nonce. The account and the key exist only for this process and hold
nothing but Anvil play-money.
"""

from __future__ import annotations

import secrets
from functools import lru_cache

import pytest
from athar.ledger.client import LedgerClient, LedgerError
from eth_account import Account
from web3 import Web3

# Anvil dev account #7 — DEV ONLY, PUBLICLY KNOWN KEY (same mnemonic as account #0 in config.py).
# Fallback when the node is not Anvil (no `anvil_setBalance`) and cannot fund a fresh account.
TEST_KEY = "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356"

_FUNDING_WEI = 10**21


@lru_cache(maxsize=1)
def process_key(rpc_url: str) -> str:
    """One funded signing key per test process (see module docstring)."""
    w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 5}))
    key = "0x" + secrets.token_hex(32)
    address = Account.from_key(key).address
    response = w3.provider.make_request("anvil_setBalance", [address, hex(_FUNDING_WEI)])  # type: ignore[arg-type]
    if "error" not in response and w3.eth.get_balance(address) > 0:
        return key
    return TEST_KEY


def fresh_client(rpc_url: str) -> LedgerClient:
    """A client on a freshly deployed contract, or skip when no funded account is available."""
    client = LedgerClient(rpc_url, process_key(rpc_url))
    w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 5}))
    if w3.eth.get_balance(client.writer_address) == 0:
        pytest.skip("no funded Anvil account; start Anvil with the default mnemonic")
    last: LedgerError | None = None
    for _ in range(3):  # the shared fallback key can still race another process; deploy is cheap
        try:
            client.deploy()
            return client
        except LedgerError as exc:
            last = exc
    raise AssertionError(f"could not deploy a fresh contract: {last}")
