"""Shared pytest configuration. Integration tests need DATABASE_URL / LEDGER_RPC_URL reachable.

Do NOT add lane-specific fixtures here (concurrent edits); put them next to your tests.
"""

from __future__ import annotations

import os
import socket
from urllib.parse import urlparse

import pytest


def _reachable(url: str) -> bool:
    try:
        p = urlparse(url if "://" in url else f"tcp://{url}")
        host, port = p.hostname or "localhost", p.port or 80
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


def pytest_configure(config: pytest.Config) -> None:
    os.environ.setdefault("ATHAR_DEV", "true")
    os.environ.setdefault("LLM_PROVIDER", "none")
    # Register markers here too: when pytest is invoked with explicit ../tests paths the rootdir
    # is tests/ and backend/pyproject.toml's [tool.pytest.ini_options] is not read.
    config.addinivalue_line(
        "markers", "integration: needs Postgres (DATABASE_URL) and/or Anvil (LEDGER_RPC_URL)"
    )
    config.addinivalue_line("markers", "slow: long-running")


#: Set by `make ci` (and anywhere else a green run must mean the integration tests actually ran).
#: Without it a missing Postgres or Anvil skips ~50 tests and the suite still reports success, so
#: `make ci` could pass on a machine where nothing had ever touched a database. With it, an
#: unreachable dependency fails instead of skipping.
REQUIRE_INTEGRATION_ENV = "ATHAR_REQUIRE_INTEGRATION"


def _unavailable(what: str, hint: str) -> None:
    """Skip, or fail when the caller has said integration coverage is not optional."""
    message = f"{what} not reachable; start with `{hint}`"
    if os.environ.get(REQUIRE_INTEGRATION_ENV, "").strip().lower() in ("1", "true", "yes"):
        pytest.fail(f"{message} ({REQUIRE_INTEGRATION_ENV} is set, so this is a failure)")
    pytest.skip(message)


@pytest.fixture(scope="session")
def db_url() -> str:
    from athar.config import get_settings

    url = get_settings().database_url
    if not _reachable(url.replace("postgresql+psycopg://", "tcp://").split("@")[-1]):
        _unavailable("Postgres", "docker compose up -d db")
    return url


@pytest.fixture(scope="session")
def rpc_url() -> str:
    from athar.config import get_settings

    url = get_settings().ledger_rpc_url
    if not _reachable(url):
        _unavailable("Anvil", "docker compose up -d anvil")
    return url
