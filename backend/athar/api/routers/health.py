"""Liveness and dependency reachability (SPEC §13 `/health`, `/health/deps`).

Neither route ever 503s because of a missing service, and neither reveals a URL or key: the LLM
row is derived from settings only (provider, model, key present). `/health` is unauthenticated
because the compose healthcheck polls it; `/health/deps` names the LLM provider and model, says
whether a key is configured, and reports the chain id, so it requires a viewer session.
"""

from __future__ import annotations

from typing import Annotated

import httpx
from fastapi import APIRouter, Depends
from fastapi.concurrency import run_in_threadpool
from sqlalchemy import text

from athar import __version__
from athar.api.deps import Repo, optional_repo
from athar.api.problem import problem_responses
from athar.api.routers.common import SettingsDep
from athar.api.schemas import DepStatus, HealthDeps, HealthOut
from athar.config import APP_NAME, Settings
from athar.log import get_logger
from athar.security.rbac import require_viewer

router = APIRouter(prefix="/health", tags=["health"])
log = get_logger("athar.api.health")

RPC_TIMEOUT_SECONDS = 2.0
OptionalRepo = Annotated[Repo | None, Depends(optional_repo)]


@router.get("", response_model=HealthOut)
def health(settings: SettingsDep, repo: OptionalRepo) -> HealthOut:
    """Liveness: app, version, current simulated month (null until the first ingest)."""
    month: int | None = None
    if repo is not None:
        try:
            month = repo.current_month()
        except Exception as exc:  # health must answer even when the DB is down
            log.warning("health: current_month failed", extra={"exc_type": type(exc).__name__})
        finally:
            close = getattr(repo, "close", None)
            if callable(close):
                close()
    return HealthOut(app=APP_NAME, version=__version__, month=month, mock=settings.api_mock)


@router.get(
    "/deps",
    response_model=HealthDeps,
    responses=problem_responses(401, 403),
    dependencies=[Depends(require_viewer)],
)
async def health_deps(settings: SettingsDep, repo: OptionalRepo) -> HealthDeps:
    """Reachability of Postgres (`SELECT 1`), Anvil (`eth_chainId`) and the LLM configuration.

    Viewer role: this is infrastructure detail, not liveness (SPEC §13).
    """
    if settings.api_mock and repo is not None:
        return repo.health_deps()
    return await run_in_threadpool(probe_deps, settings)


def probe_deps(settings: Settings) -> HealthDeps:
    return HealthDeps(db=probe_db(settings), anvil=probe_anvil(settings), llm=llm_status(settings))


def probe_db(settings: Settings) -> DepStatus:
    from athar.db.session import get_engine  # lazy: no engine in mock mode

    try:
        with get_engine().connect() as conn:
            conn.execute(text("SELECT 1"))
        return DepStatus(ok=True, detail="postgres reachable")
    except Exception as exc:
        log.warning("health: db probe failed", extra={"exc_type": type(exc).__name__})
        return DepStatus(ok=False, detail=f"database unreachable ({type(exc).__name__})")


def probe_anvil(settings: Settings) -> DepStatus:
    if not settings.ledger_enabled:
        return DepStatus(ok=True, detail="ledger disabled by configuration")
    payload = {"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}
    try:
        with httpx.Client(timeout=RPC_TIMEOUT_SECONDS) as client:
            response = client.post(settings.ledger_rpc_url, json=payload)
        response.raise_for_status()
        chain_hex = response.json().get("result")
        if not isinstance(chain_hex, str):
            return DepStatus(ok=False, detail="rpc answered without a chain id")
        return DepStatus(ok=True, detail=f"chain id {int(chain_hex, 16)}")
    except (httpx.HTTPError, ValueError) as exc:
        log.warning("health: anvil probe failed", extra={"exc_type": type(exc).__name__})
        return DepStatus(ok=False, detail=f"rpc unreachable ({type(exc).__name__})")


def llm_status(settings: Settings) -> DepStatus:
    """Configuration only — no network call, no URL, no key material."""
    provider = settings.llm_provider
    if provider == "none":
        return DepStatus(ok=True, detail="templates only (LLM_PROVIDER=none)")
    if provider == "gemini":
        present = bool(settings.effective_gemini_key)
        detail = f"gemini · {settings.llm_model} · key {'present' if present else 'missing'}"
        return DepStatus(ok=present, detail=detail)
    return DepStatus(ok=True, detail=f"ollama · {settings.ollama_model} · configured (not probed)")
