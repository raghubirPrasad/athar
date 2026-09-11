"""Mock-mode only: endpoints that prove the error handling (never registered otherwise)."""

from __future__ import annotations

from fastapi import APIRouter

from athar.api.schemas import HealthOut

router = APIRouter(prefix="/debug", tags=["debug"])


@router.get("/raise", response_model=HealthOut, include_in_schema=False)
def debug_raise() -> HealthOut:
    """Raises on purpose so tests can assert the 500 is problem+json with no trace."""
    raise RuntimeError("deliberate failure for the catch-all handler test /internal/path/secret.py")
