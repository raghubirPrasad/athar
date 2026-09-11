"""Routers, one per resource (SPEC §13). `all_routers()` is the mount order under /api/v1."""

from __future__ import annotations

from fastapi import APIRouter

from athar.api.routers import (
    agent,
    auth,
    departments,
    estate,
    evaluation,
    export,
    findings,
    health,
    identities,
    ingest,
    ledger,
    remediation,
    rules,
    scans,
    settings,
    simulate,
    timeline,
)
from athar.api.routers.debug import router as debug_router


def all_routers() -> list[APIRouter]:
    return [
        health.router,
        auth.router,
        estate.router,
        identities.router,
        findings.router,
        rules.router,
        departments.router,
        timeline.router,
        scans.run_router,
        scans.router,
        ingest.router,
        simulate.router,
        agent.router,
        remediation.router,
        ledger.router,
        evaluation.router,
        export.router,
        settings.router,
    ]


__all__ = ["all_routers", "debug_router"]
