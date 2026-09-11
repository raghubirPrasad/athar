"""Exports (SPEC §16). Same filters as `/findings`; cells escaped against formula injection."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Response
from fastapi.concurrency import run_in_threadpool

from athar.api.routers.common import READ_LIST, FiltersDep, RepoDep
from athar.security.rbac import require_viewer

router = APIRouter(prefix="/export", tags=["export"], dependencies=[Depends(require_viewer)])


def _file_responses(media_type: str, description: str) -> dict[int | str, dict[str, Any]]:
    return {200: {"content": {media_type: {}}, "description": description}, **READ_LIST}


def _attachment(content: bytes, media_type: str, filename: str) -> Response:
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get(
    "/findings.csv",
    response_class=Response,
    responses=_file_responses("text/csv", "CSV with the SPEC §16 columns"),
)
async def export_findings_csv(repo: RepoDep, filters: FiltersDep) -> Response:
    """CSV report; verify offline with `athar verify --csv` and the JSON sidecar."""
    data = await run_in_threadpool(repo.export_csv, filters)
    return _attachment(data, "text/csv; charset=utf-8", "athar-findings.csv")


@router.get(
    "/findings.json",
    response_class=Response,
    responses=_file_responses("application/json", "Rows plus per-finding instance JSON and Merkle proof"),
)
async def export_findings_json(repo: RepoDep, filters: FiltersDep) -> Response:
    """JSON sidecar: each row's committed instance, leaf and inclusion proof."""
    data = await run_in_threadpool(repo.export_json, filters)
    return _attachment(data, "application/json", "athar-findings.json")


@router.get(
    "/findings.pdf",
    response_class=Response,
    responses=_file_responses("application/pdf", "Board-ready PDF with Merkle root and tx in the footer"),
)
async def export_findings_pdf(repo: RepoDep, filters: FiltersDep) -> Response:
    """PDF report (cover, executive summary, department rollup, top findings, rule appendix)."""
    data = await run_in_threadpool(repo.export_pdf, filters)
    return _attachment(data, "application/pdf", "athar-findings.pdf")
