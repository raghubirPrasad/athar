"""Multipart IAM export upload (SPEC §13 `/ingest/upload`, §15.2 limits).

The body-size middleware bounds the whole request; this handler additionally caps each file
at `MAX_UPLOAD_BYTES` and rejects empty uploads. Schema validation of the content is the
normaliser's job (provider-specific pydantic models); a malformed file is a 4xx problem or a
warning in the result, never a crash.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, File, Form, UploadFile
from fastapi.concurrency import run_in_threadpool

from athar.api.deps import UploadedFile
from athar.api.problem import InvalidInputError, PayloadTooLargeError, problem_responses
from athar.api.routers.common import AnalystDep, RepoDep, SettingsDep
from athar.api.schemas import UploadProvider, UploadResult

router = APIRouter(prefix="/ingest", tags=["ingest"])

MAX_FILES = 12


@router.post(
    "/upload", response_model=UploadResult, responses=problem_responses(401, 403, 413, 415, 422, 503)
)
async def upload(
    user: AnalystDep,
    repo: RepoDep,
    settings: SettingsDep,
    provider: Annotated[UploadProvider, Form()],
    month: Annotated[int, Form(ge=1, le=600)],
    files: Annotated[list[UploadFile], File(description="One or more provider export files")],
) -> UploadResult:
    """Analyst: upload one month of native exports for a provider (`aws` | `azure` | `gcp` | `hr`)."""
    if not files:
        raise InvalidInputError("upload.no_files", "At least one file is required")
    if len(files) > MAX_FILES:
        raise InvalidInputError("upload.too_many_files", f"At most {MAX_FILES} files per upload")
    uploaded: list[UploadedFile] = []
    for f in files:
        content = await f.read()
        if len(content) > settings.max_upload_bytes:
            raise PayloadTooLargeError(settings.max_upload_bytes)
        uploaded.append(UploadedFile(filename=_safe_name(f.filename), content=content))
    return await run_in_threadpool(repo.upload, provider, month, uploaded, user)


def _safe_name(filename: str | None) -> str:
    """Basename only, printable ASCII, bounded — the name is echoed in results and logs."""
    name = (filename or "upload").replace("\\", "/").rsplit("/", 1)[-1]
    cleaned = "".join(ch for ch in name if 32 <= ord(ch) < 127)[:120]
    return cleaned or "upload"
