"""FastAPI dependencies and the `Repo` contract the data services must satisfy (SPEC §13).

Every router handler talks to a `Repo`. In mock mode (`ATHAR_API_MOCK=true`) that is the
in-process `MockRepo` (`athar.api.mock`); otherwise the integrator installs a factory on
`app.state.repo_factory` at startup and `get_repo` calls it once per request. Until that
factory exists, any data route answers 503 `services.not_wired` — the contract is usable
(and the OpenAPI document complete) before the services land.

Implementations may raise `athar.api.problem.ProblemException` subclasses for domain errors
(409 `plan.invalid_state`, 422 `sort.unknown_field`, …). Lookups return `None` for a missing
id; the router turns that into a 404 problem.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Protocol

from fastapi import Request

from athar.api.problem import UnavailableError
from athar.api.schemas import (
    AdvanceResult,
    ApplyResult,
    EstateSummary,
    EvalOut,
    ExceptionRequest,
    FindingOut,
    HalfLifeTable,
    HealthDeps,
    IdentityDetail,
    IdentityRow,
    InvestigationOut,
    LedgerDecisionOut,
    LedgerInfo,
    LedgerScanOut,
    LedgerVerifyOut,
    ListFilters,
    Page,
    RemediationPlanOut,
    ScanOut,
    SettingsOut,
    SettingsUpdate,
    SummaryOut,
    TimelineOut,
    UploadProvider,
    UploadResult,
)
from athar.config import Settings
from athar.security.auth import AuthUser
from athar.security.rbac import settings_for
from athar.security.users import DbUserStore, UserStore


@dataclass(frozen=True)
class UploadedFile:
    """One multipart file, fully read (bounded by the body-size middleware)."""

    filename: str
    content: bytes


class Repo(Protocol):
    """Read/write contract behind every `/api/v1` route. One instance per request."""

    # --- reads (viewer) -----------------------------------------------------
    def current_month(self) -> int | None: ...
    def estate_summary(self) -> EstateSummary: ...
    def list_identities(self, filters: ListFilters) -> Page[IdentityRow]: ...
    def identity_detail(self, identity_id: str) -> IdentityDetail | None: ...
    def list_findings(self, filters: ListFilters) -> Page[FindingOut]: ...
    def finding(self, finding_key: str) -> FindingOut | None: ...
    def halflife(self) -> HalfLifeTable: ...
    def timeline(self) -> TimelineOut: ...
    def list_scans(self, filters: ListFilters) -> Page[ScanOut]: ...
    def scan(self, scan_id: int) -> ScanOut | None: ...

    # --- runs (analyst) -----------------------------------------------------
    def run_scan(self, month: int | None, user: AuthUser) -> ScanOut: ...
    def upload(
        self, provider: UploadProvider, month: int, files: list[UploadedFile], user: AuthUser
    ) -> UploadResult: ...
    def advance(self, user: AuthUser) -> AdvanceResult: ...
    def investigate(self, finding_key: str, regenerate: bool, user: AuthUser) -> InvestigationOut | None: ...
    def plan(self, finding_key: str, regenerate: bool, user: AuthUser) -> RemediationPlanOut | None: ...
    def summary(self, regenerate: bool, user: AuthUser) -> SummaryOut: ...

    # --- decisions (approver; SoD and state checks happen in the router) ----
    def list_plans(self, filters: ListFilters) -> Page[RemediationPlanOut]: ...
    def get_plan(self, plan_id: str) -> RemediationPlanOut | None: ...
    def approve(self, plan_id: str, user: AuthUser) -> RemediationPlanOut: ...
    def reject(self, plan_id: str, user: AuthUser, reason: str) -> RemediationPlanOut: ...
    def apply(self, plan_id: str, user: AuthUser) -> ApplyResult: ...
    def grant_exception(
        self, finding_key: str, user: AuthUser, body: ExceptionRequest
    ) -> FindingOut | None: ...

    # --- ledger (viewer) ----------------------------------------------------
    def ledger_info(self) -> LedgerInfo: ...
    def ledger_scans(self, filters: ListFilters) -> Page[LedgerScanOut]: ...
    def ledger_verify(self, scan_id: int) -> LedgerVerifyOut | None: ...
    def ledger_decisions(self, filters: ListFilters) -> Page[LedgerDecisionOut]: ...

    # --- evaluation / exports (viewer) --------------------------------------
    def eval_result(self) -> EvalOut: ...
    def export_csv(self, filters: ListFilters) -> bytes: ...
    def export_json(self, filters: ListFilters) -> bytes: ...
    def export_pdf(self, filters: ListFilters) -> bytes: ...

    # --- settings / health --------------------------------------------------
    def get_settings(self) -> SettingsOut: ...
    def put_settings(self, body: SettingsUpdate, user: AuthUser) -> SettingsOut: ...
    def health_deps(self) -> HealthDeps: ...


RepoFactory = Callable[[], Repo]


def get_settings_dep(request: Request) -> Settings:
    return settings_for(request)


def optional_repo(request: Request) -> Repo | None:
    """The repo if one is available, else None (used by health, which must never 503)."""
    settings = settings_for(request)
    if settings.api_mock:
        repo: Repo = request.app.state.mock_repo
        return repo
    factory: RepoFactory | None = getattr(request.app.state, "repo_factory", None)
    return factory() if factory is not None else None


def get_repo(request: Request) -> Iterator[Repo]:
    repo = optional_repo(request)
    if repo is None:
        raise UnavailableError("services.not_wired", "Data services are not available yet")
    try:
        yield repo
    finally:
        close = getattr(repo, "close", None)
        if callable(close):
            close()


def get_user_store(request: Request) -> Iterator[UserStore]:
    settings = settings_for(request)
    if settings.api_mock:
        store: UserStore = request.app.state.user_store
        yield store
        return
    from athar.db.session import get_sessionmaker  # lazy: no engine in mock mode

    session = get_sessionmaker()()
    try:
        yield DbUserStore(session)
    finally:
        session.close()
