"""`DbRepo` — the real implementation of `athar.api.deps.Repo` (SPEC §13).

One instance per request, holding one SQLAlchemy session (`close()` releases it). Reads go to
`athar.services.queries`; writes delegate to the pipeline services (`scan`, `ingest`, `agents`,
`remediation`) and the ledger. Nothing here decides anything: the rule engine owns severity,
score and the action set, and agent output is only ever prose attached to what the engine
produced (CLAUDE.md non-negotiable 5).

Errors are the same stable codes `MockRepo` raises, because the frontend and the API tests
assert on them: `scan.month_not_ingested`, `plan.not_found`, `plan.invalid_state`,
`sort.unknown_field`, `simulate.unavailable`, `upload.*`. A missing id returns `None` and the
router turns that into a 404.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, cast

import httpx
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from athar.api.deps import Repo, UploadedFile
from athar.api.problem import ConflictError, InvalidInputError, UnavailableError
from athar.api.schemas import (
    Action,
    AdvanceResult,
    ApplyResult,
    DepStatus,
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
    LlmStatus,
    Page,
    RemediationPlanOut,
    RuleEval,
    ScanOut,
    SettingsOut,
    SettingsUpdate,
    SummaryOut,
    TimelineOut,
    UploadedFileOut,
    UploadProvider,
    UploadResult,
)
from athar.api.schemas import DecoyEval as DecoyEvalOut
from athar.config import Settings
from athar.db import models as m
from athar.log import get_logger
from athar.security.auth import AuthUser
from athar.services import exports, queries

log = get_logger(__name__)

RPC_TIMEOUT_SECONDS = 2.0
NOT_EVALUATED = "not computed yet — run `make eval` (or `athar eval --seed <n>`)"


def _provenance(generated_from: str) -> str:
    """The estate that produced an eval result, named without the API host's filesystem layout.

    `EvalResult.generated_from` is an absolute path because the harness writes it for whoever runs
    `athar eval` at a shell, where the full path is the useful thing. Serving that path to a browser
    discloses the server's directory structure, which CLAUDE.md forbids returning to an API client.
    The last component is the estate's own name (`seed-7`) and carries every bit of provenance a
    client can act on. Sentinels like "mock" and "not computed" pass through unchanged.
    """
    return PurePosixPath(generated_from.replace("\\", "/")).name or generated_from


class DbRepo:
    """`Repo` over Postgres. Construct per request; `close()` releases the session."""

    def __init__(self, session: Session, settings: Settings, writer: Any = None) -> None:
        self.session = session
        self.settings = settings
        self.writer = writer
        self._chain_client: Any = None
        self._chain_checked = False

    def close(self) -> None:
        self.session.close()

    # ------------------------------------------------------------------ reads
    def current_month(self) -> int | None:
        return queries.current_month(self.session)

    def estate_summary(self) -> EstateSummary:
        return queries.estate_summary(self.session, self.settings.ledger_enabled)

    def list_identities(self, filters: ListFilters) -> Page[IdentityRow]:
        return queries.list_identities(self.session, filters)

    def identity_detail(self, identity_id: str) -> IdentityDetail | None:
        return queries.identity_detail(self.session, identity_id)

    def list_findings(self, filters: ListFilters) -> Page[FindingOut]:
        return queries.list_findings(self.session, filters)

    def finding(self, finding_key: str) -> FindingOut | None:
        return queries.finding(self.session, finding_key)

    def halflife(self) -> HalfLifeTable:
        return queries.halflife(self.session)

    def timeline(self) -> TimelineOut:
        return queries.timeline(self.session)

    def list_scans(self, filters: ListFilters) -> Page[ScanOut]:
        return queries.list_scans(self.session, filters)

    def scan(self, scan_id: int) -> ScanOut | None:
        row = queries.scan_by_id(self.session, scan_id)
        return queries.scan_out(row) if row is not None else None

    # ------------------------------------------------------------------- runs
    def run_scan(self, month: int | None, user: AuthUser) -> ScanOut:
        """Diff → rules → score → attest for one month (SPEC §2). Idempotent (SPEC §12.4)."""
        from athar.services.remediation import audit, auto_remediate
        from athar.services.scan import run_scan as run_scan_service

        target = month if month is not None else queries.current_month(self.session)
        if target is None:
            raise InvalidInputError("scan.month_not_ingested", "No month has been ingested yet")
        try:
            outcome = run_scan_service(self.session, self.settings, target, writer=self.writer)
        except ValueError as exc:
            self.session.rollback()
            raise InvalidInputError("scan.month_not_ingested", str(exc)) from exc
        try:
            auto_remediate(self.session, self.settings, outcome.scan_id, writer=self.writer)
        except Exception as exc:  # auto-remediation is optional; the scan already stands
            self.session.rollback()
            log.warning("auto-remediation failed", extra={"exc_type": type(exc).__name__})
        # Auto-remediation disables departed identities, re-ingests and re-scans (SPEC §11.5), which
        # supersedes `outcome`. Returning the pre-remediation row would tell the caller a finding
        # count for access that has since been removed, and point the UI at a scan older than the
        # one every other read resolves. With auto-remediation off this is the same row.
        latest = queries.scan_for_month(self.session, target)
        scan_id = latest.scan_id if latest is not None else outcome.scan_id
        findings = latest.finding_count if latest is not None else outcome.finding_count
        audit(
            self.session,
            user.user_id,
            "run_scan",
            "scan",
            str(scan_id),
            {"month": target, "findings": findings, "ledger": outcome.ledger_status},
        )
        self.session.commit()
        return self._scan_or_stub(scan_id, target)

    def _scan_or_stub(self, scan_id: int, month: int) -> ScanOut:
        row = queries.scan_by_id(self.session, scan_id)
        if row is None:  # pragma: no cover — the scan service just wrote it
            raise UnavailableError("scan.unavailable", f"scan {scan_id} for month {month} is not readable")
        return queries.scan_out(row)

    def upload(
        self, provider: UploadProvider, month: int, files: list[UploadedFile], user: AuthUser
    ) -> UploadResult:
        """Validate, normalise and upsert one provider's month (SPEC §13, §15.2).

        A rejected file becomes a warning carrying its stable code; the request never fails
        because one file is malformed, and nothing raises past the router.
        """
        from athar.normaliser.schemas import UploadValidationError, validate_upload

        accepted: dict[str, bytes] = {}
        reported: list[UploadedFileOut] = []
        warnings: list[str] = []
        for item in files:
            try:
                validated = validate_upload(
                    provider, item.filename, item.content, self.settings.max_upload_bytes
                )
            except UploadValidationError as exc:
                warnings.append(f"{item.filename}: {exc.code} — {exc.detail}")
                reported.append(UploadedFileOut(filename=item.filename, bytes=len(item.content), rows=0))
                continue
            accepted[item.filename] = item.content
            warnings.extend(f"{item.filename}: {w}" for w in validated.warnings)
            reported.append(
                UploadedFileOut(
                    filename=item.filename, bytes=len(item.content), rows=_content_rows(validated.content)
                )
            )
        unmapped = 0
        if accepted:
            try:
                unmapped = self._ingest_upload(provider, month, accepted, warnings)
            except UploadValidationError as exc:
                self.session.rollback()
                warnings.append(f"{exc.code} — {exc.detail}")
            except Exception as exc:  # a surprising file must never kill the process (§15.2)
                self.session.rollback()
                warnings.append(f"upload.not_ingested — {type(exc).__name__}")
                log.warning(
                    "upload not ingested",
                    extra={"provider": provider, "month": month, "exc_type": type(exc).__name__},
                )
        else:
            warnings.append("upload.no_valid_files — nothing was ingested")
        from athar.services.remediation import audit

        audit(
            self.session,
            user.user_id,
            "upload",
            "snapshot",
            str(month),
            {"provider": provider, "files": len(files), "accepted": len(accepted)},
        )
        self.session.commit()
        return UploadResult(
            provider=provider, month=month, files=reported, warnings=warnings, unmapped=unmapped
        )

    def _ingest_upload(self, provider: str, month: int, files: dict[str, bytes], warnings: list[str]) -> int:
        from athar.normaliser.pipeline import (
            hr_rows_to_month,
            normalise_hr,
            normalise_provider,
            provider_rows_to_month,
        )
        from athar.normaliser.upsert import upsert_month

        if provider == "hr":
            rows = normalise_hr(month, files)
            normalised = hr_rows_to_month(rows)
            unmapped = 0
        else:
            bundle = self._hr_bundle(month)
            provider_rows = normalise_provider(provider, month, files, bundle)
            normalised = provider_rows_to_month(provider_rows, bundle)
            unmapped = len(provider_rows.unmapped)
        stats = upsert_month(self.session, normalised)
        warnings.extend(stats.warnings[:10])
        self.session.commit()
        log.info(
            "upload ingested",
            extra={
                "provider": provider,
                "month": month,
                "grants": stats.grants,
                "identities": stats.identities,
                "unmapped": unmapped,
            },
        )
        return unmapped

    def _hr_bundle(self, month: int) -> Any:
        """The linker's reference data rebuilt from stored rows, so an upload keeps its links."""
        from athar.normaliser.types import HrBundle

        identities = [
            queries.domain_identity(r)
            for r in self.session.scalars(
                select(m.Identity)
                .where(m.Identity.first_seen_month <= month)
                .order_by(m.Identity.identity_id)
            )
        ]
        projects = [
            _project_row(r) for r in self.session.scalars(select(m.Project).order_by(m.Project.project_id))
        ]
        exceptions = [
            _exception_row(r)
            for r in self.session.scalars(
                select(m.GovernanceException).order_by(m.GovernanceException.exception_id)
            )
        ]
        return HrBundle.from_identities(identities, projects, exceptions)

    def advance(self, user: AuthUser) -> AdvanceResult:
        """Simulate the next month, then run the governance cycle over it (SPEC §4.7, §11.6).

        SPEC §11.6 says this button "triggers the same loop" the scheduler runs, so the cycle is
        not reimplemented here: `wiring._run_cycle` is the one implementation of scan → attest →
        auto-remediate → investigate new findings → executive summary, and the demo's "watch drift
        happen" button and the timer must not be able to drift apart. The import is local because
        `wiring` imports this module.
        """
        from athar.services.ingest import estate_dir_for, ingest_month
        from athar.services.remediation import audit

        try:
            from athar.generator.estate import advance_estate
        except ImportError as exc:
            raise UnavailableError(
                "simulate.unavailable", "The estate simulator is not available in this build"
            ) from exc
        path = estate_dir_for(self.settings)
        try:
            new_month = int(advance_estate(path))
        except Exception as exc:
            log.warning("advance failed", extra={"exc_type": type(exc).__name__})
            raise UnavailableError(
                "simulate.unavailable", "This estate cannot be advanced (generated estates only)"
            ) from exc
        ingest_month(self.session, path, new_month)
        self._run_governance_cycle(new_month)
        scan_row = queries.scan_for_month(self.session, new_month)
        scan_id = scan_row.scan_id if scan_row is not None else 0
        audit(
            self.session,
            user.user_id,
            "advance",
            "snapshot",
            str(new_month),
            {"scan_id": scan_id, "findings": scan_row.finding_count if scan_row else 0},
        )
        self.session.commit()
        return AdvanceResult(new_month=new_month, scan=self._scan_or_stub(scan_id, new_month))

    #: Seconds the advance request will spend on investigations and the summary before leaving the
    #: rest to the scheduler. nginx gives the endpoint 120 s; the scan and the attest come first and
    #: are not optional, so the agent half gets what is comfortably left.
    ADVANCE_AGENT_BUDGET_SECONDS = 45.0

    def _run_governance_cycle(self, month: int) -> None:
        """One turn of the SPEC §11.6 loop over `month`, exactly as the scheduler runs it.

        Bounded, because this one runs inside an HTTP request: see `_run_cycle`.
        """
        from athar.services.wiring import _run_cycle

        _run_cycle(
            self.session,
            self.settings,
            self.writer,
            month,
            agent_budget_seconds=self.ADVANCE_AGENT_BUDGET_SECONDS,
        )

    # ----------------------------------------------------------------- agents
    def investigate(self, finding_key: str, regenerate: bool, user: AuthUser) -> InvestigationOut | None:
        from athar.services.agents import investigate_finding

        found = queries.find_finding(self.session, finding_key)
        if found is None:
            return None
        _scan, row = found
        record = investigate_finding(self.session, self.settings, row, regenerate=regenerate)
        if row.status == "open":
            row.status = "investigated"  # SPEC §10.3
            self.session.commit()
        output = record.output
        return InvestigationOut(
            finding_key=record.finding_key,
            hypothesis=str(output.get("hypothesis", "")),
            is_expected_for_role=bool(output.get("is_expected_for_role", False)),
            evidence_cited=[str(e) for e in output.get("evidence_cited", [])],
            confidence=max(0.0, min(1.0, float(output.get("confidence", 0.0) or 0.0))),
            recommended_action=cast(Action, output.get("recommended_action", "no_action_recommended")),
            rationale=str(output.get("rationale", "")),
            model_id=record.model_id,
            prompt_version=record.prompt_version,
            cached=record.cached,
            generated_by=cast(Any, record.generated_by),
        )

    def plan(self, finding_key: str, regenerate: bool, user: AuthUser) -> RemediationPlanOut | None:
        from athar.services.agents import plan_for_finding

        found = queries.find_finding(self.session, finding_key)
        if found is None:
            return None
        _scan, row = found
        plan = plan_for_finding(self.session, self.settings, row, regenerate=regenerate, user_id=user.user_id)
        return queries.plan_detail(self.session, plan.plan_id)

    def summary(self, regenerate: bool, user: AuthUser) -> SummaryOut:
        from athar.agents.prompts import SUMMARY_PROMPT_VERSION
        from athar.services.agents import estate_summary_paragraph

        scan = queries.latest_scan(self.session)
        if scan is None:
            return SummaryOut(
                summary_paragraph="No scan has been run yet, so there is nothing to summarise.",
                top_themes=[],
                model_id=None,
                prompt_version=SUMMARY_PROMPT_VERSION,
                cached=False,
                generated_by="template",
            )
        result = estate_summary_paragraph(self.session, self.settings, scan, regenerate=regenerate)
        out = SummaryOut(
            summary_paragraph=str(result.get("summary_paragraph", "")),
            top_themes=[str(t) for t in result.get("top_themes", [])][:3],
            model_id=result.get("model_id"),
            prompt_version=str(result.get("prompt_version", SUMMARY_PROMPT_VERSION)),
            cached=bool(result.get("cached", False)),
            generated_by=cast(Any, result.get("generated_by", "template")),
        )
        self._remember_summary(scan.scan_id, out)
        return out

    def _remember_summary(self, scan_id: int, out: SummaryOut) -> None:
        """Keep the paragraph beside the scan so the Overview never calls a model to read it."""
        self.session.merge(
            m.LlmCache(
                key=queries.summary_cache_key(scan_id),
                provider=self.settings.llm_provider,
                model=self.settings.llm_model,
                prompt_version=out.prompt_version,
                input_hash=f"scan:{scan_id}",
                output={
                    "summary_paragraph": out.summary_paragraph,
                    "top_themes": list(out.top_themes),
                    "model_id": out.model_id,
                    "generated_by": out.generated_by,
                },
                created_at=datetime.now(UTC),
            )
        )
        self.session.commit()

    # -------------------------------------------------------------- decisions
    def list_plans(self, filters: ListFilters) -> Page[RemediationPlanOut]:
        return queries.list_plans(self.session, filters)

    def get_plan(self, plan_id: str) -> RemediationPlanOut | None:
        return queries.plan_detail(self.session, plan_id)

    def _plan_row(self, plan_id: str) -> m.RemediationPlan:
        row = queries.get_plan_row(self.session, plan_id)
        if row is None:
            raise InvalidInputError("plan.not_found", "plan not found")
        return row

    def approve(self, plan_id: str, user: AuthUser) -> RemediationPlanOut:
        from athar.services.remediation import RemediationError, approve

        row = self._plan_row(plan_id)
        try:
            approve(self.session, self.settings, row, user.user_id, writer=self.writer)
        except RemediationError as exc:
            self.session.rollback()
            raise ConflictError("plan.invalid_state", str(exc)) from exc
        return self._plan_out(plan_id)

    def reject(self, plan_id: str, user: AuthUser, reason: str) -> RemediationPlanOut:
        from athar.services.remediation import RemediationError, reject

        row = self._plan_row(plan_id)
        try:
            reject(self.session, self.settings, row, user.user_id, reason, writer=self.writer)
        except RemediationError as exc:
            self.session.rollback()
            raise ConflictError("plan.invalid_state", str(exc)) from exc
        return self._plan_out(plan_id)

    def apply(self, plan_id: str, user: AuthUser) -> ApplyResult:
        from athar.services.remediation import RemediationError, apply_plan

        row = self._plan_row(plan_id)
        finding_key = row.finding_key
        try:
            outcome = apply_plan(self.session, self.settings, row, user.user_id, writer=self.writer)
        except RemediationError as exc:
            self.session.rollback()
            raise ConflictError("plan.invalid_state", str(exc)) from exc
        finding = queries.finding(self.session, finding_key)
        if finding is None:  # pragma: no cover — the plan's finding was just decided on
            raise ConflictError("plan.invalid_state", "the plan's finding is no longer readable")
        scan_id = outcome.scan.scan_id if outcome.scan is not None else row.scan_id
        return ApplyResult(
            plan=self._plan_out(plan_id),
            finding=finding,
            score_before=outcome.score_before,
            score_after=outcome.score_after,
            blast_radius_before=outcome.blast_radius_before,
            blast_radius_after=outcome.blast_radius_after,
            scan_id=scan_id,
            ledger_status=outcome.ledger_status,
            warnings=list(outcome.warnings),
        )

    def _plan_out(self, plan_id: str) -> RemediationPlanOut:
        out = queries.plan_detail(self.session, plan_id)
        if out is None:  # pragma: no cover — the row was loaded a moment ago
            raise InvalidInputError("plan.not_found", "plan not found")
        return out

    def grant_exception(self, finding_key: str, user: AuthUser, body: ExceptionRequest) -> FindingOut | None:
        from athar.services.remediation import RemediationError, grant_exception

        found = queries.find_finding(self.session, finding_key)
        if found is None:
            return None
        _scan, row = found
        try:
            grant_exception(
                self.session,
                self.settings,
                row,
                user.user_id,
                exception_type=body.exception_type,
                justification=body.justification,
                review_date=body.review_date,
                expires_on=body.expires_on,
                writer=self.writer,
            )
        except RemediationError as exc:
            self.session.rollback()
            raise ConflictError("plan.invalid_state", str(exc)) from exc
        return queries.finding(self.session, finding_key)

    # ----------------------------------------------------------------- ledger
    def _chain(self) -> Any:
        """The read side of the ledger, or None when there is no reachable node.

        The writer's own client when this process has one; otherwise a read-only client built
        from the resolved contract address. Only `LedgerWriter` ever signs (SPEC §12.4).
        """
        if not self.settings.ledger_enabled:
            return None
        if self._chain_checked:
            return self._chain_client
        self._chain_checked = True
        client = getattr(self.writer, "client", None) or self._read_only_client()
        if client is None:
            return None
        try:
            if not client.is_reachable():
                return None
        except Exception as exc:  # the ledger never blocks a read (SPEC §12.4)
            log.info("ledger unreachable", extra={"exc_type": type(exc).__name__})
            return None
        self._chain_client = client
        return client

    def _read_only_client(self) -> Any:
        from athar.ledger.client import LedgerClient

        meta = self.session.get(m.LedgerMeta, 1)
        address = self.settings.ledger_contract_address or (meta.contract_address if meta else "")
        if not address:
            return None
        try:
            return LedgerClient(self.settings.ledger_rpc_url, self.settings.ledger_private_key, address)
        except Exception as exc:
            log.info("ledger client unavailable", extra={"exc_type": type(exc).__name__})
            return None

    def ledger_info(self) -> LedgerInfo:
        from athar.ledger import verify as ledger_verify

        meta = self.session.get(m.LedgerMeta, 1)
        return LedgerInfo(
            enabled=self.settings.ledger_enabled,
            contract_address=meta.contract_address if meta else None,
            chain_id=meta.chain_id if meta else None,
            writer_address=meta.writer_address if meta else None,
            purpose=ledger_verify.LEDGER_PURPOSE,
            limits=ledger_verify.LEDGER_LIMITS,
            what_is_on_chain=list(ledger_verify.ON_CHAIN),
            what_is_not_on_chain=list(ledger_verify.NOT_ON_CHAIN),
        )

    def ledger_scans(self, filters: ListFilters) -> Page[LedgerScanOut]:
        return queries.ledger_scans(self.session, filters, chain=self._chain())

    def ledger_verify(self, scan_id: int) -> LedgerVerifyOut | None:
        """Recompute the root from the database and compare with `getCommit` (SPEC §12.6)."""
        from athar.ledger import verify as ledger_verify
        from athar.ledger.client import LedgerError

        scan = queries.scan_by_id(self.session, scan_id)
        if scan is None:
            return None
        hashes = queries.instance_hashes_for_scan(self.session, scan_id)
        computed = ledger_verify.compute_root(hashes)
        chain = self._chain()
        if scan.ledger_scan_index is None or chain is None:
            detail = (
                "not anchored: this scan has no on-chain commit"
                if scan.ledger_scan_index is None
                else "the ledger is not reachable from this process; nothing was verified"
            )
            return LedgerVerifyOut(
                scan_id=scan_id,
                passed=False,
                computed_root=computed,
                chain_root=None,
                scan_index=scan.ledger_scan_index,
                finding_count=len(hashes),
                detail=detail,
            )
        try:
            result = ledger_verify.verify_scan(hashes, scan.ledger_scan_index, chain)
        except LedgerError as exc:
            return LedgerVerifyOut(
                scan_id=scan_id,
                passed=False,
                computed_root=computed,
                chain_root=None,
                scan_index=scan.ledger_scan_index,
                finding_count=len(hashes),
                detail=f"the ledger node is unreachable; nothing was verified ({type(exc).__name__})",
            )
        return LedgerVerifyOut(
            scan_id=scan_id,
            passed=result.passed,
            computed_root=result.computed_root,
            chain_root=result.chain_root,
            scan_index=result.scan_index,
            finding_count=result.finding_count,
            detail=result.detail,
        )

    def ledger_decisions(self, filters: ListFilters) -> Page[LedgerDecisionOut]:
        return queries.ledger_decisions(self.session, filters)

    # ------------------------------------------------------- eval and exports
    def eval_result(self) -> EvalOut:
        """The held-out evaluation (SPEC §17); a clear placeholder until `make eval` has run."""
        from athar.eval.harness import load_result

        seed = self.settings.athar_eval_seed
        result = load_result(seed, Path(self.settings.data_dir))
        if result is None:
            return EvalOut(
                seed=seed,
                held_out=True,
                computed=False,
                precision=0.0,
                recall=0.0,
                f1=0.0,
                tp=0,
                fp=0,
                fn=0,
                per_rule=[],
                decoys=[],
                director_sentence=f"The evaluation on held-out seed {seed} has {NOT_EVALUATED}.",
                engineer_sentence=f"precision / recall on seed {seed}: {NOT_EVALUATED}",
                generated_from="not computed",
            )
        return EvalOut(
            seed=result.seed,
            held_out=result.seed == self.settings.athar_eval_seed,
            computed=True,
            precision=result.precision,
            recall=result.recall,
            f1=result.f1,
            tp=result.tp,
            fp=result.fp,
            fn=result.fn,
            per_rule=[
                RuleEval(rule_id=r.rule_id, tp=r.tp, fp=r.fp, fn=r.fn, precision=r.precision, recall=r.recall)
                for r in result.per_rule
            ],
            decoys=[
                DecoyEvalOut(
                    identity_id=d.identity_id,
                    display_name=d.display_name,
                    looks_like=list(d.looks_like),
                    why_legitimate=d.why_legitimate,
                    flagged_at=cast(Any, d.flagged_at) if d.flagged_at else None,
                    correctly_handled=d.correctly_handled,
                )
                for d in result.decoys
            ],
            director_sentence=result.director_sentence,
            engineer_sentence=result.engineer_sentence,
            generated_from=_provenance(result.generated_from),
        )

    def export_csv(self, filters: ListFilters) -> bytes:
        return exports.export_csv(self.session, self.settings, filters)

    def export_json(self, filters: ListFilters) -> bytes:
        return exports.export_json(self.session, self.settings, filters)

    def export_pdf(self, filters: ListFilters) -> bytes:
        return exports.export_pdf(self.session, self.settings, filters)

    # ------------------------------------------------------ settings / health
    def _settings_row(self) -> m.RuntimeSettings:
        row = self.session.get(m.RuntimeSettings, 1)
        if row is None:
            row = m.RuntimeSettings(
                id=1,
                dormant_days=self.settings.dormant_days,
                stale_key_days=self.settings.stale_key_days,
                approved_regions=list(self.settings.approved_regions),
                auto_remediate_departed=self.settings.auto_remediate_departed,
            )
            self.session.add(row)
            self.session.commit()
        return row

    def _llm_status(self) -> LlmStatus:
        """Provider, model and cache size only — never a URL and never a key (SPEC §13)."""
        provider = self.settings.llm_provider
        model = self.settings.ollama_model if provider == "ollama" else self.settings.llm_model
        entries = int(self.session.scalar(select(func.count()).select_from(m.LlmCache)) or 0)
        return LlmStatus(provider=provider, model=model, reachable=None, cache_entries=entries)

    def get_settings(self) -> SettingsOut:
        row = self._settings_row()
        return SettingsOut(
            dormant_days=row.dormant_days,
            stale_key_days=row.stale_key_days,
            approved_regions=[str(r) for r in (row.approved_regions or [])],
            auto_remediate_departed=bool(row.auto_remediate_departed),
            updated_by=row.updated_by,
            updated_at=row.updated_at,
            llm=self._llm_status(),
        )

    def put_settings(self, body: SettingsUpdate, user: AuthUser) -> SettingsOut:
        from athar.services.remediation import audit

        row = self._settings_row()
        update = body.model_dump(exclude_none=True)
        if "dormant_days" in update:
            row.dormant_days = int(update["dormant_days"])
        if "stale_key_days" in update:
            row.stale_key_days = int(update["stale_key_days"])
        if "approved_regions" in update:
            row.approved_regions = [str(r) for r in update["approved_regions"]]
        if "auto_remediate_departed" in update:
            row.auto_remediate_departed = bool(update["auto_remediate_departed"])
        row.updated_by = user.user_id
        row.updated_at = datetime.now(UTC)
        audit(self.session, user.user_id, "put_settings", "settings", "1", dict(update))
        self.session.commit()
        return self.get_settings()

    def health_deps(self) -> HealthDeps:
        return HealthDeps(db=self._probe_db(), anvil=self._probe_anvil(), llm=self._probe_llm())

    def _probe_db(self) -> DepStatus:
        try:
            self.session.execute(text("SELECT 1"))
        except Exception as exc:
            self.session.rollback()
            return DepStatus(ok=False, detail=f"database unreachable ({type(exc).__name__})")
        return DepStatus(ok=True, detail="postgres reachable")

    def _probe_anvil(self) -> DepStatus:
        if not self.settings.ledger_enabled:
            return DepStatus(ok=True, detail="ledger disabled by configuration")
        payload = {"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}
        try:
            with httpx.Client(timeout=RPC_TIMEOUT_SECONDS) as client:
                response = client.post(self.settings.ledger_rpc_url, json=payload)
            response.raise_for_status()
            chain_hex = response.json().get("result")
            if not isinstance(chain_hex, str):
                return DepStatus(ok=False, detail="rpc answered without a chain id")
            return DepStatus(ok=True, detail=f"chain id {int(chain_hex, 16)}")
        except (httpx.HTTPError, ValueError) as exc:
            return DepStatus(ok=False, detail=f"rpc unreachable ({type(exc).__name__})")

    def _probe_llm(self) -> DepStatus:
        provider = self.settings.llm_provider
        if provider == "none":
            return DepStatus(ok=True, detail="templates only (LLM_PROVIDER=none)")
        if provider == "gemini":
            present = bool(self.settings.effective_gemini_key)
            return DepStatus(
                ok=present,
                detail=f"gemini · {self.settings.llm_model} · key {'present' if present else 'missing'}",
            )
        return DepStatus(ok=True, detail=f"ollama · {self.settings.ollama_model} · configured (not probed)")


def _content_rows(content: Any) -> int:
    """Entries read from one validated file — what the result reports as `rows`."""
    if isinstance(content, list):
        return len(content)
    if isinstance(content, dict):
        return sum(len(v) if isinstance(v, list) else 1 for v in content.values())
    if isinstance(content, str):
        return max(0, content.count("\n") - 1)
    return 0


def _project_row(row: m.Project) -> Any:
    from athar.domain import ProjectRow

    return ProjectRow(
        project_id=row.project_id,
        name=row.name,
        department=row.department,
        status=row.status,
        retired_month=row.retired_month,
        cloud=row.cloud,
        project_ref=row.project_ref,
    )


def _exception_row(row: m.GovernanceException) -> Any:
    from athar.domain import ExceptionRow

    return ExceptionRow(
        exception_id=row.exception_id,
        identity_id=row.identity_id,
        exception_type=row.exception_type,
        approved_by=row.approved_by,
        approved_on=row.approved_on,
        review_date=row.review_date,
        expires_on=row.expires_on,
        justification=row.justification,
        source=row.source,
    )


def _conforms(r: DbRepo) -> Repo:
    """Static proof that `DbRepo` satisfies `Repo`: mypy checks the structural match here."""
    return r
