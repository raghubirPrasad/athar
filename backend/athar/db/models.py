"""Canonical Permission Model + operational tables (SPEC §5.1). FROZEN at gate G1.

Changing a CPM table requires: SPEC edit, Alembic migration, mapping tests, PR note.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

JsonType = JSON().with_variant(JSONB(), "postgresql")


class Base(DeclarativeBase):
    type_annotation_map = {dict[str, Any]: JsonType, list[Any]: JsonType}


# ---------------------------------------------------------------------------
# Canonical Permission Model
# ---------------------------------------------------------------------------


class Identity(Base):
    __tablename__ = "identities"
    identity_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(200))
    identity_type: Mapped[str] = mapped_column(String(16))  # human | service
    department: Mapped[str] = mapped_column(String(64))
    employment_type: Mapped[str] = mapped_column(String(16))  # staff | contractor | service
    employment_status: Mapped[str] = mapped_column(String(16))  # active | departed | on_leave
    hire_month: Mapped[int | None] = mapped_column(Integer)
    departure_month: Mapped[int | None] = mapped_column(Integer)
    external: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_enforced: Mapped[bool] = mapped_column(Boolean, default=False)
    tags: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict)
    contract_end_month: Mapped[int | None] = mapped_column(Integer)
    first_seen_month: Mapped[int] = mapped_column(Integer)
    last_seen_month: Mapped[int] = mapped_column(Integer)


class Principal(Base):
    __tablename__ = "principals"
    principal_ref: Mapped[str] = mapped_column(String(512), primary_key=True)
    cloud: Mapped[str] = mapped_column(String(8))  # aws | azure | gcp
    principal_type: Mapped[str] = mapped_column(
        String(32)
    )  # user | role | group | service_principal | service_account
    identity_id: Mapped[str | None] = mapped_column(ForeignKey("identities.identity_id"), nullable=True)
    raw: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict)
    link_method: Mapped[str] = mapped_column(
        String(32)
    )  # hr_email | entra_directory | aws_username | sa_project | tag_owner | unlinked
    link_confidence: Mapped[str] = mapped_column(String(16))  # exact | derived | heuristic
    __table_args__ = (Index("ix_principals_identity", "identity_id"),)


class Grant(Base):
    __tablename__ = "grants"
    grant_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    identity_id: Mapped[str] = mapped_column(ForeignKey("identities.identity_id"))
    principal_ref: Mapped[str] = mapped_column(ForeignKey("principals.principal_ref"))
    cloud: Mapped[str] = mapped_column(String(8))
    service_category: Mapped[str] = mapped_column(String(16))
    verb: Mapped[str] = mapped_column(String(16))
    scope_level: Mapped[str] = mapped_column(String(16))  # resource | project | org | global
    scope_ref: Mapped[str] = mapped_column(String(512))
    region: Mapped[str | None] = mapped_column(String(32))
    effect: Mapped[str] = mapped_column(String(8), default="allow")
    granted_via: Mapped[str] = mapped_column(String(512))
    snapshot_month: Mapped[int] = mapped_column(Integer)
    raw_snippet: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict)
    source_file: Mapped[str] = mapped_column(String(256))
    source_pointer: Mapped[str] = mapped_column(String(512))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    __table_args__ = (
        UniqueConstraint(
            "principal_ref",
            "cloud",
            "service_category",
            "verb",
            "scope_ref",
            "granted_via",
            "snapshot_month",
            name="uq_grant_natural",
        ),
        Index("ix_grants_identity_month", "identity_id", "snapshot_month"),
        Index("ix_grants_month", "snapshot_month"),
    )


class Activity(Base):
    __tablename__ = "activity"
    identity_id: Mapped[str] = mapped_column(ForeignKey("identities.identity_id"), primary_key=True)
    cloud: Mapped[str] = mapped_column(String(8), primary_key=True)
    service_category: Mapped[str] = mapped_column(String(16), primary_key=True)
    snapshot_month: Mapped[int] = mapped_column(Integer, primary_key=True)
    last_activity_at: Mapped[date | None] = mapped_column(Date)
    operation_count: Mapped[int] = mapped_column(Integer, default=0)


class Credential(Base):
    __tablename__ = "credentials"
    credential_ref: Mapped[str] = mapped_column(String(256), primary_key=True)
    identity_id: Mapped[str] = mapped_column(ForeignKey("identities.identity_id"))
    cloud: Mapped[str] = mapped_column(String(8))
    kind: Mapped[str] = mapped_column(String(16))  # key | password | sa_key
    created_at: Mapped[date | None] = mapped_column(Date)
    last_rotated_at: Mapped[date | None] = mapped_column(Date)
    last_used_at: Mapped[date | None] = mapped_column(Date)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    snapshot_month: Mapped[int] = mapped_column(Integer)
    __table_args__ = (Index("ix_credentials_identity_month", "identity_id", "snapshot_month"),)


class Resource(Base):
    __tablename__ = "resources"
    resource_ref: Mapped[str] = mapped_column(String(512), primary_key=True)
    cloud: Mapped[str] = mapped_column(String(8))
    service_category: Mapped[str] = mapped_column(String(16))
    region: Mapped[str | None] = mapped_column(String(32))
    project_ref: Mapped[str | None] = mapped_column(String(256))
    sensitivity: Mapped[str] = mapped_column(String(8), default="low")  # low | high
    snapshot_month: Mapped[int] = mapped_column(Integer)


class Project(Base):
    __tablename__ = "projects"
    project_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    department: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16))  # active | retired
    retired_month: Mapped[int | None] = mapped_column(Integer)
    cloud: Mapped[str] = mapped_column(String(8))
    project_ref: Mapped[str] = mapped_column(String(256))


class GovernanceException(Base):
    """Governance exception register (SPEC §4.3) — the ONLY source rules consult."""

    __tablename__ = "exceptions"
    exception_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    identity_id: Mapped[str] = mapped_column(String(128))
    exception_type: Mapped[str] = mapped_column(
        String(32)
    )  # break-glass | dr-failover | approved-privileged-role | time-boxed
    approved_by: Mapped[str] = mapped_column(String(128))
    approved_on: Mapped[date | None] = mapped_column(Date)
    review_date: Mapped[date | None] = mapped_column(Date)
    expires_on: Mapped[date | None] = mapped_column(Date)
    justification: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(16), default="register")  # register | workflow
    __table_args__ = (Index("ix_exceptions_identity", "identity_id"),)


class Event(Base):
    __tablename__ = "events"
    event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    month: Mapped[int] = mapped_column(Integer)
    kind: Mapped[str] = mapped_column(String(32))
    identity_id: Mapped[str | None] = mapped_column(String(128))
    cloud: Mapped[str | None] = mapped_column(String(8))
    grant_delta: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict)
    trigger: Mapped[str] = mapped_column(String(32), default="unknown")
    note: Mapped[str] = mapped_column(Text, default="")
    __table_args__ = (Index("ix_events_identity_month", "identity_id", "month"),)


class Snapshot(Base):
    __tablename__ = "snapshots"
    snapshot_month: Mapped[int] = mapped_column(Integer, primary_key=True)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    file_hashes: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict)


class EstateClock(Base):
    __tablename__ = "estate_clock"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    current_month: Mapped[int] = mapped_column(Integer, default=0)


# ---------------------------------------------------------------------------
# Derived and operational tables
# ---------------------------------------------------------------------------


class Scan(Base):
    __tablename__ = "scans"
    scan_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    snapshot_month: Mapped[int] = mapped_column(Integer)
    ruleset_hash: Mapped[str] = mapped_column(String(66))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
    merkle_root: Mapped[str | None] = mapped_column(String(66))
    snapshot_hash: Mapped[str | None] = mapped_column(String(66))
    ledger_scan_index: Mapped[int | None] = mapped_column(Integer)
    ledger_tx: Mapped[str | None] = mapped_column(String(66))
    ledger_status: Mapped[str] = mapped_column(String(24), default="pending")
    # pending | anchored | unanchored | already_anchored | failed
    __table_args__ = (Index("ix_scans_month", "snapshot_month"),)


class Finding(Base):
    __tablename__ = "findings"
    finding_key: Mapped[str] = mapped_column(String(32), primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.scan_id"), primary_key=True)
    identity_id: Mapped[str] = mapped_column(String(128))
    rule_id: Mapped[str] = mapped_column(String(8))
    severity: Mapped[str] = mapped_column(String(12))
    score: Mapped[int] = mapped_column(Integer)
    first_seen_month: Mapped[int] = mapped_column(Integer)
    evidence_refs: Mapped[list[Any]] = mapped_column(JsonType, default=list)
    causal_event_ids: Mapped[list[Any]] = mapped_column(JsonType, default=list)
    instance_hash: Mapped[str] = mapped_column(String(66))
    leaf_proof: Mapped[list[Any]] = mapped_column(JsonType, default=list)
    status: Mapped[str] = mapped_column(String(32), default="open")
    facts: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict)  # slotted facts for narratives
    __table_args__ = (
        Index("ix_findings_scan", "scan_id"),
        Index("ix_findings_identity", "identity_id"),
    )


class IdentityScore(Base):
    __tablename__ = "identity_scores"
    identity_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.scan_id"), primary_key=True)
    blast_radius: Mapped[float] = mapped_column()
    reach: Mapped[float] = mapped_column()
    exploitability: Mapped[float] = mapped_column()
    compensating: Mapped[float] = mapped_column()
    score: Mapped[int] = mapped_column(Integer)
    severity: Mapped[str] = mapped_column(String(12))
    line_items: Mapped[list[Any]] = mapped_column(JsonType, default=list)
    escalation_paths: Mapped[list[Any]] = mapped_column(JsonType, default=list)
    __table_args__ = (Index("ix_identity_scores_scan", "scan_id"),)


class RemediationPlan(Base):
    __tablename__ = "remediation_plans"
    plan_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    finding_key: Mapped[str] = mapped_column(String(32))
    scan_id: Mapped[int] = mapped_column(Integer)
    action: Mapped[str] = mapped_column(String(48))
    params: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict)
    policy_diff: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict)
    keep: Mapped[list[Any]] = mapped_column(JsonType, default=list)
    drop: Mapped[list[Any]] = mapped_column(JsonType, default=list)
    privilege_reduction_pct: Mapped[float] = mapped_column(default=0.0)
    expected_blast_radius_after: Mapped[float] = mapped_column(default=0.0)
    proposed_by: Mapped[str] = mapped_column(String(16))  # model | rule
    proposer_user_id: Mapped[str | None] = mapped_column(String(64))
    model_id: Mapped[str | None] = mapped_column(String(64))
    prompt_version: Mapped[str | None] = mapped_column(String(16))
    rationale: Mapped[str] = mapped_column(Text, default="")
    confidence: Mapped[float] = mapped_column(default=0.0)
    status: Mapped[str] = mapped_column(
        String(16), default="proposed"
    )  # proposed | approved | rejected | applied
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    __table_args__ = (Index("ix_plans_finding", "finding_key"),)


class Decision(Base):
    __tablename__ = "decisions"
    decision_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    plan_id: Mapped[str | None] = mapped_column(String(64))
    finding_key: Mapped[str] = mapped_column(String(32))
    scan_id: Mapped[int] = mapped_column(Integer)
    decision: Mapped[str] = mapped_column(String(24))
    # approved | rejected | auto_remediated | remediation_applied | exception_granted
    actor_user_id: Mapped[str] = mapped_column(String(64))
    evidence_hash: Mapped[str] = mapped_column(String(66))
    ledger_tx: Mapped[str | None] = mapped_column(String(66))
    ledger_status: Mapped[str] = mapped_column(String(24), default="pending")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    actor_user_id: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(48))
    subject_type: Mapped[str] = mapped_column(String(32))
    subject_id: Mapped[str] = mapped_column(String(128))
    detail: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict)


class LlmCache(Base):
    __tablename__ = "llm_cache"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    provider: Mapped[str] = mapped_column(String(16))
    model: Mapped[str] = mapped_column(String(64))
    prompt_version: Mapped[str] = mapped_column(String(16))
    input_hash: Mapped[str] = mapped_column(String(64))
    output: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class LedgerMeta(Base):
    __tablename__ = "ledger_meta"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    contract_address: Mapped[str] = mapped_column(String(42))
    chain_id: Mapped[int] = mapped_column(Integer)
    deployed_block: Mapped[int] = mapped_column(Integer)
    writer_address: Mapped[str] = mapped_column(String(42))


class User(Base):
    __tablename__ = "users"
    user_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    email: Mapped[str] = mapped_column(String(256), unique=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    role: Mapped[str] = mapped_column(String(16))  # analyst | approver | viewer
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class RuntimeSettings(Base):
    __tablename__ = "settings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    dormant_days: Mapped[int] = mapped_column(Integer, default=90)
    stale_key_days: Mapped[int] = mapped_column(Integer, default=180)
    approved_regions: Mapped[list[Any]] = mapped_column(JsonType, default=list)
    auto_remediate_departed: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_by: Mapped[str | None] = mapped_column(String(64))
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
