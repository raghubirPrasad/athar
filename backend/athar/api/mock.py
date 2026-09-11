"""Deterministic in-process dataset served when `ATHAR_API_MOCK=true` (SPEC §13, §14).

Exists so the frontend can be built against the real OpenAPI contract before the data
services land. Everything derives from `random.Random(seed)` and a fixed clock; two
`MockRepo(settings)` instances are field-for-field identical. Decisions mutate the in-memory
state so approve / reject / apply / exception flows can be exercised end to end.

Synthetic only: departments and names follow SPEC §4.1, emails use `nda.example`, cloud ids
are derived from the seeded RNG. Nothing here is real.
"""

from __future__ import annotations

import csv
import io
import json
import random
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, TypeVar, cast

from pydantic import BaseModel

from athar.api.deps import Repo, UploadedFile
from athar.api.problem import ConflictError, InvalidInputError
from athar.api.schemas import (
    Action,
    ActivityOut,
    AdvanceResult,
    AltitudesOut,
    ApplyResult,
    CausalStepOut,
    Cloud,
    CredentialOut,
    DecisionKind,
    DecisionOut,
    DecoyEval,
    DepartmentRollup,
    DepStatus,
    EmploymentStatus,
    EstateSummary,
    EvalOut,
    EvidenceRefOut,
    ExceptionOut,
    ExceptionRequest,
    ExceptionType,
    FindingOut,
    GrantOut,
    HalfLifeLabel,
    HalfLifeOut,
    HalfLifeTable,
    HealthDeps,
    IdentityDetail,
    IdentityRow,
    IdentityType,
    InvestigationOut,
    LedgerBadge,
    LedgerBadgeStatus,
    LedgerDecisionOut,
    LedgerInfo,
    LedgerScanOut,
    LedgerVerifyOut,
    LineItemOut,
    ListFilters,
    LlmStatus,
    Page,
    PathEdgeOut,
    PlanStatus,
    PolicyDiffOut,
    PolicyOperation,
    PrincipalOut,
    ProposedBy,
    RemediationPlanOut,
    RiskPoint,
    RuleEval,
    ScanLedgerStatus,
    ScanOut,
    ScoreOut,
    SettingsOut,
    SettingsUpdate,
    Severity,
    SummaryOut,
    TimelineOut,
    TimelinePoint,
    UploadedFileOut,
    UploadProvider,
    UploadResult,
)
from athar.clock import month_end, month_label
from athar.config import EMAIL_DOMAIN, Settings
from athar.detection.registry import all_rules
from athar.hashing import (
    canonical_json,
    finding_instance,
    finding_key,
    instance_hash,
    keccak256_hex,
    ruleset_hash,
)
from athar.ledger import merkle
from athar.security.auth import AuthUser

MOCK_NOW = datetime(2026, 9, 1, 9, 0, tzinfo=UTC)  # fixed: the mock never reads the wall clock
MOCK_MONTH = 12
MOCK_CHAIN_ID = 31337
MOCK_CONTRACT = "0x5FbDB2315678afecb367f032d93F642f64180aa3"  # Anvil's first deploy address
MOCK_WRITER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"  # Anvil dev account #0 (public)
DEMO_DOMAIN = "athar.local"
PROMPT_VERSION = "v1"
REF_SHARE = 0.25
FLOORS: dict[str, int] = {"Critical": 75, "High": 50, "Medium": 25, "Low": 0}
SEVERITY_RANK: dict[str, int] = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
SEVERITIES: tuple[Severity, ...] = ("Low", "Medium", "High", "Critical")
CLOUDS: tuple[Cloud, ...] = ("aws", "azure", "gcp")
DEPARTMENTS = (
    "Finance",
    "HR",
    "Platform Engineering",
    "Data Services",
    "Smart Services",
    "Cyber Security",
    "Field Operations",
    "Contractors",
)
FIRST_NAMES = (
    "Ahmed", "Fatima", "Mohammed", "Aisha", "Omar", "Mariam", "Khalid", "Noura", "Saeed", "Hessa",
    "Rashid", "Latifa", "Hamad", "Shamma", "Sultan", "Maitha", "Yousef", "Alya", "Tariq", "Reem",
    "Priya", "Arjun", "Sara", "Daniel", "Layla", "Hassan", "Zainab", "Faisal", "Amal", "Nasser",
)  # fmt: skip
LAST_NAMES = (
    "Al Mansoori", "Al Marzooqi", "Al Ketbi", "Al Shamsi", "Al Dhaheri", "Al Mazrouei", "Al Nuaimi",
    "Al Hammadi", "Khan", "Sharma", "Haddad", "Rahman", "Al Suwaidi", "Al Blooshi", "Iyer",
)  # fmt: skip
SERVICE_NAMES = (
    "svc-billing-etl", "svc-dr-failover-a", "svc-portal-ci", "svc-analytics-loader", "svc-dr-failover-b",
    "svc-hr-sync", "svc-backup-runner", "svc-dr-failover-c", "svc-field-telemetry", "svc-legacy-reports",
)  # fmt: skip
CATEGORIES = ("compute", "storage", "identity", "data", "network", "secrets")
UNAPPROVED_REGIONS: dict[str, str] = {"aws": "eu-west-1", "azure": "westeurope", "gcp": "us-central1"}
HOME_REGION: dict[str, str] = {"aws": "me-central-1", "azure": "uaenorth", "gcp": "me-central1"}
SOURCE_FILE: dict[str, str] = {
    "aws": "aws/authorization-details.json",
    "azure": "azure/role-assignments.json",
    "gcp": "gcp/iam-policy.json",
}
AWS_SERVICE: dict[str, str] = {
    "identity": "iam",
    "storage": "s3",
    "compute": "ec2",
    "data": "rds",
    "network": "ec2",
    "secrets": "secretsmanager",
    "unknown": "iam",
}
DECISION_CODES: dict[str, int] = {
    "approved": 1,
    "rejected": 2,
    "auto_remediated": 3,
    "remediation_applied": 4,
    "exception_granted": 5,
}
BADGE_FOR_SCAN: dict[str, LedgerBadgeStatus] = {
    "anchored": "anchored",
    "already_anchored": "anchored",
    "pending": "pending",
    "unanchored": "unanchored",
    "failed": "verification_failed",
}
# Decoys (SPEC §4.3): legitimacy lives in the exception register, never in cloud tags.
DECOY_EXCEPTIONS: dict[str, tuple[ExceptionType, str]] = {
    "emp-0006": ("break-glass", "Break-glass administrator; MFA enforced, monitored, quarterly review"),
    "emp-0014": ("break-glass", "Break-glass administrator; MFA enforced, monitored, quarterly review"),
    "emp-0011": ("approved-privileged-role", "Sanctioned platform administrator, project scope, used weekly"),
    "emp-0019": ("approved-privileged-role", "Sanctioned platform administrator, project scope, used weekly"),
    "svc-0002": ("dr-failover", "DR failover account; activation is the DR path"),
    "svc-0005": ("dr-failover", "DR failover account; activation is the DR path"),
    "svc-0008": ("dr-failover", "DR failover account; activation is the DR path"),
}
TIME_BOXED_CONTRACTORS = ("emp-0008", "emp-0016", "emp-0024", "emp-0030")
DECOY_IDS = tuple(DECOY_EXCEPTIONS) + TIME_BOXED_CONTRACTORS
LOOKS_LIKE: dict[str, list[str]] = {
    "break-glass": ["R1", "R4"],
    "approved-privileged-role": ["R1"],
    "dr-failover": ["R2"],
    "time-boxed": ["R7"],
}
EXPORT_COLUMNS = [
    "finding_key", "identity_id", "display_name", "identity_type", "department", "clouds", "rule_id",
    "rule_name", "severity", "risk_score", "blast_radius_pct", "first_seen_month", "causal_trigger",
    "plain_english_finding", "recommended_action", "attack_technique", "control_ref", "status",
    "instance_hash", "scan_id", "merkle_root", "ledger_tx",
]  # fmt: skip

M = TypeVar("M", bound=BaseModel)


def _band(score: int) -> Severity:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def _hl_label(months: float | None) -> HalfLifeLabel:
    if months is None or months > 8:
        return "Broken"
    return "Healthy" if months <= 4 else "Slow"


def _slug(name: str) -> str:
    return name.lower().replace(" ", ".")


@dataclass
class _Identity:
    identity_id: str
    display_name: str
    identity_type: IdentityType
    department: str
    employment_type: str
    employment_status: EmploymentStatus
    hire_month: int | None
    departure_month: int | None
    external: bool
    mfa_enforced: bool
    tags: dict[str, Any]
    contract_end_month: int | None
    clouds: list[Cloud]
    grants: list[GrantOut] = field(default_factory=list)
    activity: list[ActivityOut] = field(default_factory=list)
    credentials: list[CredentialOut] = field(default_factory=list)
    principals: list[PrincipalOut] = field(default_factory=list)
    events: list[CausalStepOut] = field(default_factory=list)
    rules: list[str] = field(default_factory=list)
    score: ScoreOut | None = None
    risk_history: list[RiskPoint] = field(default_factory=list)


@dataclass(frozen=True)
class _Rule:
    id: str
    name: str
    severity: Severity
    version: str
    allowed_actions: list[Action]
    attack_techniques: list[str]
    control_refs: list[str]


class MockRepo:
    """Implements `athar.api.deps.Repo` over an in-memory synthetic estate."""

    def __init__(self, settings: Settings, seed: int = 1) -> None:
        self.settings = settings
        self.rng = random.Random(seed)
        self.month = MOCK_MONTH
        self.rules: dict[str, _Rule] = {
            r.id: _Rule(
                id=r.id,
                name=r.name,
                severity=cast(Severity, r.severity),
                version=r.version,
                allowed_actions=cast(list[Action], list(r.allowed_actions)),
                attack_techniques=list(r.attack_techniques),
                control_refs=list(r.control_refs),
            )
            for r in all_rules()
        }
        self.identities: dict[str, _Identity] = {}
        self.findings: dict[str, FindingOut] = {}
        self.exceptions: list[ExceptionOut] = []
        self.scans: list[ScanOut] = []
        self.plans: dict[str, RemediationPlanOut] = {}
        self.decisions: list[DecisionOut] = []
        self.investigations: dict[str, InvestigationOut] = {}
        self.halflife_rows: list[HalfLifeOut] = []
        self.timeline_points: list[TimelinePoint] = []
        self.ruleset = ruleset_hash(
            {r.id: r.version for r in self.rules.values()},
            {
                "dormant_days": settings.dormant_days,
                "stale_key_days": settings.stale_key_days,
                "approved_regions": sorted(settings.approved_regions),
            },
        )
        self.settings_state = SettingsOut(
            dormant_days=settings.dormant_days,
            stale_key_days=settings.stale_key_days,
            approved_regions=list(settings.approved_regions),
            auto_remediate_departed=settings.auto_remediate_departed,
            updated_by=None,
            updated_at=None,
            llm=LlmStatus(
                provider=settings.llm_provider, model=settings.llm_model, reachable=None, cache_entries=0
            ),
        )
        self._build_identities()
        self._assign_rules()
        self._decoy_rows()
        self._build_findings()
        self._build_scores()
        self._build_exceptions()
        self._build_scans()
        self._build_plans()
        self._build_halflife_and_timeline()
        self.eval = self._build_eval()
        self.settings_state.llm.cache_entries = len(self.findings) + 1

    # ------------------------------------------------------------ primitives
    def _guid(self) -> str:
        return str(uuid.UUID(int=self.rng.getrandbits(128)))

    def _tx(self) -> str:
        return "0x" + self.rng.getrandbits(256).to_bytes(32, "big").hex()

    def _principal_ref(self, ident: _Identity, cloud: str) -> str:
        slug = _slug(ident.display_name)
        svc = ident.identity_type == "service"
        if cloud == "aws":
            return f"arn:aws:iam::123456789012:{'role' if svc else 'user'}/{slug}"
        if cloud == "azure":
            return f"azure:{'sp' if svc else 'user'}:{self._guid()}"
        if svc:
            return f"serviceAccount:{slug}@nda-analytics-prod.iam.gserviceaccount.com"
        return f"user:{slug}@{EMAIL_DOMAIN}"

    def _add_principal(self, ident: _Identity, cloud: Cloud) -> PrincipalOut:
        svc = ident.identity_type == "service"
        p = PrincipalOut(
            principal_ref=self._principal_ref(ident, cloud),
            cloud=cloud,
            principal_type="service_account" if svc else "user",
            link_method="sa_project" if svc else "hr_email",
            link_confidence="derived" if svc else "exact",
        )
        ident.principals.append(p)
        return p

    def _native(
        self, cloud: str, category: str, verb: str, scope_level: str, region: str
    ) -> tuple[str, str, dict[str, Any], str]:
        """Provider-native scope_ref, granted_via, raw snippet and JSON pointer (SPEC §5.2 flavour)."""
        idx = self.rng.randint(0, 40)
        if cloud == "aws":
            if verb == "admin":
                return (
                    "*",
                    "arn:aws:iam::aws:policy/AdministratorAccess",
                    {
                        "PolicyName": "AdministratorAccess",
                        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
                    },
                    f"/UserDetailList/{idx}/AttachedManagedPolicies/0",
                )
            svc = AWS_SERVICE[category]
            action = f"{svc}:{'Get*' if verb == 'read' else '*'}"
            return (
                f"arn:aws:{svc}:{region}:123456789012:*",
                f"inline:policy-{category}",
                {"Statement": [{"Effect": "Allow", "Action": action, "Resource": "*"}]},
                f"/UserDetailList/{idx}/UserPolicyList/0/PolicyDocument/Statement/0",
            )
        if cloud == "azure":
            role = "Owner" if verb == "admin" else ("Contributor" if verb == "write" else "Reader")
            scope = f"/subscriptions/{self._guid()}" + (
                f"/resourceGroups/rg-{category}" if scope_level == "resource" else ""
            )
            return (
                scope,
                f"roleDefinition:{role}",
                {"roleDefinitionName": role, "scope": scope, "location": region},
                f"/value/{idx}",
            )
        role = (
            "roles/owner"
            if verb == "admin"
            else f"roles/{category}.{'admin' if verb == 'write' else 'viewer'}"
        )
        project = "organizations/1234567890" if scope_level == "org" else "nda-analytics-prod"
        return (
            project,
            role,
            {"role": role, "members": ["<principal>"], "location": region},
            f"/bindings/{idx}",
        )

    def _add_grant(
        self,
        ident: _Identity,
        cloud: Cloud,
        category: str,
        verb: str,
        scope_level: str,
        region: str | None = None,
    ) -> GrantOut:
        principal = next((p.principal_ref for p in ident.principals if p.cloud == cloud), None)
        if principal is None:
            principal = self._add_principal(ident, cloud).principal_ref
            if cloud not in ident.clouds:
                ident.clouds = sorted([*ident.clouds, cloud], key=CLOUDS.index)
        region = region or HOME_REGION[cloud]
        scope_ref, granted_via, raw, pointer = self._native(cloud, category, verb, scope_level, region)
        grant = GrantOut(
            grant_id=f"grant-{ident.identity_id}-{len(ident.grants) + 1:02d}",
            principal_ref=principal,
            cloud=cloud,
            service_category=category,
            verb=verb,
            scope_level=scope_level,
            scope_ref=scope_ref,
            region=region,
            effect="allow",
            granted_via=granted_via,
            snapshot_month=self.month,
            raw_snippet=raw,
            source_file=SOURCE_FILE[cloud],
            source_pointer=pointer,
            active=True,
        )
        ident.grants.append(grant)
        return grant

    def _add_credential(self, ident: _Identity, cloud: Cloud, kind: str, rotated_days: int) -> CredentialOut:
        end = month_end(self.month)
        rotated = end - timedelta(days=rotated_days)
        cred = CredentialOut(
            credential_ref=f"{cloud}:{kind}:{ident.identity_id}-{len(ident.credentials) + 1}",
            cloud=cloud,
            kind=kind,
            created_at=rotated - timedelta(days=30),
            last_rotated_at=rotated,
            last_used_at=end - timedelta(days=self.rng.randint(1, 30)),
            active=True,
            age_days=rotated_days,
        )
        ident.credentials.append(cred)
        return cred

    def _set_activity(
        self, ident: _Identity, cloud: Cloud, category: str, days_ago: int, count: int
    ) -> ActivityOut:
        ident.activity = [
            a for a in ident.activity if not (a.cloud == cloud and a.service_category == category)
        ]
        row = ActivityOut(
            cloud=cloud,
            service_category=category,
            snapshot_month=self.month,
            last_activity_at=month_end(self.month) - timedelta(days=days_ago),
            operation_count=count,
        )
        ident.activity.append(row)
        return row

    def _event(
        self, ident: _Identity, month: int, kind: str, trigger: str, cloud: Cloud | None, desc: str
    ) -> str:
        eid = f"evt-{month:02d}-{ident.identity_id}-{len(ident.events) + 1}"
        ident.events.append(
            CausalStepOut(
                month=month, event_id=eid, kind=kind, trigger=trigger, cloud=cloud, description=desc
            )
        )
        return eid

    # ------------------------------------------------------------ identities
    def _build_identities(self) -> None:
        rng = self.rng
        departed = {1, 12, 20, 27}
        for i in range(30):
            dept = "Contractors" if i == 29 else DEPARTMENTS[i % 8]
            external = dept == "Contractors"
            name = f"{FIRST_NAMES[i]} {LAST_NAMES[(i * 7) % len(LAST_NAMES)]}"
            status: EmploymentStatus = "departed" if i in departed else ("on_leave" if i == 9 else "active")
            clouds = sorted(rng.sample(CLOUDS, k=rng.choice([1, 1, 2, 2, 3])), key=CLOUDS.index)
            iid = f"emp-{i + 1:04d}"
            self.identities[iid] = _Identity(
                identity_id=iid,
                display_name=name,
                identity_type="human",
                department=dept,
                employment_type="contractor" if external else "staff",
                employment_status=status,
                hire_month=rng.randint(1, 5),
                departure_month=rng.randint(7, 11) if status == "departed" else None,
                external=external,
                mfa_enforced=rng.random() < 0.8,
                tags={"owner": f"{_slug(name)}@{EMAIL_DOMAIN}", "cost-centre": f"CC-{100 + i % 8}"},
                contract_end_month=rng.choice([10, 14, 18]) if external else None,
                clouds=clouds,
            )
        for j in range(10):
            dept = DEPARTMENTS[(j * 3) % 7]
            iid = f"svc-{j + 1:04d}"
            self.identities[iid] = _Identity(
                identity_id=iid,
                display_name=SERVICE_NAMES[j],
                identity_type="service",
                department=dept,
                employment_type="service",
                employment_status="active",
                hire_month=rng.randint(1, 8),
                departure_month=None,
                external=False,
                mfa_enforced=False,
                tags={"project": f"nda-{dept.split()[0].lower()}-prod", "managed-by": "terraform"},
                contract_end_month=None,
                clouds=sorted(rng.sample(CLOUDS, k=rng.choice([1, 1, 2])), key=CLOUDS.index),
            )
        for ident in self.identities.values():
            for cloud in ident.clouds:
                self._add_principal(ident, cloud)
            for _ in range(rng.randint(2, 4)):
                cloud = rng.choice(ident.clouds)
                category = rng.choice(CATEGORIES[:5])
                self._add_grant(ident, cloud, category, rng.choice(["read", "read", "write"]), "resource")
                self._set_activity(ident, cloud, category, rng.randint(0, 40), rng.randint(5, 400))
            if ident.identity_type == "human" and "aws" in ident.clouds:
                self._add_credential(ident, "aws", "password", rng.randint(10, 120))
            if ident.identity_type == "service":
                self._add_credential(
                    ident, ident.clouds[0], "sa_key" if ident.clouds[0] == "gcp" else "key", 60
                )

    def _assign_rules(self) -> None:
        rng = self.rng
        humans = [
            i
            for i in self.identities.values()
            if i.identity_type == "human" and i.identity_id not in DECOY_IDS
        ]
        services = [
            i
            for i in self.identities.values()
            if i.identity_type == "service" and i.identity_id not in DECOY_IDS
        ]
        everyone = humans + services
        for ident in humans:
            if ident.employment_status == "departed":
                ident.rules.append("R3")
        plan: list[tuple[str, list[_Identity]]] = [
            ("R1", rng.sample(everyone, 8)),
            ("R2", rng.sample(everyone, 7)),
            ("R4", rng.sample(humans, 3)),
            ("R5", rng.sample(everyone, 4)),
            ("R6", rng.sample(everyone, 5)),
            ("R7", [*rng.sample(humans, 3), self.identities["emp-0008"]]),
            ("R8", rng.sample(everyone, 4)),
            ("R9", rng.sample(humans, 4)),
            ("R10", rng.sample(services, 3)),
            ("R0", rng.sample(everyone, 3)),
        ]
        for rule_id, targets in plan:
            for ident in targets:
                ident.rules.append(rule_id)
        for ident in self.identities.values():
            ident.rules = sorted(set(ident.rules), key=lambda r: int(r[1:]))

    def _decoy_rows(self) -> None:
        """Decoys look risky in the cloud data; only the register (SPEC §4.3) says they are fine."""
        for iid, (etype, _) in DECOY_EXCEPTIONS.items():
            ident = self.identities[iid]
            if etype == "break-glass":
                ident.mfa_enforced = True
                for cloud in ident.clouds[:2] or ["aws"]:
                    self._add_grant(ident, cloud, "identity", "admin", "org")
            elif etype == "approved-privileged-role":
                ident.mfa_enforced = True
                g = self._add_grant(ident, ident.clouds[0], "compute", "admin", "project")
                self._set_activity(ident, g.cloud, "compute", 3, 120)
            else:
                for a in list(ident.activity):
                    self._set_activity(ident, a.cloud, a.service_category, 330, 0)
        for iid in TIME_BOXED_CONTRACTORS:
            ident = self.identities[iid]
            ident.contract_end_month = self.month + 4
            self._add_grant(ident, ident.clouds[0], "data", "write", "project")

    # --------------------------------------------------------------- findings
    def _materialise(
        self, ident: _Identity, rule_id: str
    ) -> tuple[list[EvidenceRefOut], dict[str, Any], list[str]]:
        """Add the rows a rule needs and return (evidence, facts, causal event ids). Evidence or it did not fire."""
        rng = self.rng
        cloud = rng.choice(ident.clouds)
        ev: list[EvidenceRefOut] = []
        facts: dict[str, Any] = {
            "rule_id": rule_id,
            "display_name": ident.display_name,
            "department": ident.department,
        }
        events: list[str] = []
        if rule_id == "R0":
            g = self._add_grant(ident, cloud, "unknown", "unknown", "resource")
            g.raw_snippet = {
                "Action": "iam:PassRole" if cloud == "aws" else "Microsoft.Custom/legacy/action",
                "Resource": "*",
            }
            ev.append(EvidenceRefOut(kind="grant", ref=g.grant_id, note="no mapping in normaliser/mappings"))
            facts.update(action=str(g.raw_snippet["Action"]), cloud=cloud)
        elif rule_id == "R1":
            m = rng.randint(2, 9)
            g = self._add_grant(ident, cloud, "identity", "admin", rng.choice(["org", "global"]))
            ev.append(EvidenceRefOut(kind="grant", ref=g.grant_id, note=f"{g.verb} at {g.scope_level}"))
            trigger = rng.choice(["incident_response", "role_change"])
            events.append(
                self._event(
                    ident,
                    m,
                    "grant",
                    trigger,
                    cloud,
                    f"{cloud.upper()} admin at {g.scope_level} added ({trigger})",
                )
            )
            facts.update(cloud=cloud, scope_level=g.scope_level, since_month=m, since_label=month_label(m))
        elif rule_id == "R2":
            days = self.settings.dormant_days + rng.randint(20, 240)
            g = ident.grants[0]
            a = self._set_activity(ident, g.cloud, g.service_category, days, 0)
            last = a.last_activity_at.isoformat() if a.last_activity_at else ""
            ev.append(
                EvidenceRefOut(
                    kind="activity",
                    ref=f"{ident.identity_id}:{g.cloud}:{g.service_category}",
                    note=f"last activity {last}",
                )
            )
            ev.append(EvidenceRefOut(kind="grant", ref=g.grant_id))
            stop = max(1, self.month - days // 30)
            events.append(
                self._event(
                    ident,
                    stop,
                    "activity_stop",
                    "unknown",
                    g.cloud,
                    f"No {g.service_category} activity since {month_label(stop)}",
                )
            )
            facts.update(dormant_days=days, dormant_months=days // 30, last_activity_at=last, cloud=g.cloud)
        elif rule_id == "R3":
            dep = ident.departure_month or 9
            for g in ident.grants[:2]:
                ev.append(EvidenceRefOut(kind="grant", ref=g.grant_id, note="still active after departure"))
            ev.append(
                EvidenceRefOut(
                    kind="identity", ref=ident.identity_id, note=f"HR status departed since month {dep}"
                )
            )
            events.append(
                self._event(
                    ident,
                    dep,
                    "departure",
                    "departure",
                    None,
                    f"Left the organisation in {month_label(dep)}; access not revoked",
                )
            )
            facts.update(
                departure_month=dep,
                departure_label=month_label(dep),
                months_since=self.month - dep,
                clouds=list(ident.clouds),
            )
        elif rule_id == "R4":
            for c in CLOUDS:
                g = self._add_grant(ident, c, "identity", "admin", "org")
                ev.append(EvidenceRefOut(kind="grant", ref=g.grant_id, note=f"{c} admin"))
                events.append(
                    self._event(
                        ident,
                        rng.randint(2, 10),
                        "grant",
                        "role_change",
                        c,
                        f"{c.upper()} admin at org added (role change)",
                    )
                )
            facts.update(clouds=list(CLOUDS))
        elif rule_id == "R5":
            g1 = self._add_grant(ident, cloud, "identity", "grant", "project")
            g2 = self._add_grant(ident, cloud, "compute", "write", "project")
            ev.append(EvidenceRefOut(kind="grant", ref=g1.grant_id, note="grant on identity"))
            ev.append(EvidenceRefOut(kind="grant", ref=g2.grant_id, note="write on compute"))
            events.append(
                self._event(
                    ident,
                    rng.randint(3, 10),
                    "grant",
                    "role_change",
                    cloud,
                    "IAM grant rights added; toxic with existing compute write",
                )
            )
            facts.update(cloud=cloud, pair=["identity/grant", "compute/write"])
        elif rule_id == "R6":
            days = self.settings.stale_key_days + rng.randint(30, 400)
            cred = self._add_credential(ident, cloud, "sa_key" if cloud == "gcp" else "key", days)
            ev.append(
                EvidenceRefOut(kind="credential", ref=cred.credential_ref, note=f"rotated {days} days ago")
            )
            facts.update(credential_ref=cred.credential_ref, age_days=days, cloud=cloud)
        elif rule_id == "R7":
            for _ in range(4):
                g = self._add_grant(ident, cloud, rng.choice(CATEGORIES), "write", "project")
                ev.append(EvidenceRefOut(kind="grant", ref=g.grant_id))
            ev.append(
                EvidenceRefOut(kind="identity", ref=ident.identity_id, note=f"peer group {ident.department}")
            )
            facts.update(grant_count=len(ident.grants), peer_median=3)
        elif rule_id == "R8":
            region = UNAPPROVED_REGIONS[cloud]
            g = self._add_grant(ident, cloud, "storage", "write", "resource", region=region)
            res = f"{cloud}:storage:{region}:bucket-{ident.identity_id}"
            ev.append(EvidenceRefOut(kind="grant", ref=g.grant_id, note=f"region {region}"))
            ev.append(EvidenceRefOut(kind="resource", ref=res))
            events.append(
                self._event(
                    ident,
                    rng.randint(4, 11),
                    "region_drift",
                    "region_drift",
                    cloud,
                    f"Resource created in {region} (outside approved regions)",
                )
            )
            facts.update(
                region=region,
                resource_ref=res,
                approved_regions=list(self.settings.approved_regions),
                cloud=cloud,
            )
        elif rule_id == "R9":
            ident.mfa_enforced = False
            g = next((x for x in ident.grants if x.verb == "admin"), None) or self._add_grant(
                ident, cloud, "identity", "admin", "project"
            )
            ev.append(EvidenceRefOut(kind="grant", ref=g.grant_id, note="privileged"))
            ev.append(EvidenceRefOut(kind="identity", ref=ident.identity_id, note="mfa_enforced=false"))
            events.append(
                self._event(
                    ident,
                    rng.randint(5, 11),
                    "mfa_lapse",
                    "mfa_lapse",
                    g.cloud,
                    "MFA flag flipped off; re-registration never happened",
                )
            )
            facts.update(cloud=g.cloud, scope_level=g.scope_level)
        elif rule_id == "R10":
            p = ident.principals[0]
            ident.principals[0] = p.model_copy(
                update={"link_method": "tag_owner", "link_confidence": "heuristic"}
            )
            # SPEC? R10 fires per principal; the mock attributes it to the identity the heuristic linker guessed.
            ev.append(
                EvidenceRefOut(
                    kind="principal", ref=p.principal_ref, note="no HR owner; linked heuristically"
                )
            )
            events.append(
                self._event(
                    ident,
                    rng.randint(2, 8),
                    "project_retirement",
                    "project_retirement",
                    p.cloud,
                    "Project retired; service account survived",
                )
            )
            facts.update(principal_ref=p.principal_ref, cloud=p.cloud)
        return ev, facts, events

    def _altitudes(self, ident: _Identity, rule_id: str, facts: dict[str, Any], score: int) -> AltitudesOut:
        """Three altitudes from the same facts (SPEC §10.2 phrase table)."""
        name, dept = ident.display_name, ident.department
        headlines = {
            "R0": f"{name} ({dept}) holds a permission ATHAR could not classify.",
            "R1": f"{name} in {dept} has unrestricted control over everything in the {facts.get('cloud', 'cloud')} account.",
            "R2": f"{name} ({dept}) has not used this access in {facts.get('dormant_months', 0)} months.",
            "R3": f"{name} left the organisation in {facts.get('departure_label', '')} but can still sign in to {', '.join(facts.get('clouds', []))}.",
            "R4": f"{name} ({dept}) is an administrator in all three clouds at once.",
            "R5": f"{name} ({dept}) can give themselves any permission they want.",
            "R6": f"A credential belonging to {name} ({dept}) has not been rotated in {facts.get('age_days', 0)} days.",
            "R7": f"{name} holds far more access than peers in {dept}.",
            "R8": f"{name} ({dept}) can write data in {facts.get('region', '')}, outside the approved regions.",
            "R9": f"{name} ({dept}) is privileged without multi-factor authentication.",
            "R10": f"A cloud principal in {dept} has no accountable human owner.",
        }
        rule = self.rules[rule_id]
        explanation = (
            f"Rule {rule_id} ({rule.name}) fired at {month_label(self.month)}. "
            f"This identity can reach {facts.get('blast_radius_pct', 0.0):.0f}% of the estate with control verbs; "
            f"risk score {score}. Remediating the cited rows removes the finding and lowers the score below the "
            f"{rule.severity} floor."
        )
        return AltitudesOut(
            headline=headlines[rule_id],
            explanation=explanation,
            evidence={"facts": facts, "rules_fired": [rule_id]},
        )

    def _build_findings(self) -> None:
        for ident in self.identities.values():
            for rule_id in ident.rules:
                ev, facts, events = self._materialise(ident, rule_id)
                rule = self.rules[rule_id]
                first_seen = min([e.month for e in ident.events if e.event_id in events] or [self.month])
                key = finding_key(ident.identity_id, rule_id)
                self.findings[key] = FindingOut(
                    finding_key=key,
                    scan_id=self.month,
                    snapshot_month=self.month,
                    identity_id=ident.identity_id,
                    display_name=ident.display_name,
                    identity_type=ident.identity_type,
                    department=ident.department,
                    clouds=list(ident.clouds),
                    rule_id=rule_id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    score=0,
                    first_seen_month=first_seen,
                    status="open",
                    evidence_refs=ev,
                    causal_event_ids=sorted(events),
                    instance_hash="",
                    leaf="",
                    proof=[],
                    altitudes=AltitudesOut(headline="", explanation="", evidence={}),
                    allowed_actions=list(rule.allowed_actions),
                    attack_techniques=list(rule.attack_techniques),
                    control_refs=list(rule.control_refs),
                    facts=facts,
                )

    def _build_scores(self) -> None:
        """Every term is a line item (SPEC §8.3 transparency rule)."""
        rng = self.rng
        for ident in self.identities.values():
            privileged = any(g.verb in ("admin", "grant") for g in ident.grants)
            br = rng.uniform(0.12, 0.45) if privileged else rng.uniform(0.005, 0.08)
            high = int(br * 40)
            reach = round(min(1.0, br / REF_SHARE), 2)
            items = [
                LineItemOut(
                    term="reach",
                    label=f"reach {reach:.2f} (blast radius {br * 100:.0f}% of estate, {high} high-sensitivity resources)",
                    value=reach,
                    detail={"blast_radius": round(br, 4), "ref_share": REF_SHARE},
                )
            ]
            expl, parts = 1.0, []
            for rule_id, inc, label in (
                ("R3", 0.5, "departed"),
                ("R2", 0.3, "dormant"),
                ("R9", 0.3, "no MFA"),
                ("R6", 0.2, "stale key"),
                ("R5", 0.2, "toxic pair"),
            ):
                if rule_id in ident.rules:
                    expl += inc
                    parts.append(f"{label} +{inc}")
            items.append(
                LineItemOut(
                    term="exploitability",
                    label=f"exploitability {expl:.1f} ({', '.join(parts) or 'baseline'})",
                    value=round(expl, 2),
                )
            )
            comp = 0.8 if ident.identity_id in DECOY_EXCEPTIONS else 1.0
            items.append(
                LineItemOut(
                    term="compensating",
                    label=f"controls {comp:.1f}" + (" (valid exception in register)" if comp < 1 else ""),
                    value=comp,
                )
            )
            formula = min(100.0, round(50.0 * reach * expl * comp, 1))
            items.append(
                LineItemOut(
                    term="formula", label=f"reach × exploitability × controls = {formula:.0f}", value=formula
                )
            )
            floor = max([FLOORS[self.rules[r].severity] for r in ident.rules] or [0])
            top = max(ident.rules, key=lambda r: SEVERITY_RANK[self.rules[r].severity], default=None)
            items.append(
                LineItemOut(
                    term="floor", label=f"floor from {top} = {floor}" if top else "no rule floor", value=floor
                )
            )
            score = int(max(formula, floor))
            items.append(LineItemOut(term="final", label=f"final {score}", value=score))
            paths: list[list[PathEdgeOut]] = []
            if privileged:
                g = next(x for x in ident.grants if x.verb in ("admin", "grant"))
                role = f"{g.cloud}:role/IAMRoleManager"
                paths.append(
                    [
                        PathEdgeOut(src=ident.identity_id, verb=g.verb, dst=g.scope_ref, grant_id=g.grant_id),
                        PathEdgeOut(src=g.scope_ref, verb="assume", dst=role),
                        PathEdgeOut(src=role, verb="admin", dst=f"{g.cloud}:org"),
                    ]
                )
            ident.score = ScoreOut(
                blast_radius=round(br, 4),
                reachable_resources=int(br * 400),
                high_sensitivity_reached=high,
                reach=reach,
                exploitability=round(expl, 2),
                compensating=comp,
                formula_score=formula,
                rule_floor=floor,
                score=score,
                severity=_band(score),
                line_items=items,
                escalation_paths=paths,
            )
            self._risk_history(ident, score)
            for f in self.findings.values():
                if f.identity_id == ident.identity_id:
                    f.score = score
                    f.facts["blast_radius_pct"] = round(br * 100, 1)
                    f.altitudes = self._altitudes(ident, f.rule_id, f.facts, score)

    def _risk_history(self, ident: _Identity, final: int) -> None:
        base = self.rng.randint(4, 18)
        events = sorted(ident.events, key=lambda e: e.month)
        points: list[RiskPoint] = []
        for m in range(1, self.month + 1):
            if m == self.month:
                score = final
            elif events:
                passed = sum(1 for e in events if e.month <= m)
                score = min(final, base + int((final - base) * passed / len(events)))
            else:
                score = min(final, base)
            points.append(
                RiskPoint(
                    month=m, score=score, severity=_band(score), events=[e for e in events if e.month == m]
                )
            )
        ident.risk_history = points

    def _build_exceptions(self) -> None:
        end = month_end(self.month)
        for n, (iid, (etype, why)) in enumerate(DECOY_EXCEPTIONS.items(), start=1):
            self.exceptions.append(
                ExceptionOut(
                    exception_id=f"exc-{n:04d}",
                    identity_id=iid,
                    exception_type=etype,
                    approved_by=f"ciso@{EMAIL_DOMAIN}",
                    approved_on=end - timedelta(days=200),
                    review_date=end + timedelta(days=60),
                    expires_on=end + timedelta(days=180),
                    justification=why,
                    source="register",
                    valid=True,
                )
            )
        self.exceptions.append(
            ExceptionOut(
                exception_id=f"exc-{len(self.exceptions) + 1:04d}",
                identity_id="emp-0023",
                exception_type="time-boxed",
                approved_by=f"ciso@{EMAIL_DOMAIN}",
                approved_on=end - timedelta(days=400),
                review_date=end - timedelta(days=100),
                expires_on=end - timedelta(days=30),
                justification="Expired time-boxed elevation (kept for audit; no longer suppresses anything)",
                source="register",
                valid=False,
            )
        )

    # ------------------------------------------------------------------ scans
    def _build_scans(self) -> None:
        for m in range(1, self.month + 1):
            started = MOCK_NOW - timedelta(days=(self.month - m) * 30)
            self.scans.append(
                ScanOut(
                    scan_id=m,
                    snapshot_month=m,
                    ruleset_hash=self.ruleset,
                    started_at=started,
                    finished_at=started + timedelta(seconds=7),
                    finding_count=int(len(self.findings) * m / self.month),
                    merkle_root=keccak256_hex(f"mock|root|{m}".encode()),
                    snapshot_hash=keccak256_hex(f"mock|snapshot|{m}".encode()),
                    ledger_scan_index=m - 1,
                    ledger_tx=self._tx(),
                    ledger_status="anchored",
                )
            )
        self._commit_current_scan(self.scans[-1])

    def _commit_current_scan(self, scan: ScanOut) -> None:
        """Recompute instance hashes, leaves and proofs for the current findings (SPEC §10.1, §12.3)."""
        leaves: dict[str, bytes] = {}
        for f in self.findings.values():
            f.scan_id, f.snapshot_month = scan.scan_id, scan.snapshot_month
            inst = finding_instance(
                finding_key=f.finding_key,
                identity_id=f.identity_id,
                rule_id=f.rule_id,
                severity=f.severity,
                score=f.score,
                snapshot_month=f.snapshot_month,
                first_seen_month=f.first_seen_month,
                evidence_refs=[f"{e.kind}:{e.ref}" for e in f.evidence_refs],
                causal_event_ids=list(f.causal_event_ids),
            )
            f.instance_hash = instance_hash(inst)
            f.facts["instance"] = inst
            leaves[f.finding_key] = merkle.leaf_from_instance_hash(f.instance_hash)
        all_leaves = list(leaves.values())
        root_hex = merkle.to_hex(merkle.root(all_leaves)) if all_leaves else None
        for f in self.findings.values():
            f.leaf = merkle.to_hex(leaves[f.finding_key])
            f.proof = [merkle.to_hex(p) for p in merkle.proof(all_leaves, leaves[f.finding_key])]
            f.altitudes.evidence["ledger"] = {
                "leaf": f.leaf,
                "scan_id": scan.scan_id,
                "merkle_root": root_hex,
            }
        scan.finding_count = len(self.findings)
        scan.merkle_root = root_hex

    def _new_scan(self, month: int, status: ScanLedgerStatus) -> ScanOut:
        prev = self.scans[-1]
        n = prev.scan_id + 1
        started = MOCK_NOW + timedelta(minutes=n)
        anchored = status == "anchored"
        scan = ScanOut(
            scan_id=n,
            snapshot_month=month,
            ruleset_hash=self.ruleset,
            started_at=started,
            finished_at=started + timedelta(seconds=5),
            finding_count=len(self.findings),
            merkle_root=None,
            snapshot_hash=keccak256_hex(f"mock|snapshot|{month}".encode()),
            ledger_scan_index=(prev.ledger_scan_index or 0) + (1 if anchored else 0),
            ledger_tx=self._tx() if anchored else prev.ledger_tx,
            ledger_status=status,
        )
        self.scans.append(scan)
        self._commit_current_scan(scan)
        return scan

    # ------------------------------------------------------- plans / agents
    def _build_plans(self) -> None:
        by_rule = {r: [f for f in self.findings.values() if f.rule_id == r] for r in self.rules}
        picks: list[tuple[FindingOut, ProposedBy, str | None, PlanStatus]] = [
            (by_rule["R3"][0], "model", None, "proposed"),  # any approver may approve
            (by_rule["R1"][0], "rule", "usr-approver", "proposed"),  # SoD: usr-approver may NOT approve
            (by_rule["R1"][1], "rule", "usr-analyst", "approved"),  # ready to apply
            (by_rule["R2"][0], "model", None, "applied"),
            (by_rule["R5"][0], "model", None, "rejected"),
        ]
        for n, (f, by, proposer, status) in enumerate(picks, start=1):
            plan = self._make_plan(f, f"plan-{n:04d}", by, proposer, MOCK_NOW - timedelta(days=6 - n))
            plan.status = status
            self.plans[plan.plan_id] = plan
            f.plan = plan
            if status == "approved":
                self._decide(plan, "approved", "usr-approver")
                f.status = "approved"
            elif status == "applied":
                self._decide(plan, "approved", "usr-approver")
                self._decide(plan, "remediation_applied", "usr-approver")
                f.status = "remediated"
            elif status == "rejected":
                self._decide(plan, "rejected", "usr-approver")
                f.status = "open"
            else:
                f.status = "remediation_proposed"
        for f in by_rule["R9"][:2]:
            f.investigation = self._make_investigation(f, cached=True)
            self.investigations[f.finding_key] = f.investigation
            if f.status == "open":
                f.status = "investigated"
        exc_f = by_rule["R7"][0]
        exc = ExceptionOut(
            exception_id=f"exc-{len(self.exceptions) + 1:04d}",
            identity_id=exc_f.identity_id,
            exception_type="approved-privileged-role",
            approved_by="usr-approver",
            approved_on=MOCK_NOW.date(),
            review_date=MOCK_NOW.date() + timedelta(days=90),
            expires_on=None,
            justification="Approved data-platform role, reviewed quarterly",
            source="workflow",
            valid=True,
        )
        self.exceptions.append(exc)
        exc_f.exception, exc_f.status = exc, "exception_granted"
        self._record_exception_decision(exc_f, exc, "usr-approver", f"approver@{DEMO_DOMAIN}")

    def _make_plan(
        self, f: FindingOut, plan_id: str, by: ProposedBy, proposer: str | None, at: datetime
    ) -> RemediationPlanOut:
        """Least-privilege diff computed deterministically (SPEC §11.4 fallback path, §11.5 fields)."""
        ident = self.identities[f.identity_id]
        cited = [e.ref for e in f.evidence_refs if e.kind == "grant"]
        drop = cited[:1] or [ident.grants[0].grant_id]
        keep = [g.grant_id for g in ident.grants if g.grant_id not in drop and g.verb == "read"]
        action: Action = (
            "disable_identity"
            if f.rule_id == "R3"
            else "rotate_or_disable_credential"
            if f.rule_id == "R6"
            else "revoke_grant"
        )
        g = next((x for x in ident.grants if x.grant_id in drop), ident.grants[0])
        if action == "disable_identity":
            diff = PolicyDiffOut(
                cloud=g.cloud,
                before={
                    "UserName": _slug(ident.display_name),
                    "LoginProfile": {"PasswordResetRequired": False},
                    "Enabled": True,
                },
                after={"UserName": _slug(ident.display_name), "LoginProfile": None, "Enabled": False},
                operations=[
                    PolicyOperation(
                        op="disable_login",
                        target=g.principal_ref,
                        detail="delete console login profile / disable Entra user",
                    )
                ],
                summary=f"Disable {ident.display_name}; departed {f.facts.get('departure_label', '')}",
            )
        else:
            op = {
                "aws": "detach_managed_policy",
                "azure": "delete_role_assignment",
                "gcp": "remove_binding_member",
            }[g.cloud]
            diff = PolicyDiffOut(
                cloud=g.cloud,
                before={"principal": g.principal_ref, "attached": [g.granted_via]},
                after={"principal": g.principal_ref, "attached": []},
                operations=[PolicyOperation(op=op, target=g.granted_via, detail=f"scope {g.scope_ref}")],
                summary=f"Remove {g.granted_via} from {g.principal_ref}",
            )
        reduction = round(100.0 * len(drop) / max(1, len(ident.grants)), 1)
        blast = ident.score.blast_radius if ident.score else 0.0
        return RemediationPlanOut(
            plan_id=plan_id,
            finding_key=f.finding_key,
            scan_id=f.scan_id,
            identity_id=ident.identity_id,
            display_name=ident.display_name,
            rule_id=f.rule_id,
            action=action,
            params={"grant_ids": drop} if action == "revoke_grant" else {},
            policy_diff=diff,
            keep=keep,
            drop=drop,
            privilege_reduction_pct=reduction,
            expected_blast_radius_after=round(blast * (1 - reduction / 100), 4),
            proposed_by=by,
            proposer_user_id=proposer,
            model_id=None,
            prompt_version=PROMPT_VERSION,
            rationale=f"Least-privilege diff: drop {len(drop)} grant(s) cited by {f.rule_id}; keep {len(keep)} read grant(s) used in the last 90 days.",
            confidence=0.82 if by == "model" else 1.0,
            status="proposed",
            created_at=at,
            decisions=[],
        )

    def _make_investigation(self, f: FindingOut, cached: bool) -> InvestigationOut:
        ident = self.identities[f.identity_id]
        steps = (
            "; ".join(e.description for e in sorted(ident.events, key=lambda e: e.month))
            or "no causal events recorded"
        )
        return InvestigationOut(
            finding_key=f.finding_key,
            hypothesis=f"{f.rule_name} on {ident.display_name}: {steps}.",
            is_expected_for_role=ident.identity_id in DECOY_IDS,
            evidence_cited=[f"{e.kind}:{e.ref}" for e in f.evidence_refs],
            confidence=0.7,
            recommended_action=f.allowed_actions[0],
            rationale="Template from causal history (no model configured in mock mode).",
            model_id=None,
            prompt_version=PROMPT_VERSION,
            cached=cached,
            generated_by="template",
        )

    def _decide(self, plan: RemediationPlanOut, kind: DecisionKind, actor: str) -> DecisionOut:
        n = len(self.decisions) + 1
        evidence = keccak256_hex(
            canonical_json(
                {
                    "plan_id": plan.plan_id,
                    "action": plan.action,
                    "model_id": plan.model_id,
                    "prompt_version": plan.prompt_version,
                    "rationale_hash": keccak256_hex(plan.rationale.encode()),
                }
            )
        )
        d = DecisionOut(
            decision_id=f"dec-{n:04d}",
            plan_id=plan.plan_id,
            finding_key=plan.finding_key,
            scan_id=plan.scan_id,
            decision=kind,
            actor_user_id=actor,
            actor_email=f"{actor.removeprefix('usr-')}@{DEMO_DOMAIN}",
            evidence_hash=evidence,
            ledger_tx=self._tx(),
            ledger_status="anchored",
            created_at=MOCK_NOW - timedelta(days=1) + timedelta(minutes=n),
        )
        self.decisions.append(d)
        plan.decisions.append(d)
        return d

    def _record_exception_decision(
        self, f: FindingOut, exc: ExceptionOut, actor: str, email: str
    ) -> DecisionOut:
        n = len(self.decisions) + 1
        d = DecisionOut(
            decision_id=f"dec-{n:04d}",
            plan_id=None,
            finding_key=f.finding_key,
            scan_id=f.scan_id,
            decision="exception_granted",
            actor_user_id=actor,
            actor_email=email,
            evidence_hash=keccak256_hex(
                canonical_json({"exception_id": exc.exception_id, "type": exc.exception_type})
            ),
            ledger_tx=self._tx(),
            ledger_status="anchored",
            created_at=MOCK_NOW + timedelta(minutes=n),
        )
        self.decisions.append(d)
        return d

    # ------------------------------------------------------ drift / eval
    def _build_halflife_and_timeline(self) -> None:
        rng = self.rng
        for dept in DEPARTMENTS:
            for trigger in ("all", "departure", "role_change"):
                grants = rng.randint(20, 80)
                never = (
                    dept == "Finance" or rng.random() < 0.2
                )  # Finance: "offboarding half-life: Never" (SPEC §14)
                revocations = (
                    rng.randint(0, int(grants * 0.09)) if never else rng.randint(int(grants * 0.15), grants)
                )
                hl = None if never else round(rng.uniform(1.5, 11.0), 1)
                self.halflife_rows.append(
                    HalfLifeOut(
                        department=dept,
                        trigger=trigger,
                        grants=grants,
                        revocations=revocations,
                        half_life_months=hl,
                        label=_hl_label(hl),
                    )
                )
        final = self._severity_counts(list(self.findings.values()))
        for m in range(1, self.month + 1):
            share = m / self.month
            half_life: dict[str, float | None] = {}
            for d in DEPARTMENTS:
                h = self._offboarding(d)
                half_life[d] = None if h is None else round(max(1.0, h - (self.month - m) * 0.2), 1)
            self.timeline_points.append(
                TimelinePoint(
                    month=m,
                    month_label=month_label(m),
                    identity_count=28 + m,
                    findings_by_severity={s: int(final[s] * share) for s in SEVERITIES},
                    median_score=round(8 + 22 * share + rng.uniform(-2, 2), 1),
                    half_life=half_life,
                )
            )

    def _offboarding(self, dept: str) -> float | None:
        return next(
            r.half_life_months
            for r in self.halflife_rows
            if r.department == dept and r.trigger == "departure"
        )

    def _build_eval(self) -> EvalOut:
        rng = self.rng
        per_rule: list[RuleEval] = []
        tp = fp = fn = 0
        for rule_id in list(self.rules)[1:]:
            t, p, n = rng.randint(2, 7), rng.choice([0, 0, 1, 1, 2]), rng.choice([0, 0, 0, 1])
            tp, fp, fn = tp + t, fp + p, fn + n
            per_rule.append(
                RuleEval(
                    rule_id=rule_id,
                    tp=t,
                    fp=p,
                    fn=n,
                    precision=round(t / (t + p), 3) if t + p else None,
                    recall=round(t / (t + n), 3) if t + n else None,
                )
            )
        precision, recall = tp / (tp + fp), tp / (tp + fn)
        f1 = 2 * precision * recall / (precision + recall)
        decoys: list[DecoyEval] = []
        for iid in DECOY_IDS:
            ident = self.identities[iid]
            exc = next((e for e in self.exceptions if e.identity_id == iid), None)
            etype = exc.exception_type if exc else "time-boxed"
            why = (
                exc.justification
                if exc
                else f"HR contract_end in month {ident.contract_end_month}; the HR feed is the record"
            )
            flagged = next((f.severity for f in self.findings.values() if f.identity_id == iid), None)
            decoys.append(
                DecoyEval(
                    identity_id=iid,
                    display_name=ident.display_name,
                    looks_like=LOOKS_LIKE[etype],
                    why_legitimate=why,
                    flagged_at=flagged,
                    correctly_handled=flagged is None or SEVERITY_RANK[flagged] <= 1,
                )
            )
        seed = self.settings.athar_eval_seed
        return EvalOut(
            seed=seed,
            held_out=True,
            precision=round(precision, 3),
            recall=round(recall, 3),
            f1=round(f1, 3),
            tp=tp,
            fp=fp,
            fn=fn,
            per_rule=per_rule,
            decoys=decoys,
            director_sentence=f"Of {tp + fp} accounts flagged, {tp} are verified genuine risks; {fp} are known exceptions the system now recognises.",
            engineer_sentence=f"precision {precision:.2f} / recall {recall:.2f} / F1 {f1:.2f} at High+ on held-out seed {seed} (tp {tp}, fp {fp}, fn {fn})",
            generated_from="mock",
        )

    # --------------------------------------------------------------- helpers
    @staticmethod
    def _severity_counts(findings: list[FindingOut]) -> dict[Severity, int]:
        out: dict[Severity, int] = {s: 0 for s in SEVERITIES}
        for f in findings:
            out[f.severity] += 1
        return out

    @staticmethod
    def _page(items: list[M], filters: ListFilters) -> Page[M]:
        window = items[filters.offset : filters.offset + filters.limit]
        return Page[M](items=window, total=len(items), limit=filters.limit, offset=filters.offset)

    @staticmethod
    def _sort(items: list[M], sort: str | None, allowed: tuple[str, ...], default: str) -> list[M]:
        spec = sort or default
        desc, fld = spec.startswith("-"), spec.lstrip("-")
        if fld not in allowed:
            raise InvalidInputError("sort.unknown_field", f"Cannot sort by '{fld}'; one of {sorted(allowed)}")

        def key(m: M) -> tuple[bool, Any]:
            v = getattr(m, fld)
            if fld == "severity":
                v = SEVERITY_RANK[v]
            return (v is None, 0 if v is None else v)

        return sorted(items, key=key, reverse=desc)

    @staticmethod
    def _matches(value: str, wanted: str | None) -> bool:
        return wanted is None or value.lower() == wanted.lower()

    def _row(self, ident: _Identity) -> IdentityRow:
        fs = [f for f in self.findings.values() if f.identity_id == ident.identity_id]
        top = max(fs, key=lambda f: (SEVERITY_RANK[f.severity], f.score), default=None)
        last = max((a.last_activity_at for a in ident.activity if a.last_activity_at), default=None)
        sc = ident.score
        return IdentityRow(
            identity_id=ident.identity_id,
            display_name=ident.display_name,
            identity_type=ident.identity_type,
            department=ident.department,
            clouds=list(ident.clouds),
            score=sc.score if sc else 0,
            severity=sc.severity if sc else "Low",
            top_rule=top.rule_id if top else None,
            top_rule_name=top.rule_name if top else None,
            blast_radius_pct=round((sc.blast_radius if sc else 0.0) * 100, 1),
            last_activity_at=last,
            status=ident.employment_status,
            finding_count=len(fs),
            external=ident.external,
            mfa_enforced=ident.mfa_enforced,
        )

    def _ledger_badge(self) -> LedgerBadge:
        last = self.scans[-1]
        if not self.settings.ledger_enabled:
            return LedgerBadge(status="disabled", last_scan_id=last.scan_id, last_root=last.merkle_root)
        status = BADGE_FOR_SCAN.get(last.ledger_status, "unanchored")
        return LedgerBadge(
            status=status,
            last_scan_id=last.scan_id,
            last_root=last.merkle_root,
            last_tx=last.ledger_tx,
            chain_id=MOCK_CHAIN_ID,
        )

    def _rollups(self) -> list[DepartmentRollup]:
        out: list[DepartmentRollup] = []
        for dept in DEPARTMENTS:
            fs = [f for f in self.findings.values() if f.department == dept]
            c = self._severity_counts(fs)
            hl = self._offboarding(dept)
            out.append(
                DepartmentRollup(
                    department=dept,
                    identities=sum(1 for i in self.identities.values() if i.department == dept),
                    findings=len(fs),
                    critical=c["Critical"],
                    high=c["High"],
                    medium=c["Medium"],
                    low=c["Low"],
                    offboarding_half_life=hl,
                    half_life_label=_hl_label(hl),
                )
            )
        return out

    def _summary_text(self, cached: bool) -> SummaryOut:
        """Aggregate stats only — names never reach the summary (SPEC §11.4)."""
        counts = self._severity_counts(list(self.findings.values()))
        rollups = self._rollups()
        worst = max(rollups, key=lambda r: r.critical + r.high)
        never = [r.department for r in rollups if r.offboarding_half_life is None]
        text = (
            f"At {month_label(self.month)} ATHAR tracks {len(self.identities)} identities across three clouds and holds "
            f"{len(self.findings)} governance findings ({counts['Critical']} critical, {counts['High']} high). "
            f"{worst.department} carries the largest share of critical and high findings. "
            f"Offboarding never completes in {', '.join(never) or 'no department'}; departed staff retain cloud access for months. "
            f"{len(self.plans)} remediation plans are in the queue; every scan and decision is anchored to the governance ledger."
        )
        themes = ["Orphaned access after departure", "Standing admin without MFA", "Cross-cloud superusers"]
        return SummaryOut(
            summary_paragraph=text,
            top_themes=themes,
            model_id=None,
            prompt_version=PROMPT_VERSION,
            cached=cached,
            generated_by="template",
        )

    # ----------------------------------------------------------------- reads
    def current_month(self) -> int | None:
        return self.month

    def estate_summary(self) -> EstateSummary:
        scores = sorted(i.score.score if i.score else 0 for i in self.identities.values())
        mid = len(scores) // 2
        median = float(scores[mid]) if len(scores) % 2 else (scores[mid - 1] + scores[mid]) / 2
        by_cloud: dict[Cloud, int] = {c: 0 for c in CLOUDS}
        for f in self.findings.values():
            for c in f.clouds:
                by_cloud[c] += 1
        return EstateSummary(
            current_month=self.month,
            current_month_label=month_label(self.month),
            identity_count=len(self.identities),
            humans=sum(1 for i in self.identities.values() if i.identity_type == "human"),
            services=sum(1 for i in self.identities.values() if i.identity_type == "service"),
            findings_total=len(self.findings),
            findings_by_severity=self._severity_counts(list(self.findings.values())),
            findings_by_cloud=by_cloud,
            findings_by_department=self._rollups(),
            median_score=median,
            ledger=self._ledger_badge(),
            executive_summary=self._summary_text(cached=True).summary_paragraph,
            model_id=None,
            scan_id=self.scans[-1].scan_id,
        )

    def list_identities(self, filters: ListFilters) -> Page[IdentityRow]:
        rows = [self._row(i) for i in self.identities.values()]
        with_rule = (
            {f.identity_id for f in self.findings.values() if f.rule_id == filters.rule}
            if filters.rule
            else None
        )
        q = filters.q.lower() if filters.q else None
        rows = [
            r
            for r in rows
            if (filters.cloud is None or filters.cloud in r.clouds)
            and self._matches(r.department, filters.department)
            and (with_rule is None or r.identity_id in with_rule)
            and (filters.severity is None or r.severity == filters.severity)
            and (filters.status is None or r.status == filters.status)
            and (q is None or q in r.display_name.lower() or q in r.identity_id.lower())
        ]
        allowed = (
            "score",
            "severity",
            "display_name",
            "department",
            "blast_radius_pct",
            "last_activity_at",
            "finding_count",
            "identity_id",
            "status",
        )
        return self._page(self._sort(rows, filters.sort, allowed, "-score"), filters)

    def identity_detail(self, identity_id: str) -> IdentityDetail | None:
        ident = self.identities.get(identity_id)
        if ident is None:
            return None
        row = self._row(ident)
        fs = sorted(
            (f for f in self.findings.values() if f.identity_id == identity_id),
            key=lambda f: (-SEVERITY_RANK[f.severity], f.rule_id),
        )
        top = fs[0] if fs else None
        return IdentityDetail(
            identity_id=ident.identity_id,
            display_name=ident.display_name,
            identity_type=ident.identity_type,
            department=ident.department,
            employment_type=ident.employment_type,
            employment_status=ident.employment_status,
            hire_month=ident.hire_month,
            departure_month=ident.departure_month,
            external=ident.external,
            mfa_enforced=ident.mfa_enforced,
            tags=ident.tags,
            contract_end_month=ident.contract_end_month,
            first_seen_month=ident.hire_month or 1,
            last_seen_month=self.month,
            clouds=list(ident.clouds),
            score=ident.score,
            severity=row.severity,
            blast_radius_pct=row.blast_radius_pct,
            last_activity_at=row.last_activity_at,
            top_finding_key=top.finding_key if top else None,
            grants=list(ident.grants),
            activity=list(ident.activity),
            credentials=list(ident.credentials),
            findings=fs,
            causal_history=sorted(ident.events, key=lambda e: (e.month, e.event_id)),
            risk_history=list(ident.risk_history),
            exceptions=[e for e in self.exceptions if e.identity_id == identity_id],
            altitudes=top.altitudes if top else None,
            principals=list(ident.principals),
        )

    def _filter_findings(self, filters: ListFilters) -> list[FindingOut]:
        q = filters.q.lower() if filters.q else None
        fs = [
            f
            for f in self.findings.values()
            if (filters.cloud is None or filters.cloud in f.clouds)
            and self._matches(f.department, filters.department)
            and (filters.rule is None or f.rule_id == filters.rule)
            and (filters.severity is None or f.severity == filters.severity)
            and (filters.month is None or f.snapshot_month == filters.month)
            and (filters.status is None or f.status == filters.status)
            and (q is None or q in f.display_name.lower() or q in f.identity_id.lower())
        ]
        allowed = (
            "score",
            "severity",
            "rule_id",
            "first_seen_month",
            "display_name",
            "department",
            "status",
            "finding_key",
        )
        return self._sort(fs, filters.sort, allowed, "-score")

    def list_findings(self, filters: ListFilters) -> Page[FindingOut]:
        return self._page(self._filter_findings(filters), filters)

    def finding(self, finding_key: str) -> FindingOut | None:
        return self.findings.get(finding_key)

    def halflife(self) -> HalfLifeTable:
        return HalfLifeTable(month=self.month, rows=list(self.halflife_rows))

    def timeline(self) -> TimelineOut:
        return TimelineOut(current_month=self.month, points=list(self.timeline_points))

    def list_scans(self, filters: ListFilters) -> Page[ScanOut]:
        scans = [
            s
            for s in self.scans
            if (filters.month is None or s.snapshot_month == filters.month)
            and (filters.status is None or s.ledger_status == filters.status)
        ]
        allowed = ("scan_id", "snapshot_month", "finding_count", "started_at", "ledger_status")
        return self._page(self._sort(scans, filters.sort, allowed, "-scan_id"), filters)

    def scan(self, scan_id: int) -> ScanOut | None:
        return next((s for s in self.scans if s.scan_id == scan_id), None)

    # ------------------------------------------------------------------ runs
    def run_scan(self, month: int | None, user: AuthUser) -> ScanOut:
        target = month or self.month
        if target > self.month:
            raise InvalidInputError("scan.month_not_ingested", f"Month {target} has not been ingested")
        # Same snapshot, same root, same ruleset → one ledger commit (SPEC §12.4 idempotency).
        return self._new_scan(target, "already_anchored" if target == self.month else "anchored")

    def upload(
        self, provider: UploadProvider, month: int, files: list[UploadedFile], user: AuthUser
    ) -> UploadResult:
        out: list[UploadedFileOut] = []
        warnings: list[str] = []
        for f in files:
            rows = 0
            try:
                text = f.content.decode("utf-8")
                if f.filename.endswith(".json"):
                    parsed = json.loads(text)
                    rows = len(parsed) if isinstance(parsed, list | dict) else 0
                else:
                    rows = max(0, text.count("\n") - 1)
            except UnicodeDecodeError:
                warnings.append(f"{f.filename}: not UTF-8; ignored")
            except json.JSONDecodeError:
                warnings.append(f"{f.filename}: malformed JSON; ignored")
            out.append(UploadedFileOut(filename=f.filename, bytes=len(f.content), rows=rows))
        return UploadResult(provider=provider, month=month, files=out, warnings=warnings, unmapped=0)

    def advance(self, user: AuthUser) -> AdvanceResult:
        self.month += 1
        for ident in self.identities.values():
            if ident.score:
                ident.risk_history.append(
                    RiskPoint(month=self.month, score=ident.score.score, severity=ident.score.severity)
                )
        last = self.timeline_points[-1]
        self.timeline_points.append(
            last.model_copy(update={"month": self.month, "month_label": month_label(self.month)})
        )
        return AdvanceResult(new_month=self.month, scan=self._new_scan(self.month, "anchored"))

    def investigate(self, finding_key: str, regenerate: bool, user: AuthUser) -> InvestigationOut | None:
        f = self.findings.get(finding_key)
        if f is None:
            return None
        cached = self.investigations.get(finding_key)
        if cached is not None and not regenerate:
            return cached.model_copy(update={"cached": True})
        inv = self._make_investigation(f, cached=False)
        self.investigations[finding_key] = inv
        f.investigation = inv
        if f.status == "open":
            f.status = "investigated"
        return inv

    def plan(self, finding_key: str, regenerate: bool, user: AuthUser) -> RemediationPlanOut | None:
        f = self.findings.get(finding_key)
        if f is None:
            return None
        if f.plan is not None and not regenerate:
            return f.plan
        plan = self._make_plan(
            f,
            f"plan-{len(self.plans) + 1:04d}",
            "rule",
            user.user_id,
            MOCK_NOW + timedelta(minutes=len(self.plans)),
        )
        self.plans[plan.plan_id] = plan
        f.plan = plan
        if f.status in ("open", "investigated", "rejected"):
            f.status = "remediation_proposed"
        return plan

    def summary(self, regenerate: bool, user: AuthUser) -> SummaryOut:
        return self._summary_text(cached=not regenerate)

    # ------------------------------------------------------------- decisions
    def list_plans(self, filters: ListFilters) -> Page[RemediationPlanOut]:
        q = filters.q.lower() if filters.q else None
        plans = [
            p
            for p in self.plans.values()
            if (filters.status is None or p.status == filters.status)
            and (filters.rule is None or p.rule_id == filters.rule)
            and self._matches(self.identities[p.identity_id].department, filters.department)
            and (q is None or q in p.display_name.lower())
        ]
        allowed = ("created_at", "status", "confidence", "plan_id", "display_name", "privilege_reduction_pct")
        return self._page(self._sort(plans, filters.sort, allowed, "-created_at"), filters)

    def get_plan(self, plan_id: str) -> RemediationPlanOut | None:
        return self.plans.get(plan_id)

    def _require_plan(self, plan_id: str, *states: str) -> RemediationPlanOut:
        plan = self.plans.get(plan_id)
        if plan is None:
            raise InvalidInputError("plan.not_found", "plan not found")
        if plan.status not in states:
            raise ConflictError(
                "plan.invalid_state", f"Plan is {plan.status}; expected one of {sorted(states)}"
            )
        return plan

    def approve(self, plan_id: str, user: AuthUser) -> RemediationPlanOut:
        plan = self._require_plan(plan_id, "proposed")
        plan.status = "approved"
        self._decide(plan, "approved", user.user_id)
        self.findings[plan.finding_key].status = "approved"
        return plan

    def reject(self, plan_id: str, user: AuthUser, reason: str) -> RemediationPlanOut:
        plan = self._require_plan(plan_id, "proposed", "approved")
        plan.status = "rejected"
        plan.params = {**plan.params, "rejection_reason": reason}
        self._decide(plan, "rejected", user.user_id)
        self.findings[plan.finding_key].status = "open"  # rejected returns the finding to open (SPEC §10.3)
        return plan

    def apply(self, plan_id: str, user: AuthUser) -> ApplyResult:
        plan = self._require_plan(plan_id, "approved")
        f = self.findings[plan.finding_key]
        ident = self.identities[f.identity_id]
        before = f.score
        for g in ident.grants:
            if g.grant_id in plan.drop:
                g.active = False
        plan.status = "applied"
        self._decide(plan, "remediation_applied", user.user_id)
        f.status = "remediated"
        if ident.score:
            after = max(0, int(ident.score.score * (1 - plan.privilege_reduction_pct / 100)))
            ident.score = ident.score.model_copy(update={"score": after, "severity": _band(after)})
            for x in self.findings.values():
                if x.identity_id == ident.identity_id:
                    x.score = after
        scan = self._new_scan(self.month, "anchored")
        return ApplyResult(
            plan=plan, finding=f, score_before=before, score_after=f.score, scan_id=scan.scan_id
        )

    def grant_exception(self, finding_key: str, user: AuthUser, body: ExceptionRequest) -> FindingOut | None:
        f = self.findings.get(finding_key)
        if f is None:
            return None
        exc = ExceptionOut(
            exception_id=f"exc-{len(self.exceptions) + 1:04d}",
            identity_id=f.identity_id,
            exception_type=body.exception_type,
            approved_by=user.user_id,
            approved_on=MOCK_NOW.date(),
            review_date=body.review_date,
            expires_on=body.expires_on,
            justification=body.justification,
            source="workflow",
            valid=body.expires_on is None or body.expires_on >= month_end(self.month),
        )
        self.exceptions.append(exc)
        f.exception, f.status = exc, "exception_granted"
        self._record_exception_decision(f, exc, user.user_id, user.email)
        return f

    # ---------------------------------------------------------------- ledger
    def ledger_info(self) -> LedgerInfo:
        return LedgerInfo(
            enabled=self.settings.ledger_enabled,
            contract_address=MOCK_CONTRACT,
            chain_id=MOCK_CHAIN_ID,
            writer_address=MOCK_WRITER,
            purpose=(
                "Defends against post-hoc alteration of findings or decisions in the scanner's own database, "
                "and disputes about when a finding existed or who approved a revocation."
            ),
            limits=(
                "Does not defend against a compromised API host holding the writer key. "
                "Production path: HSM-backed key, per-approver wallets, permissioned chain."
            ),
            what_is_on_chain=[
                "Merkle root of finding instances per scan",
                "snapshot hash and ruleset hash",
                "finding count and timestamp",
                "decision code, actor hash, evidence hash, finding leaf",
            ],
            what_is_not_on_chain=[
                "identity names, emails or principals",
                "grants, policies or any IAM data",
                "narratives or LLM output",
                "plan contents (only their hash)",
            ],
        )

    def ledger_scans(self, filters: ListFilters) -> Page[LedgerScanOut]:
        rows = [
            LedgerScanOut(
                scan_id=s.scan_id,
                snapshot_month=s.snapshot_month,
                merkle_root=s.merkle_root,
                snapshot_hash=s.snapshot_hash,
                ruleset_hash=s.ruleset_hash,
                finding_count=s.finding_count,
                ledger_scan_index=s.ledger_scan_index,
                ledger_tx=s.ledger_tx,
                ledger_status=s.ledger_status,
                block_number=(100 + 7 * s.scan_id) if s.ledger_tx else None,
                chain_root=s.merkle_root if s.ledger_status in ("anchored", "already_anchored") else None,
                timestamp=int(s.started_at.timestamp()) if s.ledger_tx else None,
            )
            for s in self.scans
            if (filters.month is None or s.snapshot_month == filters.month)
            and (filters.status is None or s.ledger_status == filters.status)
        ]
        allowed = ("scan_id", "snapshot_month", "finding_count", "ledger_status")
        return self._page(self._sort(rows, filters.sort, allowed, "-scan_id"), filters)

    def ledger_verify(self, scan_id: int) -> LedgerVerifyOut | None:
        scan = self.scan(scan_id)
        if scan is None:
            return None
        if scan.scan_id == self.scans[-1].scan_id:
            leaves = [merkle.leaf_from_instance_hash(f.instance_hash) for f in self.findings.values()]
            computed = merkle.to_hex(merkle.root(leaves)) if leaves else None
        else:
            computed = scan.merkle_root  # SPEC? the mock keeps no per-scan finding rows for historical scans
        passed = computed == scan.merkle_root
        return LedgerVerifyOut(
            scan_id=scan_id,
            passed=passed,
            computed_root=computed,
            chain_root=scan.merkle_root,
            scan_index=scan.ledger_scan_index,
            finding_count=scan.finding_count,
            detail="PASS: recomputed root matches getCommit(scanIndex).findingsRoot"
            if passed
            else "FAIL: recomputed root differs from the chain",
        )

    def ledger_decisions(self, filters: ListFilters) -> Page[LedgerDecisionOut]:
        rows = [
            LedgerDecisionOut(
                decision_id=d.decision_id,
                plan_id=d.plan_id,
                finding_key=d.finding_key,
                scan_id=d.scan_id,
                decision=d.decision,
                decision_code=DECISION_CODES[d.decision],
                actor_user_id=d.actor_user_id,
                actor_hash=keccak256_hex(d.actor_user_id.encode()),
                evidence_hash=d.evidence_hash,
                leaf=self.findings[d.finding_key].leaf if d.finding_key in self.findings else None,
                ledger_tx=d.ledger_tx,
                ledger_status=d.ledger_status,
                created_at=d.created_at,
            )
            for d in self.decisions
            if filters.status is None or filters.status in (d.decision, d.ledger_status)
        ]
        allowed = ("created_at", "decision", "scan_id", "decision_id")
        return self._page(self._sort(rows, filters.sort, allowed, "-created_at"), filters)

    # ------------------------------------------------------ eval / exports
    def eval_result(self) -> EvalOut:
        return self.eval

    @staticmethod
    def _escape(cell: Any) -> str:
        s = "" if cell is None else str(cell)
        return "'" + s if s[:1] in ("=", "+", "-", "@") else s  # SPEC §15.2 formula-injection guard

    def _export_rows(self, filters: ListFilters) -> list[dict[str, Any]]:
        scan = self.scans[-1]
        rows: list[dict[str, Any]] = []
        for f in self._filter_findings(filters):
            rows.append(
                {
                    "finding_key": f.finding_key,
                    "identity_id": f.identity_id,
                    "display_name": f.display_name,
                    "identity_type": f.identity_type,
                    "department": f.department,
                    "clouds": "|".join(f.clouds),
                    "rule_id": f.rule_id,
                    "rule_name": f.rule_name,
                    "severity": f.severity,
                    "risk_score": f.score,
                    "blast_radius_pct": f.facts.get("blast_radius_pct", 0.0),
                    "first_seen_month": f.first_seen_month,
                    "causal_trigger": ";".join(f.causal_event_ids),
                    "plain_english_finding": f.altitudes.headline,
                    "recommended_action": f.investigation.recommended_action
                    if f.investigation
                    else f.allowed_actions[0],
                    "attack_technique": "|".join(f.attack_techniques),
                    "control_ref": "|".join(f.control_refs),
                    "status": f.status,
                    "instance_hash": f.instance_hash,
                    "scan_id": f.scan_id,
                    "merkle_root": scan.merkle_root,
                    "ledger_tx": scan.ledger_tx,
                }
            )
        return rows

    def export_csv(self, filters: ListFilters) -> bytes:
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\n")
        writer.writerow(EXPORT_COLUMNS)
        for r in self._export_rows(filters):
            writer.writerow([self._escape(r[c]) for c in EXPORT_COLUMNS])
        return buf.getvalue().encode("utf-8")

    def export_json(self, filters: ListFilters) -> bytes:
        rows = self._export_rows(filters)
        sidecar = [
            {
                "finding_key": r["finding_key"],
                "instance": self.findings[r["finding_key"]].facts.get("instance"),
                "instance_hash": r["instance_hash"],
                "leaf": self.findings[r["finding_key"]].leaf,
                "proof": self.findings[r["finding_key"]].proof,
                "merkle_root": r["merkle_root"],
                "scan_id": r["scan_id"],
            }
            for r in rows
        ]
        doc = {
            "generated_from": "mock",
            "scan_id": self.scans[-1].scan_id,
            "merkle_root": self.scans[-1].merkle_root,
            "rows": rows,
            "findings": sidecar,
        }
        return json.dumps(doc, indent=2, default=str).encode("utf-8")

    def export_pdf(self, filters: ListFilters) -> bytes:
        from reportlab.lib.pagesizes import A4  # lazy: keep app import light
        from reportlab.pdfgen import canvas

        scan = self.scans[-1]
        buf = io.BytesIO()
        pdf = canvas.Canvas(buf, pagesize=A4)
        _, height = A4
        y = height - 60
        pdf.setFont("Helvetica-Bold", 16)
        pdf.drawString(50, y, f"ATHAR governance report — {month_label(self.month)} (mock)")
        pdf.setFont("Helvetica", 10)
        y -= 24
        pdf.drawString(50, y, f"Scan {scan.scan_id} · root {scan.merkle_root} · tx {scan.ledger_tx}")
        y -= 30
        for r in self._export_rows(filters)[:40]:
            if y < 80:
                pdf.showPage()
                pdf.setFont("Helvetica", 10)
                y = height - 60
            pdf.drawString(50, y, f"[{r['severity']}] {r['plain_english_finding'][:95]}")
            y -= 14
        pdf.setFont("Helvetica-Oblique", 8)
        pdf.drawString(
            50, 40, f"Merkle root {scan.merkle_root} · tx {scan.ledger_tx} · verify with: athar verify --csv"
        )
        pdf.showPage()
        pdf.save()
        return buf.getvalue()

    # ------------------------------------------------------ settings / health
    def get_settings(self) -> SettingsOut:
        return self.settings_state

    def put_settings(self, body: SettingsUpdate, user: AuthUser) -> SettingsOut:
        update = body.model_dump(exclude_none=True)
        update["updated_by"] = user.user_id
        update["updated_at"] = MOCK_NOW + timedelta(minutes=1)
        self.settings_state = self.settings_state.model_copy(update=update)
        return self.settings_state

    def health_deps(self) -> HealthDeps:
        llm = self.settings.llm_provider
        detail = (
            "templates only (mock)"
            if llm == "none"
            else f"{llm} · {self.settings.llm_model} (mock, not probed)"
        )
        return HealthDeps(
            db=DepStatus(ok=True, detail="mock (in-memory)"),
            anvil=DepStatus(ok=True, detail=f"mock chain id {MOCK_CHAIN_ID}"),
            llm=DepStatus(ok=True, detail=detail),
        )


def as_repo(repo: MockRepo) -> Repo:
    """Static proof that MockRepo satisfies `Repo`: mypy checks the structural match here."""
    return repo
