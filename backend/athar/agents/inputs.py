"""Agent inputs built ONLY from canonical facts (SPEC §11.3, §11.4). Pure.

Every value that could have originated in provider data passes through
`guard.sanitize_untrusted()` before it enters a prompt. The rule is stated the safe way round:
**everything is provider text until it is named as canonical.** `CANONICAL_SLOTS` is the
allowlist of fact slots (SPEC `detection/facts.py`) ATHAR produces itself — enums, rule ids,
severities, months, counts, booleans and ids ATHAR minted — and every other slot, at any depth,
is wrapped leaf by leaf. A rule that adds a slot is therefore safe before anyone reviews it, and
`tests/agents/test_inputs.py` fails if a slot in `RULE_SLOTS` is in neither set.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from datetime import date, timedelta
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from athar.agents.guard import is_wrapped, sanitize_untrusted, unwrap
from athar.config import ORG_NAME
from athar.detection.base import FindingDraft, RuleSpec
from athar.domain import DEPARTMENTS, SEVERITIES, ActivityRow, EstateView, GrantRow, IdentityRow
from athar.drift.types import CausalStep, HalfLifeRow
from athar.hashing import finding_key as make_finding_key
from athar.scoring.types import ScoreResult

ACTIVITY_WINDOW_DAYS = 90

# Fact slots ATHAR produces itself and therefore passes to the model unwrapped: enums, counts,
# booleans, months, dates ATHAR formatted, thresholds from its own settings, and ids it minted
# (grant ids are a hash of the natural key, event ids are `ev-<month>-<index>`). Keys of the
# causal-step dict (SPEC §9.2) are in here too, because `sanitize_facts` wraps those as well.
# A canonical slot carries canonical values all the way down — `grant_delta` holds grant ids —
# so the allowlist is applied to the top level of a facts dict only. Nothing below it is
# consulted: a provider controls the *keys* of its own tag dict, and naming one `grant_ids`
# must not buy it a free pass.
CANONICAL_SLOTS: frozenset[str] = frozenset(
    {
        # common + causal step
        "department",
        "identity_type",
        "clouds",
        "cloud",
        "month",
        "event_id",
        "kind",
        "trigger",
        "grant_delta",
        "grant_ids",
        # R1 / R2 / R3
        "scope_level",
        "wildcard",
        "exception_expired_on",
        "dormant_days",
        "last_activity_at",
        "clouds_with_write",
        "orphan_kind",
        "departure_month",
        "months_since_departure",
        "retired_month",
        # R4 / R5
        "power",
        "combination",
        "path_len",
        # R6
        "age_days",
        "last_rotated_at",
        "threshold_days",
        # R7
        "grant_count",
        "department_median",
        "department_mad",
        "categories_over",
        "peer_categories",
        # R8 / R9 / R10
        "approved_regions",
        "resource_sensitivity",
        "privileged_verbs",
        "clouds_privileged",
        "principal_type",
        "link_attempts",
    }
)

# Slots known to carry provider text. Listing them changes nothing — they are wrapped because
# they are not in `CANONICAL_SLOTS` — but it records the decision, and the RULE_SLOTS coverage
# test forces a new slot into one set or the other. `identity_id` is here because it is not
# always ATHAR's own: the linker mints `unlinked:<cloud>:<principal_ref>` and `svc:<project>:
# <name>` around strings the provider chose. `region` is whatever the export said, not an enum.
PROVIDER_TEXT_SLOTS: frozenset[str] = frozenset(
    {
        "identity_id",
        "display_name",
        "raw_action",
        "principal_ref",
        "scope_ref",
        "granted_via",
        "project_id",
        "project_name",
        "project_ref",
        "resource_ref",
        "credential_ref",
        "region",
        "path",
        "per_cloud",
        "description",
        "note",
        "notes",
        "tags",
        "policy_name",
        "role_name",
    }
)

# Evidence kinds (`detection.base.EvidenceKind`) whose ref is an id ATHAR minted. Every other
# kind quotes a provider string — a credential ref, a principal, a resource, a project, an
# escalation path built from node names — so the whole `<kind>:<ref>` token is wrapped.
CANONICAL_EVIDENCE_KINDS: frozenset[str] = frozenset({"grant", "event", "exception"})

# A citation token: canonical as it stands, or the same token wrapped as untrusted data.
Citation = str | dict[str, str]


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class IdentityFacts(BaseModel):
    model_config = ConfigDict(extra="forbid")

    identity_id: str
    display_name: dict[str, str]  # {"untrusted_text": ...}
    identity_type: str
    department: str
    employment_status: str
    external: bool
    mfa_enforced: bool


class DepartmentBaseline(BaseModel):
    model_config = ConfigDict(extra="forbid")

    median_grants: float = 0.0
    median_categories: float = 0.0
    identities: int = 0


class FindingFacts(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_key: str
    rule_id: str
    rule_name: str
    severity: str
    score: int | None


class InvestigateInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding: FindingFacts
    identity: IdentityFacts
    facts: dict[str, Any]
    causal_history: list[dict[str, Any]] = Field(default_factory=list)
    department_baseline: DepartmentBaseline
    allowed_actions: list[str]
    evidence_refs: list[Citation]


class GrantFacts(BaseModel):
    model_config = ConfigDict(extra="forbid")

    grant_id: str
    cloud: str
    service_category: str
    verb: str
    scope_level: str
    scope_ref: dict[str, str]
    granted_via: dict[str, str]


class ActivityFacts(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cloud: str
    service_category: str
    last_activity_at: date | None
    operation_count: int


class PlanInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding: FindingFacts
    identity: IdentityFacts
    facts: dict[str, Any]
    grants: list[GrantFacts]
    activity_90d: list[ActivityFacts]
    credential_refs: list[Citation] = Field(default_factory=list)
    allowed_actions: list[str]
    current_blast_radius: float
    as_of: date


class SummaryInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    month: int
    org_name: str = ORG_NAME
    counts_per_rule: dict[str, int]
    counts_per_department: dict[str, int]
    counts_per_severity: dict[str, int]
    halflife_table: list[dict[str, Any]]
    top_headlines: list[str]
    rule_names: dict[str, str] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Sanitizing helpers
# ---------------------------------------------------------------------------


def _sanitize_deep(value: Any) -> Any:
    if is_wrapped(value):
        return value
    if isinstance(value, str):
        return sanitize_untrusted(value)
    if isinstance(value, dict):
        return {str(k): _sanitize_deep(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_sanitize_deep(v) for v in value]
    return value


def sanitize_facts(facts: Mapping[str, Any]) -> dict[str, Any]:
    """Wrap every slot except the canonical ones, leaf by leaf (SPEC §11.3).

    Unknown slots are wrapped, not passed through: a rule that grows a new fact cannot leak
    provider text into a prompt before anyone has classified it.
    """
    out: dict[str, Any] = {}
    for key, value in facts.items():
        out[key] = value if key in CANONICAL_SLOTS else _sanitize_deep(value)
    return out


def sanitize_citations(refs: Sequence[str]) -> list[Citation]:
    """Evidence / credential refs as the model may see them (SPEC §11.3).

    A ref the model is asked to cite back has to stay recognisable, so the token itself is kept
    — but only `CANONICAL_EVIDENCE_KINDS` keep it bare. Everything else quotes a provider string
    and is wrapped, which is what tells the model it is data. `citation_values()` is the way back
    for any code that compares what the model echoed against what was offered.
    """
    out: list[Citation] = []
    for ref in refs:
        kind, _, _ = str(ref).partition(":")
        out.append(str(ref) if kind in CANONICAL_EVIDENCE_KINDS else sanitize_untrusted(str(ref)))
    return out


def citation_values(refs: Sequence[Citation]) -> list[str]:
    """The bare tokens behind `sanitize_citations()` — wrapped or not."""
    return [str(unwrap(ref)) for ref in refs]


def identity_facts(estate: EstateView, draft: FindingDraft) -> IdentityFacts:
    row: IdentityRow | None = estate.identities.get(draft.identity_id)
    facts = draft.facts
    if row is None:  # e.g. R10 unowned principal — only the draft knows it
        return IdentityFacts(
            identity_id=draft.identity_id,
            display_name=sanitize_untrusted(str(facts.get("display_name") or "")),
            identity_type=str(facts.get("identity_type") or "unknown"),
            department=str(facts.get("department") or "unknown"),
            employment_status="unknown",
            external=False,
            mfa_enforced=False,
        )
    return IdentityFacts(
        identity_id=row.identity_id,
        display_name=sanitize_untrusted(row.display_name),
        identity_type=row.identity_type,
        department=row.department,
        employment_status=row.employment_status,
        external=row.external,
        mfa_enforced=row.mfa_enforced,
    )


def finding_facts(draft: FindingDraft, score: ScoreResult | None, rule_spec: RuleSpec) -> FindingFacts:
    return FindingFacts(
        finding_key=make_finding_key(draft.identity_id, draft.rule_id),
        rule_id=draft.rule_id,
        rule_name=rule_spec.name,
        severity=score.severity if score is not None else draft.severity,
        score=score.score if score is not None else None,
    )


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def build_investigate_input(
    estate: EstateView,
    draft: FindingDraft,
    score: ScoreResult | None,
    causal: Sequence[CausalStep],
    department_baseline: Mapping[str, Any],
    rule_spec: RuleSpec,
) -> InvestigateInput:
    baseline = DepartmentBaseline(
        median_grants=float(department_baseline.get("median_grants", 0.0) or 0.0),
        median_categories=float(department_baseline.get("median_categories", 0.0) or 0.0),
        identities=int(department_baseline.get("identities", 0) or 0),
    )
    return InvestigateInput(
        finding=finding_facts(draft, score, rule_spec),
        identity=identity_facts(estate, draft),
        facts=sanitize_facts(draft.facts),
        causal_history=[sanitize_facts(step.as_dict()) for step in causal],
        department_baseline=baseline,
        allowed_actions=list(rule_spec.allowed_actions),
        evidence_refs=sanitize_citations(draft.evidence_keys()),
    )


def grant_facts(g: GrantRow) -> GrantFacts:
    return GrantFacts(
        grant_id=g.grant_id,
        cloud=g.cloud,
        service_category=g.service_category,
        verb=g.verb,
        scope_level=g.scope_level,
        scope_ref=sanitize_untrusted(g.scope_ref),
        granted_via=sanitize_untrusted(g.granted_via),
    )


def activity_window(
    rows: Sequence[ActivityRow], as_of: date, days: int = ACTIVITY_WINDOW_DAYS
) -> list[ActivityFacts]:
    cutoff = as_of - timedelta(days=days)
    out = [
        ActivityFacts(
            cloud=a.cloud,
            service_category=a.service_category,
            last_activity_at=a.last_activity_at,
            operation_count=a.operation_count,
        )
        for a in rows
        if a.last_activity_at is not None and cutoff <= a.last_activity_at <= as_of
    ]
    return sorted(out, key=lambda a: (a.cloud, a.service_category))


def build_plan_input(
    estate: EstateView,
    draft: FindingDraft,
    score: ScoreResult | None,
    rule_spec: RuleSpec,
    as_of: date,
) -> PlanInput:
    # `allow` rows only (SPEC §5.2 `effect`). A remediation plan decides which access to take away,
    # and a `deny` row is not access — it is a control someone put there on purpose, like the
    # citizen-data guardrail. Passed in as an ordinary grant it becomes a candidate for `drop`, and
    # the tool ends up proposing to remove a data-protection measure. Rules already read only allow
    # rows (`detection.common.active_allow_grants`), so nothing a finding cites can be missing here.
    grants = sorted(
        (g for g in estate.grants_for(draft.identity_id) if g.effect == "allow"),
        key=lambda g: g.grant_id,
    )
    creds = sorted(c.credential_ref for c in estate.credentials_for(draft.identity_id) if c.active)
    return PlanInput(
        finding=finding_facts(draft, score, rule_spec),
        identity=identity_facts(estate, draft),
        facts=sanitize_facts(draft.facts),
        grants=[grant_facts(g) for g in grants],
        activity_90d=activity_window(estate.activity_for(draft.identity_id), as_of),
        credential_refs=sanitize_citations(creds),
        allowed_actions=list(rule_spec.allowed_actions),
        current_blast_radius=float(score.blast_radius) if score is not None else 0.0,
        as_of=as_of,
    )


# -- summary ------------------------------------------------------------------

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_IDENTITY_ID = re.compile(r"\b(?:emp|svc|usr|con|ctr|sa|id)-[0-9A-Za-z]{2,}\b", re.IGNORECASE)
_CAP_PAIR = re.compile(r"\b([A-Z][a-z]+(?:-[A-Z][a-z]+)?)\s+([A-Z][a-z]+(?:-[A-Z][a-z]+)?)\b")
_KEEP_WORDS: frozenset[str] = frozenset(
    {w for dep in DEPARTMENTS for w in dep.split()}
    | set(ORG_NAME.split())
    | set(SEVERITIES)
    | {
        "January", "February", "March", "April", "May", "June", "July", "August",
        "September", "October", "November", "December",
        "The", "This", "An", "A", "In", "On", "At", "Of", "For", "With", "Since", "After", "Before",
        "Access", "Cloud", "Identity", "Service", "Account", "Left", "Has", "Is", "Was", "Can",
    }
)  # fmt: skip


def redact_headline(text: str) -> str:
    """Heuristically remove emails, identity ids and personal names from a headline (SPEC §11.4)."""
    out = _EMAIL.sub("[redacted]", text)
    out = _IDENTITY_ID.sub("[redacted]", out)

    def _pair(m: re.Match[str]) -> str:
        a, b = m.group(1), m.group(2)
        if a in _KEEP_WORDS or b in _KEEP_WORDS:
            return m.group(0)
        return "[name]"

    return _CAP_PAIR.sub(_pair, out)


def build_summary_input(
    *,
    month: int,
    counts_per_rule: Mapping[str, int],
    counts_per_department: Mapping[str, int],
    counts_per_severity: Mapping[str, int],
    halflife_table: Sequence[HalfLifeRow | Mapping[str, Any]],
    top_headlines: Sequence[str],
    org_name: str = ORG_NAME,
    rule_names: Mapping[str, str] | None = None,
) -> SummaryInput:
    rows = [r.as_dict() if isinstance(r, HalfLifeRow) else dict(r) for r in halflife_table]
    return SummaryInput(
        month=month,
        org_name=org_name,
        counts_per_rule=dict(sorted(counts_per_rule.items())),
        counts_per_department=dict(sorted(counts_per_department.items())),
        counts_per_severity=dict(sorted(counts_per_severity.items())),
        halflife_table=rows,
        top_headlines=[redact_headline(h) for h in list(top_headlines)[:3]],
        rule_names=dict(rule_names or {}),
    )


def payload(inp: BaseModel) -> dict[str, Any]:
    """JSON-ready dict for the LLM and the cache key."""
    return inp.model_dump(mode="json")
