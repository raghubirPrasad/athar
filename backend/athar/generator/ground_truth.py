"""Ground truth derived from what the simulator did (SPEC §4.4). Pure.

What this is, precisely. It reads the simulator's own bookkeeping — which template it granted
to whom, at what scope, whether a person departed, whether a project was retired, when a key
was last rotated, when an account last did anything — and writes down the rules those facts
satisfy, in the canonical terms of SPEC §7. That makes it a second statement of each rule's
predicate over the simulator's state, not an independent judgement of risk, and the evaluation
built on it is a pipeline-recovery check: does the rule engine recover, from the written
exports, what the simulator recorded doing? It catches a broken writer, mapping, linker or
rule, which is worth having; it is not evidence of accuracy on a real estate, and SPEC §17 and
the Evaluation page say so. The decoys are the part that tests judgement.

The catalogue records each template's power in the SPEC §5.3 vocabulary, so the two sides agree
on definitions by construction; where the rule engine's reading is narrower than the SPEC prose,
the narrower reading is mirrored here and documented on the function.

`positives` lists every identity that a rule fires on at the final month with `since_month`
(the first month of the unbroken run ending at the final month) and a reason built from the
causal history. `decoys` lists the eleven §4.3 identities with the rules that WOULD fire
without the register (`looks_like`). `expected_halflife` is the per-department median
grant→revoke interval over the window (SPEC §9.3 definition, computed on native grants).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date
from statistics import median
from typing import Any

from athar.clock import days_between, iso_ts, month_end, month_start
from athar.domain import CLOUDS, DEPARTMENTS, Thresholds
from athar.generator import decoys as dec
from athar.generator.state import Credential, EstateState, ExceptionEntry, Grant, Identity, MonthSnapshot

GENERATOR_VERSION = "1.0.1"

PRIVILEGED_VERBS: frozenset[str] = frozenset({"admin", "grant", "impersonate"})
SA_KEY_HIGH_DAYS = 365
NEVER_RATIO = 0.10  # SPEC §9.3: "Never" when R/G < 0.10
RULE_ORDER: tuple[str, ...] = ("R3", "R4", "R1", "R5", "R9", "R8", "R6", "R2", "R0", "R10")
AWS_FILLER_ROLES: tuple[str, ...] = ("nda-lambda-exec", "nda-ci-deploy")  # unowned principals → R10


@dataclass
class _Ctx:
    """Everything the per-identity checks need for one month."""

    state: EstateState
    snap: MonthSnapshot
    month: int
    thresholds: Thresholds
    ignore_register: bool = False
    grants_by_identity: dict[str, list[Grant]] = field(default_factory=dict)
    creds_by_identity: dict[str, list[Credential]] = field(default_factory=dict)
    admin_principals_aws: set[str] = field(default_factory=set)

    @property
    def as_of(self) -> date:
        return month_end(self.month)

    def grants(self, identity_id: str) -> list[Grant]:
        return self.grants_by_identity.get(identity_id, [])

    def creds(self, identity_id: str) -> list[Credential]:
        return self.creds_by_identity.get(identity_id, [])

    def valid_exception(self, identity_id: str, *types: str) -> ExceptionEntry | None:
        if self.ignore_register:
            return None
        for exc in self.state.exceptions:
            if exc.identity_id != identity_id or exc.exception_type not in types:
                continue
            if exc.review_date is not None and exc.review_date < self.as_of:
                continue
            if exc.expires_on is not None and exc.expires_on < self.as_of:
                continue
            return exc
        return None


def _context(
    state: EstateState, month: int, thresholds: Thresholds, *, ignore_register: bool = False
) -> _Ctx:
    snap = state.snapshot(month)
    ctx = _Ctx(state, snap, month, thresholds, ignore_register)
    by_id: dict[str, list[Grant]] = defaultdict(list)
    for g in snap.grants:
        ident = snap.identities.get(g.identity_id)
        if ident is not None and ident.present_in(g.cloud) and g.cloud not in ident.disabled_clouds:
            by_id[g.identity_id].append(g)
    ctx.grants_by_identity = dict(by_id)
    creds: dict[str, list[Credential]] = defaultdict(list)
    for c in snap.credentials:
        ident = snap.identities.get(c.identity_id)
        if (
            c.active
            and ident is not None
            and ident.present_in(c.cloud)
            and c.cloud not in ident.disabled_clouds
        ):
            creds[c.identity_id].append(c)
    ctx.creds_by_identity = dict(creds)
    ctx.admin_principals_aws = {
        g.identity_id
        for gs in by_id.values()
        for g in gs
        if g.cloud == "aws" and g.is_admin_at_least_project()
    }
    return ctx


# ---------------------------------------------------------------------------
# Per-rule checks: (fires, reason)
# ---------------------------------------------------------------------------


def _origin_text(g: Grant) -> str:
    if g.origin.startswith("role:"):
        return "role baseline"
    if g.origin == "incident":
        return "incident response"
    if g.origin == "service":
        return "service-account creation"
    if g.origin == "drift":
        return "region drift"
    return g.origin


def _r1(ctx: _Ctx, ident: Identity) -> str | None:
    cited = [g for g in ctx.grants(ident.identity_id) if g.is_admin_at_least_project() or g.wildcard]
    if not cited or ctx.valid_exception(ident.identity_id, "break-glass", "approved-privileged-role"):
        return None
    worst = sorted(cited, key=lambda g: (g.scope_level != "global", g.scope_level != "org", g.grant_ref))[0]
    return (
        f"{worst.name} at {worst.scope_level} scope in {worst.cloud} since month {worst.granted_month}"
        f" ({_origin_text(worst)}), no break-glass or approved-privileged-role register entry"
    )


def _observed_last_activity(ctx: _Ctx, ident: Identity) -> date | None:
    """Last activity as the native exports will show it: AWS and Azure usage summaries are per
    principal, GCP usage is per current binding, so a GCP record for a project the identity no
    longer holds a role in is not observable."""
    gcp_projects = {
        g.scope_ref.removeprefix("projects/") for g in ctx.grants(ident.identity_id) if g.cloud == "gcp"
    }
    dates: list[date] = []
    for (iid, cloud, svc), rec in ctx.snap.activity.items():
        if iid != ident.identity_id or rec.last is None or not ident.present_in(cloud):
            continue
        if cloud == "gcp" and svc not in gcp_projects:
            continue
        dates.append(rec.last)
    return max(dates) if dates else None


def _r2(ctx: _Ctx, ident: Identity) -> str | None:
    cited = [g for g in ctx.grants(ident.identity_id) if g.non_read()]
    if not cited:
        return None
    last = _observed_last_activity(ctx, ident)
    if last is not None:
        idle = days_between(last, ctx.as_of)
    else:
        idle = days_between(month_start(max(1, ident.created_month)), ctx.as_of)
    if idle < ctx.thresholds.dormant_days or ctx.valid_exception(ident.identity_id, "dr-failover"):
        return None
    clouds = sorted({g.cloud for g in cited})
    when = f"last activity {last.isoformat()}" if last else "no activity ever recorded"
    return f"idle {idle} days ({when}) while holding non-read access in {', '.join(clouds)}"


def _r3(ctx: _Ctx, ident: Identity) -> str | None:
    grants = ctx.grants(ident.identity_id)
    if not grants:
        return None
    clouds = ", ".join(sorted({g.cloud for g in grants}))
    if ident.is_human:
        if (
            ident.status != "departed"
            or ident.departure_month is None
            or ident.departure_month > ctx.month - 1
        ):
            return None
        return f"departed in month {ident.departure_month}; {len(grants)} grant(s) still active in {clouds}"
    project = ctx.snap.projects.get(ident.project_id or "")
    if project is None or project.status != "retired":
        return None
    return f"project {project.name} retired in month {project.retired_month}; service account survived with {clouds} access"


def _cloud_power(grants: list[Grant]) -> str | None:
    wide = [g for g in grants if g.scope_level in ("project", "org", "global")]
    if any("admin" in g.verbs for g in wide):
        return "admin"
    if any("write" in g.verbs for g in wide) and any("delete" in g.verbs for g in wide):
        return "write_delete"
    return None


def _r4(ctx: _Ctx, ident: Identity) -> str | None:
    grants = ctx.grants(ident.identity_id)
    powers = {c: _cloud_power([g for g in grants if g.cloud == c]) for c in CLOUDS}
    if any(p is None for p in powers.values()):
        return None
    tier = "admin" if all(p == "admin" for p in powers.values()) else "write and delete"
    return f"{tier} at project scope or above in all three clouds"


def _r5(ctx: _Ctx, ident: Identity) -> str | None:
    """Mirrors `detection.r5`: a `grant` at scope ≥ project always yields a ≤3-hop path (it can
    rewrite its own principal's permissions, or reach another admin principal); an `impersonate`
    at global scope reaches every AWS principal, so it escalates when another AWS principal is
    admin. SPEC? R5 does not consult the register, but a break-glass / approved-privileged-role
    holder is a §4.3 negative, so a valid entry of those types is honoured here."""
    if ctx.valid_exception(ident.identity_id, "break-glass", "approved-privileged-role"):
        return None
    grants = ctx.grants(ident.identity_id)
    granters = [g for g in grants if "grant" in g.verbs and g.scope_level in ("project", "org", "global")]
    if granters:
        g = sorted(granters, key=lambda x: x.grant_ref)[0]
        return f"{g.name} in {g.cloud} can assign permissions at {g.scope_level} scope, including to itself"
    others = ctx.admin_principals_aws - {ident.identity_id}
    impersonators = [
        g for g in grants if "impersonate" in g.verbs and g.cloud == "aws" and g.scope_ref == "*"
    ]
    if impersonators and others:
        g = sorted(impersonators, key=lambda x: x.grant_ref)[0]
        return f"{g.name} allows iam:PassRole on every AWS principal while other principals hold admin"
    return None


def _stale(ctx: _Ctx, ident: Identity) -> list[tuple[str, str, int]]:
    """(credential_ref, kind, age_days) for every active credential older than the threshold."""
    out: list[tuple[str, str, int]] = []
    for c in ctx.creds(ident.identity_id):
        age = days_between(c.last_rotated, ctx.as_of)
        if age > ctx.thresholds.stale_key_days:
            out.append((c.credential_ref, c.kind, age))
    if (
        ident.is_human
        and ident.present_in("aws")
        and "aws" not in ident.disabled_clouds
        and not ident.console_disabled
    ):
        age = days_between(ident.password_last_changed(ctx.as_of), ctx.as_of)
        if age > ctx.thresholds.stale_key_days:
            out.append((f"aws:password:{ident.username}", "password", age))
    return out


def _r6(ctx: _Ctx, ident: Identity) -> str | None:
    stale = _stale(ctx, ident)
    if not stale:
        return None
    ref, kind, age = sorted(stale, key=lambda t: (not (t[1] == "sa_key" and t[2] > SA_KEY_HIGH_DAYS), -t[2]))[
        0
    ]
    return f"{kind} {ref} not rotated for {age} days"


def _r8(ctx: _Ctx, ident: Identity) -> str | None:
    approved = set(ctx.thresholds.approved_regions)
    by_ref = {r.ref: r for r in ctx.snap.resources}
    for g in sorted(ctx.grants(ident.identity_id), key=lambda x: x.grant_ref):
        if g.cloud == "gcp" and g.scope_level == "project":
            covered = [r for r in ctx.snap.resources if r.project_id == g.project_id]
        else:
            covered = [by_ref[r] for r in g.resources if r in by_ref]
        for r in sorted(covered, key=lambda x: x.ref):
            if r.sensitivity == "high" and r.region not in approved:
                return f"{g.name} reaches high-sensitivity {r.name} in {r.region} ({g.cloud}), outside the approved regions"
    return None


def _r9(ctx: _Ctx, ident: Identity) -> str | None:
    if not ident.is_human or ident.mfa or not ident.present_in("aws"):
        return None
    cited = [g for g in ctx.grants(ident.identity_id) if PRIVILEGED_VERBS & set(g.verbs)]
    if not cited:
        return None
    verbs = sorted({v for g in cited for v in g.verbs if v in PRIVILEGED_VERBS})
    return f"MFA not enforced (credential report) while holding {', '.join(verbs)} rights"


def _r0(ctx: _Ctx, ident: Identity) -> str | None:
    cited = [g for g in ctx.grants(ident.identity_id) if g.unmapped]
    if not cited:
        return None
    g = sorted(cited, key=lambda x: x.grant_ref)[0]
    return f"{g.name} in {g.cloud} carries an action or role no mapping table knows"


_CHECKS = {"R0": _r0, "R1": _r1, "R2": _r2, "R3": _r3, "R4": _r4, "R5": _r5, "R6": _r6, "R8": _r8, "R9": _r9}


def rules_for(ctx: _Ctx, ident: Identity) -> dict[str, str]:
    """Rule id → reason for every rule that fires on the identity in `ctx`'s month."""
    if ident.status == "departed" and not ctx.grants(ident.identity_id):
        return {}
    out: dict[str, str] = {}
    for rule in RULE_ORDER:
        check = _CHECKS.get(rule)
        if check is None:
            continue
        reason = check(ctx, ident)
        if reason:
            out[rule] = reason
    return out


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------


def _filler_role_positives(state: EstateState, month: int) -> list[dict[str, Any]]:
    """The AWS filler roles carry no owner tag and no HR row: the linker falls through (SPEC §6)."""
    account = state.constants.aws_account_id
    return [
        {
            "identity_id": f"unlinked:aws:arn:aws:iam::{account}:role/{role}",
            "rules": ["R10"],
            "since_month": 1,
            "reason": f"IAM role {role} has no owner tag and no HR record; no linker rule matches",
        }
        for role in AWS_FILLER_ROLES
    ]


def positives_at(state: EstateState, month: int, thresholds: Thresholds) -> dict[str, dict[str, str]]:
    ctx = _context(state, month, thresholds)
    out: dict[str, dict[str, str]] = {}
    for iid in sorted(ctx.snap.identities):
        ident = ctx.snap.identities[iid]
        if dec.is_decoy(ident):
            continue
        fired = rules_for(ctx, ident)
        if fired:
            out[iid] = fired
    return out


def _since_month(per_month: list[dict[str, dict[str, str]]], identity_id: str, rule: str, final: int) -> int:
    since = final
    while since > 1 and rule in per_month[since - 2].get(identity_id, {}):
        since -= 1
    return since


def expected_halflife(state: EstateState) -> dict[str, float | None]:
    """SPEC §9.3 on native grants: per department, median(revoke − grant) over grants made and
    revoked inside the window; `None` when nothing was granted or fewer than 10% were revoked."""
    grants: dict[str, int] = defaultdict(int)
    revocations: dict[str, int] = defaultdict(int)
    intervals: dict[str, list[int]] = defaultdict(list)
    for g in state.all_grants:
        ident = state.identities.get(g.identity_id)
        if ident is None:
            continue
        dept = ident.department
        if g.granted_month >= 1:
            grants[dept] += 1
        if g.revoked_month is not None and g.revoked_month >= 1:
            revocations[dept] += 1
            if g.granted_month >= 1:
                intervals[dept].append(g.revoked_month - g.granted_month)
    out: dict[str, float | None] = {}
    for dept in DEPARTMENTS:
        g_count, r_count = grants.get(dept, 0), revocations.get(dept, 0)
        if g_count == 0 or r_count / g_count < NEVER_RATIO or not intervals.get(dept):
            out[dept] = None
        else:
            out[dept] = round(float(median(intervals[dept])), 1)
    return out


def build_ground_truth(state: EstateState, thresholds: Thresholds | None = None) -> dict[str, Any]:
    """The `ground_truth.json` document for the state's final month (SPEC §4.4)."""
    thresholds = thresholds or Thresholds()
    final = state.months
    per_month = [positives_at(state, m, thresholds) for m in range(1, final + 1)]
    positives: list[dict[str, Any]] = []
    for iid, fired in sorted(per_month[-1].items()):
        rules = [r for r in RULE_ORDER if r in fired]
        since = min(_since_month(per_month, iid, r, final) for r in rules)
        reason = "; ".join(f"{r}: {fired[r]}" for r in rules)
        positives.append({"identity_id": iid, "rules": rules, "since_month": since, "reason": reason})
    positives.extend(_filler_role_positives(state, final))
    positives.sort(key=lambda p: p["identity_id"])

    naive = _context(state, final, thresholds, ignore_register=True)
    decoys: list[dict[str, Any]] = []
    for iid in sorted(naive.snap.identities):
        ident = naive.snap.identities[iid]
        if not dec.is_decoy(ident):
            continue
        looks_like = [r for r in RULE_ORDER if r in rules_for(naive, ident)]
        assert ident.decoy is not None
        decoys.append(
            {"identity_id": iid, "looks_like": looks_like, "why_legitimate": dec.DECOY_WHY[ident.decoy]}
        )

    injection = next(
        (iid for iid, i in sorted(state.final.identities.items()) if i.decoy == dec.INJECTION), None
    )
    rule_counts: dict[str, int] = defaultdict(int)
    for p in positives:
        for r in p["rules"]:
            rule_counts[r] += 1
    return {
        "seed": state.seed,
        "months": final,
        "generated_at": iso_ts(month_end(final), 23, 59),
        "generator_version": GENERATOR_VERSION,
        "thresholds": thresholds.as_dict(),
        "identities": len(state.final.identities),
        "positives": positives,
        "decoys": decoys,
        "injection_decoy": injection,
        "expected_halflife": expected_halflife(state),
        "counts": {
            "positives": len(positives),
            "decoys": len(decoys),
            "by_rule": dict(sorted(rule_counts.items())),
        },
    }
