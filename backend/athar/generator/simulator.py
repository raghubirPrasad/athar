"""Process simulator for the Nahar Digital Authority estate (SPEC §4.2, §4.5, §11.5).

`Simulator(seed, months, identities, remediations).run()` builds a population that pre-dates
month 1, then plays `months` months of organisational events whose counts are Poisson-sampled
from the seeded generators. The estate becomes over-privileged on its own (role changes that
keep the old role, departures whose offboarding ticket is never closed, incident admin that
is never removed, retired projects whose service accounts survive). The generator never
authors a snapshot: month N is whatever the events left behind.

Randomness: exactly one `random.Random(seed)` (choices, dates, ids) and one
`numpy.random.default_rng(seed)` (event counts). Time: `athar.clock` only.
Side effects: none — writers turn the returned `EstateState` into files.
"""

from __future__ import annotations

import random
from collections import defaultdict
from collections.abc import Sequence
from datetime import date, timedelta
from typing import Any

import numpy as np

from athar.clock import EPOCH, month_end, month_start
from athar.config import EMAIL_DOMAIN
from athar.domain import CLOUDS, DEPARTMENTS
from athar.generator import catalogue as cat
from athar.generator import names
from athar.generator import rng as rnd
from athar.generator.state import (
    ActivityKey,
    ActivityRecord,
    Credential,
    EstateState,
    Event,
    ExceptionEntry,
    Grant,
    Identity,
    MonthSnapshot,
    Project,
    RemediationSpec,
    Resource,
    SimConstants,
    principal_ref_for,
    snapshot_of,
)

PRIVILEGED_VERBS: frozenset[str] = frozenset({"admin", "grant", "impersonate"})
ON_CALL_DEPARTMENTS: tuple[str, ...] = ("Platform Engineering", "Cyber Security")
AWS_FILLER_ROLES: tuple[str, ...] = ("nda-lambda-exec", "nda-ci-deploy")


class SimulationError(ValueError):
    """A remediation names an identity / grant / credential that does not exist at its month."""


class Simulator:
    """One deterministic run. Build with `Simulator(...)` and call `run()` once."""

    def __init__(
        self,
        seed: int,
        months: int,
        identities: int,
        remediations: Sequence[RemediationSpec] = (),
        horizon: int | None = None,
    ) -> None:
        if months < 1:
            raise ValueError("months must be >= 1")
        if identities < 40:
            raise ValueError("identities must be >= 40 (eight departments, eleven decoys)")
        self.seed = seed
        self.months = months
        # The window the estate was DESIGNED for: it sizes the starting population and anchors the
        # decoy review / contract dates. `athar generate --advance` (SPEC §4.7) simulates month N+1
        # with the original horizon, so months 1..N replay byte-identically. Defaults to `months`.
        self.horizon = horizon if horizon is not None else months
        if self.horizon < 1:
            raise ValueError("horizon must be >= 1")
        self.identities_target = identities
        self.rng = random.Random(seed)
        self.np_rng = np.random.default_rng(seed)
        self.scale = identities / cat.REFERENCE_IDENTITIES
        self.remediations: list[RemediationSpec] = sorted(remediations, key=lambda r: r.month)

        self.identities: dict[str, Identity] = {}
        self.projects: dict[str, Project] = {}
        self.grants: list[Grant] = []
        self.grants_by_identity: dict[str, list[Grant]] = defaultdict(list)
        self.credentials: list[Credential] = []
        self.resources: list[Resource] = []
        self.resources_by_ref: dict[str, Resource] = {}
        self.activity: dict[ActivityKey, ActivityRecord] = {}
        self.events: list[Event] = []
        self.exceptions: list[ExceptionEntry] = []
        self.snapshots: list[MonthSnapshot] = []
        self.home_projects: dict[tuple[str, str], Project] = {}
        self.citizen_bucket: Resource | None = None
        self._scheduled: list[tuple[int, str, str]] = []  # (month, grant_ref, cause)
        self._guardrailed: list[str] = []  # identities carrying the citizen-data deny (SPEC §5.2)
        self._emp_seq = 0
        self._prj_seq = 0
        self._grant_seq = 0
        self._event_seq = 0
        self._used_locals: set[str] = set()
        self._used_slugs: set[str] = set()
        self.constants = self._make_constants()

    # ------------------------------------------------------------------ run
    def run(self) -> EstateState:
        from athar.generator.decoys import seed_decoys  # local import: decoys type-checks against Simulator

        self._init_projects()
        self._init_population()
        seed_decoys(self)
        for month in range(1, self.months + 1):
            self._simulate_month(month)
        return EstateState(
            seed=self.seed,
            months=self.months,
            identities_target=self.identities_target,
            constants=self.constants,
            snapshots=self.snapshots,
            events=self.events,
            exceptions=self.exceptions,
            remediations=list(self.remediations),
            all_grants=self.grants,
            projects=self.projects,
            identities=self.identities,
        )

    # ------------------------------------------------------------ constants
    def _make_constants(self) -> SimConstants:
        rng = self.rng
        aws_ids: dict[str, str] = {}
        for dept in DEPARTMENTS:
            aws_ids[f"grp-{names.DEPARTMENT_SLUG[dept]}"] = rnd.upper_id(rng, "AGPA")
        for name in sorted(cat.AWS_MANAGED_POLICY_DOCUMENTS):
            aws_ids[f"policy:{name}"] = rnd.upper_id(rng, "ANPA")
        for role in AWS_FILLER_ROLES:
            aws_ids[f"role:{role}"] = rnd.upper_id(rng, "AROA")
        custom = {n: rnd.guid(rng) for n, d in sorted(cat.AZURE_ROLE_DEFINITIONS.items()) if d.custom}
        return SimConstants(
            aws_account_id=rnd.digits(rng, 12),
            azure_tenant_id=rnd.guid(rng),
            azure_subscription_id=rnd.guid(rng),
            azure_sandbox_subscription_id=rnd.guid(rng),
            azure_management_group="mg-nda-root",
            gcp_org_id=rnd.digits(rng, 12),
            gcp_folder_id=rnd.digits(rng, 12),
            azure_custom_role_guids=custom,
            aws_ids=aws_ids,
        )

    # ------------------------------------------------------------- projects
    def _init_projects(self) -> None:
        for dept in DEPARTMENTS:
            slug_base = names.DEPARTMENT_SLUG[dept]
            for cloud in cat.DEPARTMENT_HOME_CLOUDS[dept]:
                p = self._create_project(
                    f"{slug_base}-core", f"{dept} core platform", dept, cloud, 0, "department"
                )
                self.home_projects[(dept, cloud)] = p
        for cloud in CLOUDS:
            self._create_project(
                f"dr-failover-{cloud}", f"DR failover ({cloud})", "Platform Engineering", cloud, 0, "dr"
            )
        data_aws = self.home_projects[("Data Services", "aws")]
        self.citizen_bucket = self._create_resource(
            data_aws, "aws", "s3", "storage", "bucket", "nda-citizen-data", cat.HOME_REGION["aws"], "high", 0
        )
        n_delivery = max(4, round(cat.INITIAL_DELIVERY_PROJECTS * self.scale))
        for _ in range(n_delivery):
            dept = self._pick_project_department()
            cloud = rnd.weighted(self.rng, cat.LAUNCH_CLOUD_WEIGHTS)
            self._create_delivery_project(dept, cloud, 0)

    def _pick_project_department(self) -> str:
        return rnd.weighted(self.rng, tuple((d, w) for d, w in cat.DEPARTMENT_WEIGHTS if d != "Contractors"))

    def _new_slug(self) -> str:
        for _ in range(200):
            slug = f"{rnd.pick(self.rng, names.PROJECT_STEMS)}-{rnd.pick(self.rng, names.PROJECT_QUALIFIERS)}"
            if slug not in self._used_slugs:
                return slug
        raise RuntimeError("project slug space exhausted")

    def _create_delivery_project(
        self, dept: str, cloud: str, month: int, region: str | None = None
    ) -> Project:
        slug = self._new_slug()
        return self._create_project(
            slug, slug.replace("-", " ").title(), dept, cloud, month, "delivery", region
        )

    def _create_project(
        self,
        slug: str,
        name: str,
        dept: str,
        cloud: str,
        month: int,
        kind: str,
        region: str | None = None,
    ) -> Project:
        self._used_slugs.add(slug)
        self._prj_seq += 1
        refs = {"aws": slug, "azure": f"rg-{slug}", "gcp": f"nda-{slug}"[:30]}
        created = rnd.days_before_epoch(self.rng, 90, 1500) if month == 0 else rnd.day_in(self.rng, month)
        project = Project(
            project_id=f"prj-{self._prj_seq:04d}",
            name=name,
            slug=slug,
            department=dept,
            status="active",
            retired_month=None,
            cloud=cloud,
            project_ref=refs[cloud],
            created_month=month,
            kind=kind,
            protected=kind != "delivery",
            gcp_number=rnd.digits(self.rng, 12),
            created_on=created,
            region=region or cat.HOME_REGION[cloud],
        )
        self.projects[project.project_id] = project
        self._create_project_resources(project, month)
        return project

    def _sensitivity(self, dept: str) -> str:
        return "high" if dept in cat.HIGH_SENSITIVITY_DEPARTMENTS else "low"

    def _create_project_resources(self, p: Project, month: int) -> None:
        sens = self._sensitivity(p.department)
        region = p.region
        slug = p.slug
        if p.cloud == "aws":
            self._create_resource(p, "aws", "s3", "storage", "bucket", f"nda-{slug}", region, sens, month)
            self._create_resource(
                p, "aws", "dynamodb", "data", "table", f"{slug}-records", region, sens, month
            )
            self._create_resource(
                p, "aws", "lambda", "compute", "function", f"{slug}-api", region, sens, month
            )
        elif p.cloud == "azure":
            self._create_resource(
                p, "azure", "Microsoft.Resources", "compute", "rg", p.project_ref, region, sens, month
            )
            st = "st" + slug.replace("-", "")[:20]
            self._create_resource(
                p, "azure", "Microsoft.Storage", "storage", "storage_account", st, region, sens, month
            )
            self._create_resource(
                p,
                "azure",
                "Microsoft.KeyVault",
                "security",
                "key_vault",
                f"kv-{slug}"[:24],
                region,
                sens,
                month,
            )
        else:
            self._create_resource(
                p, "gcp", "resourcemanager", "identity", "project", p.project_ref, region, sens, month
            )
            self._create_resource(
                p, "gcp", "bigquery", "data", "dataset", slug.replace("-", "_") + "_ds", region, sens, month
            )
            self._create_resource(
                p, "gcp", "storage", "storage", "gcs_bucket", f"nda-{slug}", region, sens, month
            )

    def _resource_ref(
        self, p: Project, cloud: str, kind: str, name: str, region: str, subscription: str | None = None
    ) -> str:
        c = self.constants
        if cloud == "aws":
            if kind == "bucket":
                return f"arn:aws:s3:::{name}"
            if kind == "table":
                return f"arn:aws:dynamodb:{region}:{c.aws_account_id}:table/{name}"
            return f"arn:aws:lambda:{region}:{c.aws_account_id}:function:{name}"
        if cloud == "azure":
            sub_id = subscription or c.azure_subscription_id
            rg_name = name if kind == "rg" else p.project_ref
            rg = f"/subscriptions/{sub_id}/resourceGroups/{rg_name}"
            if kind == "rg":
                return rg
            if kind == "storage_account":
                return f"{rg}/providers/Microsoft.Storage/storageAccounts/{name}"
            return f"{rg}/providers/Microsoft.KeyVault/vaults/{name}"
        if kind == "project":
            return f"projects/{p.project_ref}"
        if kind == "dataset":
            return f"//bigquery.googleapis.com/projects/{p.project_ref}/datasets/{name}"
        return f"//storage.googleapis.com/projects/_/buckets/{name}"

    def _create_resource(
        self,
        p: Project,
        cloud: str,
        service: str,
        category: str,
        kind: str,
        name: str,
        region: str,
        sensitivity: str,
        month: int,
        subscription: str | None = None,
    ) -> Resource:
        ref = self._resource_ref(p, cloud, kind, name, region, subscription)
        if ref in self.resources_by_ref:
            return self.resources_by_ref[ref]
        created = p.created_on if month == 0 else rnd.day_in(self.rng, month)
        res = Resource(
            ref=ref,
            cloud=cloud,
            service=service,
            category=category,
            region=region,
            sensitivity=sensitivity,
            project_id=p.project_id,
            project_ref=p.project_ref,
            created_month=month,
            name=name,
            kind=kind,
            created_on=created,
        )
        self.resources.append(res)
        self.resources_by_ref[ref] = res
        return res

    def project_resource(self, p: Project, kind: str) -> Resource:
        for res in self.resources:
            if res.project_id == p.project_id and res.kind == kind:
                return res
        raise KeyError(f"{p.project_id} has no {kind} resource")

    def projects_in_kind(self, kind: str) -> list[Project]:
        return sorted((p for p in self.projects.values() if p.kind == kind), key=lambda p: p.project_id)

    def projects_in(self, cloud: str, *, active_only: bool = True, kind: str | None = None) -> list[Project]:
        return [
            p
            for p in self.projects.values()
            if p.cloud == cloud
            and (not active_only or p.status == "active")
            and (kind is None or p.kind == kind)
        ]

    def context_project(self, ident: Identity, cloud: str) -> Project:
        """The project whose resources scope an identity's resource-level grants in `cloud`."""
        if ident.project_id is not None and self.projects[ident.project_id].cloud == cloud:
            return self.projects[ident.project_id]
        home = self.home_projects.get((ident.department, cloud))
        if home is not None:
            return home
        candidates = self.projects_in(cloud, kind="delivery") or self.projects_in(cloud, active_only=False)
        return candidates[0]

    # ----------------------------------------------------------- population
    def _init_population(self) -> None:
        hires = cat.EVENT_RATES[0][1] * self.scale * self.horizon
        n_humans = max(20, round(self.identities_target * cat.HUMAN_SHARE - hires) - cat.SEEDED_HUMANS)
        n_sa = max(
            6,
            round(
                self.identities_target * (1 - cat.HUMAN_SHARE)
                - cat.NEW_SA_PER_MONTH * self.scale * self.horizon
            )
            - cat.SEEDED_SERVICE_ACCOUNTS,
        )
        for _ in range(n_humans):
            dept = rnd.weighted(self.rng, cat.DEPARTMENT_WEIGHTS)
            level = rnd.weighted(self.rng, cat.LEVEL_WEIGHTS)
            clouds = rnd.weighted(self.rng, cat.DEPARTMENT_CLOUDS[dept])
            start = rnd.days_before_epoch(self.rng, 60, 3000)
            ident = self.create_human(dept, level, clouds, start, 0)
            self.grant_role(ident, 0, None)
            self._maybe_human_key(ident, 0)
            self._seed_initial_activity(ident)
        actives = [i for i in self.identities.values() if i.is_human and i.status == "active"]
        for ident in rnd.sample(self.rng, actives, cat.INITIAL_ON_LEAVE):
            ident.status = "on_leave"
            ident.profile = "dormant"
            ident.dormant_from = 1
        home = [p for p in self.projects.values() if p.kind == "department"]
        delivery = [p for p in self.projects.values() if p.kind == "delivery"]
        for _ in range(n_sa):
            pool = home if self.rng.random() < cat.P_INITIAL_SA_IN_HOME_PROJECT else delivery
            project = rnd.pick(self.rng, pool)
            scope_kind = "broad" if self.rng.random() < cat.P_SA_BROAD_INITIAL else "scoped"
            self.create_service_account(project, 0, scope_kind, rnd.days_before_epoch(self.rng, 30, 1200))

    def _next_emp_id(self) -> str:
        self._emp_seq += 1
        return f"emp-{self._emp_seq:04d}"

    def _new_person(self) -> tuple[str, str]:
        for _ in range(100):
            given = rnd.pick(self.rng, names.GIVEN_NAMES)
            family = rnd.pick(self.rng, names.FAMILY_NAMES)
            local = names.email_local_part(given, family)
            if local not in self._used_locals:
                self._used_locals.add(local)
                return f"{given} {family}", local
        suffix = len(self._used_locals) + 1
        local = f"{local}{suffix}"
        self._used_locals.add(local)
        return f"{given} {family}", local

    def create_human(
        self,
        dept: str,
        level: str,
        clouds: tuple[str, ...],
        start: date,
        month: int,
        *,
        decoy: str | None = None,
        protected: bool = False,
        profile: str | None = None,
        contract_end: date | None = None,
    ) -> Identity:
        display, local = self._new_person()
        contractor = dept == "Contractors"
        if contractor and contract_end is None:
            lo, hi = cat.CONTRACT_LENGTH_DAYS
            contract_end = start + timedelta(days=self.rng.randint(lo, hi))
        if profile is None:
            profile = rnd.weighted(self.rng, cat.ACTIVITY_PROFILES_HUMAN)
        ident = Identity(
            identity_id=self._next_emp_id(),
            kind="human",
            display_name=display,
            email=f"{local}@{EMAIL_DOMAIN}",
            department=dept,
            title=rnd.pick(self.rng, names.TITLES[dept][level]),
            level=level,
            employment_type="contractor" if contractor else "staff",
            status="active",
            start_date=start,
            end_date=None,
            contract_end=contract_end,
            manager_id=None,
            clouds=tuple(c for c in CLOUDS if c in clouds),
            mfa=True,
            role_key=(dept, level),
            profile=profile,
            dormant_from=None,
            created_month=month,
            departure_month=None,
            project_id=None,
            sa_name=None,
            aws_user_id=rnd.upper_id(self.rng, "AIDA"),
            azure_object_id=rnd.guid(self.rng),
            azure_app_id=None,
            password_offset=self.rng.randint(0, 80),
            decoy=decoy,
            protected=protected,
            tags={"department": dept},
        )
        if profile == "dormant":
            ident.dormant_from = max(1, month + self.rng.randint(1, 3)) if month else 1
        if contractor:
            in_cloud = self.projects_in(ident.clouds[0], kind="delivery") or self.projects_in(ident.clouds[0])
            project = rnd.pick(self.rng, in_cloud)
            ident.project_id = project.project_id
            ident.tags["project"] = project.project_ref
        self.identities[ident.identity_id] = ident
        return ident

    def create_service_account(
        self,
        project: Project,
        month: int,
        scope_kind: str,
        start: date,
        *,
        decoy: str | None = None,
        protected: bool = False,
        key_policy: str | None = None,
        profile: str | None = None,
        name: str | None = None,
    ) -> Identity:
        used = {i.sa_name for i in self.identities.values() if i.project_id == project.project_id}
        free = [n for n in names.SERVICE_ACCOUNT_NAMES if n not in used]
        sa_name = name or (rnd.pick(self.rng, free) if free else f"svc{len(used) + 1}")
        cloud = project.cloud
        if key_policy is None:
            key_policy = "manual" if self.rng.random() < cat.P_SA_KEY_MANUAL_ROTATION else "auto"
        if profile is None:
            profile = rnd.weighted(self.rng, cat.ACTIVITY_PROFILES_SERVICE)
        ident = Identity(
            identity_id=f"svc:{project.project_id}:{sa_name}",
            kind="service",
            display_name=f"svc-{sa_name}-{project.slug}",
            # The project REF, not the slug: a department present in two clouds gets one
            # `<dept>-core` project per cloud with the same slug, so a slug-derived address
            # named two different service accounts and the linker had to guess between them.
            email=f"svc-{sa_name}-{project.project_ref}@{EMAIL_DOMAIN}",
            department=project.department,
            title=f"Service account ({project.name})",
            level="service",
            employment_type="service",
            status="active",
            start_date=start,
            end_date=None,
            contract_end=None,
            manager_id=None,
            clouds=(cloud,),
            mfa=False,
            role_key=None,
            profile=profile,
            dormant_from=None,
            created_month=month,
            departure_month=None,
            project_id=project.project_id,
            sa_name=sa_name,
            aws_user_id=rnd.upper_id(self.rng, "AIDA"),
            azure_object_id=rnd.guid(self.rng),
            azure_app_id=rnd.guid(self.rng) if cloud == "azure" else None,
            password_offset=0,
            decoy=decoy,
            protected=protected,
            tags={"department": project.department, "project": project.project_ref},
            key_policy=key_policy,
        )
        if project.owner_id:
            ident.tags["owner"] = self.identities[project.owner_id].email
        if profile == "dormant":
            ident.dormant_from = max(1, month + self.rng.randint(1, 4)) if month else 1
        self.identities[ident.identity_id] = ident
        for tpl in cat.SERVICE_ACCOUNT_TEMPLATES[cloud][scope_kind]:
            self.new_grant(ident, tpl, month, None, origin="service", note=f"{scope_kind} scope at creation")
        if cloud in ("aws", "gcp"):
            self.create_key(ident, cloud, start, key_policy)
        if month == 0:
            self._seed_initial_activity(ident)
        return ident

    def _maybe_human_key(self, ident: Identity, month: int) -> None:
        if "aws" in ident.clouds and self.rng.random() < cat.P_HUMAN_HAS_ACCESS_KEY:
            policy = "manual" if self.rng.random() < cat.P_HUMAN_KEY_MANUAL_ROTATION else "auto"
            created = ident.start_date if month == 0 else rnd.day_in(self.rng, month)
            self.create_key(ident, "aws", created, policy)

    def create_key(self, ident: Identity, cloud: str, created: date, policy: str) -> Credential:
        if created < EPOCH:
            # a key that pre-dates the window has its own rotation history
            if policy == "auto":
                rotated = rnd.days_before_epoch(self.rng, 1, cat.KEY_ROTATION_DAYS)
            else:
                rotated = rnd.days_before_epoch(self.rng, 100, 600)
            rotated = max(rotated, created)
        else:
            rotated = created
        if cloud == "aws":
            key_id = rnd.access_key_id(self.rng)
            ref = f"aws:key:{key_id}"
            project_ref = None
        else:
            key_id = rnd.hex_id(self.rng, 40)
            ref = f"gcp:sa_key:{key_id}"
            project_ref = self.projects[ident.project_id].project_ref if ident.project_id else None
        cred = Credential(
            credential_ref=ref,
            identity_id=ident.identity_id,
            cloud=cloud,
            kind="key" if cloud == "aws" else "sa_key",
            key_id=key_id,
            created=min(created, rotated),
            last_rotated=rotated,
            last_used=None,
            active=True,
            policy=policy,
            project_ref=project_ref,
        )
        self.credentials.append(cred)
        return cred

    def seed_activity(self, ident: Identity) -> None:
        """Public alias used by `decoys.py` for identities created outside `_init_population`."""
        self._seed_initial_activity(ident)

    def _seed_initial_activity(self, ident: Identity) -> None:
        """Pre-window usage so month-1 dormancy is a property of the identity, not of the window start."""
        if ident.profile == "never":
            return
        for g in self.active_grants(ident.identity_id):
            for svc in g.services:
                key = (ident.identity_id, g.cloud, svc)
                if ident.profile == "dormant":
                    last = rnd.days_before_epoch(self.rng, 20, 150)
                else:
                    last = rnd.days_before_epoch(self.rng, 1, 45)
                rec = self.activity.setdefault(key, ActivityRecord())
                rec.last = max(rec.last, last) if rec.last else last
        for cred in self.credentials:
            if cred.identity_id == ident.identity_id and cred.active:
                cred.last_used = max(
                    (
                        r.last
                        for (i, c, _), r in self.activity.items()
                        if i == ident.identity_id and c == cred.cloud and r.last
                    ),
                    default=None,
                )

    # --------------------------------------------------------------- grants
    def active_grants(self, identity_id: str) -> list[Grant]:
        return [g for g in self.grants_by_identity.get(identity_id, []) if g.active]

    def principal_ref(self, ident: Identity, cloud: str) -> str:
        return principal_ref_for(ident, cloud, self.constants, self.projects)

    def _resolve_scope(
        self, tpl: cat.GrantTemplate, ident: Identity
    ) -> tuple[str, tuple[str, ...], tuple[str, ...], tuple[str, ...], Project | None]:
        """(scope_ref, native_scopes, resource refs, activity service keys, project)."""
        cloud = tpl.cloud
        c = self.constants
        if cloud == "aws":
            if tpl.scope == "*":
                return "*", ("*",), (), tpl.services, None
            kind = tpl.scope.split(":")[1]
            if kind == "citizen":
                assert self.citizen_bucket is not None
                res = self.citizen_bucket
                project = self.projects[res.project_id]
            else:
                project = self.context_project(ident, cloud)
                res = self.project_resource(project, kind)
            if res.kind == "bucket":
                return f"{res.ref}/*", (res.ref, f"{res.ref}/*"), (res.ref,), tpl.services, project
            return res.ref, (res.ref,), (res.ref,), tpl.services, project
        if cloud == "azure":
            if tpl.scope == "mg":
                return c.azure_mg_scope, (c.azure_mg_scope,), (), tpl.services, None
            if tpl.scope == "sub":
                return c.azure_subscription_scope, (c.azure_subscription_scope,), (), tpl.services, None
            project = self.context_project(ident, cloud)
            rg = self.project_resource(project, "rg")
            return rg.ref, (rg.ref,), (rg.ref,), tpl.services, project
        project = self.context_project(ident, cloud)
        scope = f"projects/{project.project_ref}"
        return scope, (scope,), (scope,), (project.project_ref,), project

    def new_grant(
        self,
        ident: Identity,
        tpl: cat.GrantTemplate,
        month: int,
        event_id: str | None,
        *,
        origin: str,
        note: str = "",
        scope_override: tuple[str, tuple[str, ...], tuple[str, ...], tuple[str, ...], Project | None]
        | None = None,
        granted_on: date | None = None,
    ) -> Grant | None:
        """Instantiate a template for an identity; returns None when an identical grant is already active.

        `granted_on` overrides the sampled date and, crucially, draws nothing from the RNG: a caller
        that adds a grant outside the SPEC §4.2 event stream (the citizen-data guardrail) must not
        shift the stream every later event reads from.
        """
        if tpl.cloud not in ident.clouds:
            return None
        name = f"grp-{names.DEPARTMENT_SLUG[ident.department]}" if tpl.name == "GROUP" else tpl.name
        scope_ref, native_scopes, resources, services, project = scope_override or self._resolve_scope(
            tpl, ident
        )
        for g in self.active_grants(ident.identity_id):
            if g.cloud == tpl.cloud and g.kind == tpl.kind and g.name == name and g.scope_ref == scope_ref:
                return None
        self._grant_seq += 1
        if granted_on is None:
            granted_on = (
                rnd.days_before_epoch(self.rng, 1, 400) if month == 0 else rnd.day_in(self.rng, month)
            )
        granted_on = max(granted_on, ident.start_date)
        grant = Grant(
            grant_ref=f"g-{self._grant_seq:05d}",
            identity_id=ident.identity_id,
            cloud=tpl.cloud,
            kind=tpl.kind,
            name=name,
            scope_ref=scope_ref,
            scope_level=tpl.scope_level,
            category=tpl.category,
            verbs=tpl.verbs,
            services=services,
            actions=tpl.actions,
            resources=resources,
            project_id=project.project_id if project else None,
            granted_month=month,
            event_id=event_id,
            granted_on=granted_on,
            native_scopes=native_scopes,
            native_id=rnd.guid(self.rng) if tpl.cloud == "azure" else "",
            origin=origin,
            wildcard=tpl.wildcard,
            unmapped=tpl.unmapped,
            effect=tpl.effect,
            note=note,
        )
        self.grants.append(grant)
        self.grants_by_identity[ident.identity_id].append(grant)
        return grant

    def grant_role(self, ident: Identity, month: int, event_id: str | None) -> list[Grant]:
        assert ident.role_key is not None
        origin = f"role:{ident.role_key[0]}:{ident.role_key[1]}"
        added: list[Grant] = []
        for cloud in ident.clouds:
            for tpl in cat.ROLES[ident.role_key].get(cloud, ()):
                g = self.new_grant(ident, tpl, month, event_id, origin=origin, note=f"{ident.title} baseline")
                if g is not None:
                    added.append(g)
        return added

    def revoke(self, grant: Grant, month: int, event_id: str | None) -> None:
        if grant.active:
            grant.revoked_month = month
            grant.revoked_event_id = event_id

    def entries(self, grants: Sequence[Grant]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for g in grants:
            out.extend(g.event_refs(self.principal_ref(self.identities[g.identity_id], g.cloud)))
        return out

    # --------------------------------------------------------------- events
    def new_event(
        self,
        month: int,
        kind: str,
        ident: Identity | None,
        cloud: str | None,
        trigger: str,
        note: str,
        **extra: Any,
    ) -> Event:
        self._event_seq += 1
        ev = Event(
            event_id=f"ev-{month:02d}-{self._event_seq:03d}",
            month=month,
            kind=kind,
            identity_id=ident.identity_id if ident else None,
            cloud=cloud,
            grants_added=[],
            grants_removed=[],
            trigger=trigger,
            note=note,
            extra=dict(extra),
        )
        self.events.append(ev)
        return ev

    def _simulate_month(self, month: int) -> None:
        self._event_seq = 0
        counts = {kind: int(self.np_rng.poisson(rate * self.scale)) for kind, rate in cat.EVENT_RATES}
        handlers = {
            "new_hire": self._ev_new_hire,
            "role_change": self._ev_role_change,
            "departure": self._ev_departure,
            "project_launch": self._ev_project_launch,
            "project_retirement": self._ev_project_retirement,
            "incident_response": self._ev_incident_response,
            "region_drift": self._ev_region_drift,
            "mfa_lapse": self._ev_mfa_lapse,
        }
        for kind, _ in cat.EVENT_RATES:
            for _ in range(counts[kind]):
                handlers[kind](month)
        self._process_scheduled(month)
        self._citizen_data_guardrail(month)
        self._simulate_activity(month)
        self._rotate_keys(month)
        for rem in self.remediations:
            if rem.month == month:
                self._apply_remediation(rem)
        self.snapshots.append(
            snapshot_of(
                month,
                self.identities,
                self.grants,
                self.credentials,
                self.resources,
                self.projects,
                self.activity,
            )
        )

    def _candidates(self, month: int, *, humans: bool = True) -> list[Identity]:
        return [
            i
            for i in self.identities.values()
            if i.is_human == humans and i.status == "active" and not i.protected and i.created_month < month
        ]

    def _ev_new_hire(self, month: int) -> None:
        dept = rnd.weighted(self.rng, cat.DEPARTMENT_WEIGHTS)
        level = rnd.weighted(self.rng, cat.NEW_HIRE_LEVEL_WEIGHTS)
        clouds = rnd.weighted(self.rng, cat.DEPARTMENT_CLOUDS[dept])
        ident = self.create_human(dept, level, clouds, rnd.day_in(self.rng, month), month)
        ev = self.new_event(month, "new_hire", ident, None, "new_hire", f"{ident.title} joined {dept}")
        ev.grants_added = self.entries(self.grant_role(ident, month, ev.event_id))
        self._maybe_human_key(ident, month)

    def _ev_role_change(self, month: int) -> None:
        pool = self._candidates(month)
        if not pool:
            return
        ident = rnd.pick(self.rng, pool)
        assert ident.role_key is not None
        old_key = ident.role_key
        old_dept, old_level = old_key
        lateral = old_dept != "Contractors" and (
            old_level == "lead" or self.rng.random() < cat.P_LATERAL_MOVE
        )
        if lateral:
            others = [d for d in DEPARTMENTS if d not in (old_dept, "Contractors")]
            new_dept, new_level = rnd.pick(self.rng, others), old_level
            note = f"moved from {old_dept} to {new_dept}"
        else:
            new_dept = old_dept
            new_level = {"member": "senior", "senior": "lead", "lead": "lead"}[old_level]
            note = f"promoted from {old_level} to {new_level}"
        ident.role_key = (new_dept, new_level)
        ident.department, ident.level = new_dept, new_level
        ident.title = rnd.pick(self.rng, names.TITLES[new_dept][new_level])
        ident.tags["department"] = new_dept
        ev = self.new_event(month, "role_change", ident, None, "role_change", note)
        old_grants = [
            g for g in self.active_grants(ident.identity_id) if g.origin == f"role:{old_dept}:{old_level}"
        ]
        if self.rng.random() < cat.P_ROLE_CHANGE_REVOKES_OLD:
            for g in old_grants:
                self.revoke(g, month, ev.event_id)
            ev.grants_removed = self.entries(old_grants)
            ev.note += "; previous role's access revoked"
        else:
            ev.note += "; previous role's access left in place"
        ev.grants_added = self.entries(self.grant_role(ident, month, ev.event_id))

    def _ev_departure(self, month: int) -> None:
        pool = self._candidates(month)
        if not pool:
            return
        ident = rnd.pick(self.rng, pool)
        end = max(rnd.day_in(self.rng, month), ident.start_date)
        ident.status = "departed"
        ident.end_date = end
        ident.departure_month = month
        ev = self.new_event(
            month, "departure", ident, None, "departure", f"{ident.title} left the organisation"
        )
        if self.rng.random() < cat.P_DEPARTURE_REVOKED:
            self._remove_all_access(ident, month, ev)
            ev.note += "; cloud access revoked at offboarding"
        else:
            ev.note += "; offboarding ticket never closed, cloud access still active"
            ev.extra["access_revoked"] = False

    def _remove_all_access(self, ident: Identity, month: int, ev: Event) -> None:
        removed = self.active_grants(ident.identity_id)
        for g in removed:
            self.revoke(g, month, ev.event_id)
        ev.grants_removed = self.entries(removed)
        ev.extra["access_revoked"] = True
        for cred in self.credentials:
            if cred.identity_id == ident.identity_id:
                cred.active = False
        ident.removed_clouds = set(ident.clouds)

    def _ev_project_launch(self, month: int) -> None:
        dept = self._pick_project_department()
        cloud = rnd.weighted(self.rng, cat.LAUNCH_CLOUD_WEIGHTS)
        project = self._create_delivery_project(dept, cloud, month)
        owners = [i for i in self._candidates(month) if i.department == dept] or self._candidates(month)
        if owners:
            project.owner_id = rnd.pick(self.rng, owners).identity_id
        n_sa = rnd.weighted(self.rng, cat.SA_COUNT_WEIGHTS)
        for _ in range(n_sa):
            scope_kind = "broad" if self.rng.random() < cat.P_SA_BROAD_AT_LAUNCH else "scoped"
            sa = self.create_service_account(project, month, scope_kind, rnd.day_in(self.rng, month))
            ev = self.new_event(
                month,
                "project_launch",
                sa,
                cloud,
                "project_launch",
                f"project {project.name} launched; service account created with {scope_kind} scope",
                project_id=project.project_id,
            )
            ev.grants_added = self.entries(self.active_grants(sa.identity_id))
            for g in self.active_grants(sa.identity_id):
                g.event_id = ev.event_id

    def _ev_project_retirement(self, month: int) -> None:
        pool = [
            p
            for p in self.projects.values()
            if p.kind == "delivery"
            and p.status == "active"
            and p.created_month <= month - cat.MIN_RETIREMENT_AGE_MONTHS
        ]
        if not pool:
            return
        project = rnd.pick(self.rng, pool)
        project.status = "retired"
        project.retired_month = month
        sas = [
            i
            for i in self.identities.values()
            if i.project_id == project.project_id and not i.is_human and i.status == "active"
        ]
        if not sas:
            self.new_event(
                month,
                "project_retirement",
                None,
                project.cloud,
                "project_retirement",
                f"project {project.name} retired",
                project_id=project.project_id,
            )
        for sa in sas:
            ev = self.new_event(
                month,
                "project_retirement",
                sa,
                project.cloud,
                "project_retirement",
                f"project {project.name} retired",
                project_id=project.project_id,
            )
            if self.rng.random() < cat.P_SA_SURVIVES_RETIREMENT:
                sa.profile = "dormant"
                sa.dormant_from = month + 1
                ev.note += "; service account left in place, no longer scheduled"
            else:
                sa.status = "departed"
                sa.end_date = rnd.day_in(self.rng, month)
                sa.departure_month = month
                self._remove_all_access(sa, month, ev)
                ev.note += "; service account deleted"

    def _ev_incident_response(self, month: int) -> None:
        pool = [
            i
            for i in self._candidates(month)
            if i.department in ON_CALL_DEPARTMENTS
            and i.level in ("senior", "lead")
            and any(i.present_in(c) for c in CLOUDS)
        ]
        if not pool:
            return
        cause = rnd.pick(self.rng, names.INCIDENT_CAUSES)
        n = min(rnd.weighted(self.rng, cat.INCIDENT_HUMAN_WEIGHTS), len(pool))
        for ident in rnd.sample(self.rng, pool, n):
            cloud = rnd.pick(self.rng, [c for c in CLOUDS if ident.present_in(c)])
            ev = self.new_event(
                month,
                "incident_response",
                ident,
                cloud,
                "incident_response",
                f"emergency admin granted during {cause}",
            )
            g = self.new_grant(
                ident,
                cat.INCIDENT_ADMIN[cloud],
                month,
                ev.event_id,
                origin="incident",
                note=f"incident: {cause}",
            )
            if g is None:
                ev.note += " (already held)"
                continue
            ev.grants_added = self.entries([g])
            if self.rng.random() < cat.P_INCIDENT_ADMIN_REMOVED:
                lo, hi = cat.INCIDENT_REMOVAL_DELAY_MONTHS
                self._scheduled.append((month + self.rng.randint(lo, hi), g.grant_ref, cause))
                ev.extra["removal_planned"] = True
            else:
                ev.extra["removal_planned"] = False

    def _process_scheduled(self, month: int) -> None:
        due = sorted(s for s in self._scheduled if s[0] == month)
        self._scheduled = [s for s in self._scheduled if s[0] != month]
        for _, grant_ref, cause in due:
            g = next(x for x in self.grants if x.grant_ref == grant_ref)
            if not g.active:
                continue
            ident = self.identities[g.identity_id]
            ev = self.new_event(
                month,
                "incident_admin_revoked",
                ident,
                g.cloud,
                "incident_response",
                f"temporary emergency admin removed after {cause}",
            )
            self.revoke(g, month, ev.event_id)
            ev.grants_removed = self.entries([g])

    def _citizen_data_guardrail(self, month: int) -> None:
        """Attach the citizen-data deny to a couple of data-lake holders (SPEC §5.2 `effect`).

        Not a §4.2 event: this is a standing control the authority applied once, so it draws
        nothing from the RNG — the candidates are the `citizen-data-lake` holders in identity-id
        order, the grant date is the first of the month, and `_simulate_activity` skips deny rows
        so the per-grant usage draw is not made for this one either. A holder keeps it until the grant is
        revoked with the rest of their access, and at most `CITIZEN_DENY_IDENTITIES` identities
        ever carry it, so the estate gains a small, stable set of deny rows rather than a
        population that grows with the window.
        """
        if month < cat.CITIZEN_DENY_FROM_MONTH or self.citizen_bucket is None:
            return
        if len(self._guardrailed) >= cat.CITIZEN_DENY_IDENTITIES:
            return
        holders = sorted(
            {
                g.identity_id
                for g in self.grants
                if g.active and g.name == cat.AWS_DATA_LAKE.name and g.is_allow
            }
        )
        for identity_id in holders:
            if len(self._guardrailed) >= cat.CITIZEN_DENY_IDENTITIES:
                return
            if identity_id in self._guardrailed:
                continue
            ident = self.identities[identity_id]
            if ident.status != "active" or not ident.present_in("aws"):
                continue
            ev = self.new_event(
                month,
                "guardrail_applied",
                ident,
                "aws",
                "data_protection_guardrail",
                "explicit deny on the citizen data lake; the standing allow was left in place",
            )
            grant = self.new_grant(
                ident,
                cat.AWS_CITIZEN_DENY,
                month,
                ev.event_id,
                origin="guardrail",
                note="citizen data lake carved out by an explicit deny",
                granted_on=month_start(month),
            )
            if grant is None:  # pragma: no cover - the dedupe cannot hit on a first attach
                self.events.remove(ev)
                continue
            ev.grants_added = self.entries([grant])
            self._guardrailed.append(identity_id)

    def _ev_region_drift(self, month: int) -> None:
        cloud = rnd.weighted(self.rng, cat.DRIFT_CLOUD_WEIGHTS)
        depts = [d for d in DEPARTMENTS if (d, cloud) in self.home_projects]
        dept = rnd.pick(self.rng, depts)
        region = rnd.pick(self.rng, cat.DRIFT_REGIONS[cloud])
        sens = "high" if self.rng.random() < cat.P_REGION_DRIFT_HIGH_SENSITIVITY else "low"
        grantees = [i for i in self._candidates(month) if i.department == dept and i.present_in(cloud)] or [
            i for i in self._candidates(month) if i.present_in(cloud)
        ]
        if not grantees:
            return
        ident = rnd.pick(self.rng, grantees)
        home = self.home_projects[(dept, cloud)]
        short = region.replace("-", "")[:10]
        override: tuple[str, tuple[str, ...], tuple[str, ...], tuple[str, ...], Project | None]
        if cloud == "aws":
            res = self._create_resource(
                home, "aws", "dynamodb", "data", "table", f"{home.slug}-replica-{short}", region, sens, month
            )
            override = (res.ref, (res.ref,), (res.ref,), ("dynamodb",), home)
        elif cloud == "azure":
            # Shadow IT lands in the non-production sandbox subscription, outside the landing zone's
            # region policy — the classic way an Azure estate drifts out of region.
            rg_name = f"rg-{home.slug}-{short}"
            sandbox = self.constants.azure_sandbox_subscription_id
            res = self._create_resource(
                home,
                "azure",
                "Microsoft.Resources",
                "compute",
                "rg",
                rg_name,
                region,
                sens,
                month,
                subscription=sandbox,
            )
            override = (res.ref, (res.ref,), (res.ref,), ("Microsoft.Resources", "Microsoft.Storage"), home)
        else:
            slug = f"{home.slug}-{short}"
            existing = next((p for p in self.projects.values() if p.slug == slug), None)
            project = existing or self._create_project(
                slug, f"{home.name} ({region})", dept, "gcp", month, "drift", region
            )
            for r in self.resources:
                if r.project_id == project.project_id and existing is None:
                    r.sensitivity = sens
            if existing is not None:
                sens = self.project_resource(project, "project").sensitivity
            res = self.project_resource(project, "project")
            override = (res.ref, (res.ref,), (res.ref,), (project.project_ref,), project)
        ev = self.new_event(
            month,
            "region_drift",
            ident,
            cloud,
            "region_drift",
            f"resource created in {region} (outside the approved region list), sensitivity {sens}",
            resource_ref=res.ref,
            region=region,
            sensitivity=sens,
        )
        g = self.new_grant(
            ident,
            cat.REGION_DRIFT_GRANT[cloud],
            month,
            ev.event_id,
            origin="drift",
            scope_override=override,
            note=f"access to {res.name} in {region}",
        )
        ev.grants_added = self.entries([g]) if g else []

    def _ev_mfa_lapse(self, month: int) -> None:
        # Only AWS reports an MFA state in its native export (credential report `mfa_active`);
        # the Graph /users shape carries none, so a lapse is only observable for AWS console users.
        pool = [
            i
            for i in self._candidates(month)
            if i.mfa
            and i.present_in("aws")
            and any(
                PRIVILEGED_VERBS & set(g.verbs)
                for g in self.active_grants(i.identity_id)
                if i.present_in(g.cloud)
            )
        ]
        if not pool:
            return
        ident = rnd.pick(self.rng, pool)
        ident.mfa = False
        self.new_event(
            month,
            "mfa_lapse",
            ident,
            "aws",
            "mfa_lapse",
            "MFA re-registration never completed after a device replacement",
        )

    # ------------------------------------------------------------- activity
    def _active_until(self, ident: Identity, month: int) -> date | None:
        start, end = month_start(month), month_end(month)
        if ident.status == "on_leave" or ident.profile == "never":
            return None
        if all(c in ident.removed_clouds or c in ident.disabled_clouds for c in ident.clouds):
            return None
        if ident.status == "departed":
            return ident.end_date if ident.end_date is not None and ident.end_date >= start else None
        if ident.profile == "dormant" and ident.dormant_from is not None and ident.dormant_from <= month:
            return None
        if ident.profile == "light" and self.rng.random() >= cat.P_LIGHT_USER_ACTIVE_MONTH:
            return None
        return end

    def _simulate_activity(self, month: int) -> None:
        start = month_start(month)
        touched: dict[tuple[str, str], date] = {}
        for iid in sorted(self.identities):
            ident = self.identities[iid]
            until = self._active_until(ident, month)
            if until is None or until < max(start, ident.start_date):
                continue
            p_use = cat.P_SERVICE_USED_HUMAN if ident.is_human else cat.P_SERVICE_KEY_USED_IN_MONTH
            ops_mean = cat.OPS_MEAN_HUMAN if ident.is_human else cat.OPS_MEAN_SERVICE
            lo = max(start, ident.start_date)
            span = (until - lo).days
            for g in self.active_grants(iid):
                if not g.is_allow:
                    # Activity is usage, and nothing is ever used *through* an explicit deny. Two
                    # reasons this matters beyond tidiness: it would write activity rows saying an
                    # identity called s3 through the policy that forbids s3, and — because the draw
                    # below is per grant per service — it would shift every later number the seeded
                    # RNG produces, so adding the citizen-data guardrail would silently rewrite the
                    # whole estate from month 4 on rather than adding two rows to it.
                    continue
                if not ident.present_in(g.cloud) or g.cloud in ident.disabled_clouds:
                    continue
                for svc in g.services:
                    if self.rng.random() >= p_use:
                        continue
                    day = lo + timedelta(days=self.rng.randint(0, span)) if span > 0 else lo
                    rec = self.activity.setdefault((iid, g.cloud, svc), ActivityRecord())
                    rec.last = max(rec.last, day) if rec.last else day
                    rec.ops[month] = rec.ops.get(month, 0) + 1 + rnd.poisson(self.rng, ops_mean)
                    key = (iid, g.cloud)
                    touched[key] = max(touched.get(key, day), day)
        for cred in self.credentials:
            if cred.active and (cred.identity_id, cred.cloud) in touched:
                cred.last_used = touched[(cred.identity_id, cred.cloud)]

    def _rotate_keys(self, month: int) -> None:
        end = month_end(month)
        for cred in self.credentials:
            if not cred.active or cred.policy != "auto" or cred.rotated_by_remediation:
                continue
            if (end - cred.last_rotated).days < cat.KEY_ROTATION_DAYS:
                continue
            rotated = max(rnd.day_in(self.rng, month), cred.last_rotated + timedelta(days=1))
            if cred.cloud == "aws":
                cred.key_id = rnd.access_key_id(self.rng)
                cred.credential_ref = f"aws:key:{cred.key_id}"
            else:
                cred.key_id = rnd.hex_id(self.rng, 40)
                cred.credential_ref = f"gcp:sa_key:{cred.key_id}"
            cred.created = rotated
            cred.last_rotated = rotated
            cred.last_used = None

    # --------------------------------------------------------- remediation
    def _apply_remediation(self, rem: RemediationSpec) -> None:
        """SPEC §11.5: applied to the end-of-month state; deterministic and RNG-free."""
        ident = self.identities.get(rem.identity_id)
        if ident is None:
            raise SimulationError(f"remediation names unknown identity {rem.identity_id!r}")
        month = rem.month
        ev = self.new_event(
            month,
            "remediation",
            ident,
            rem.cloud,
            "remediation",
            rem.note,
            action=rem.action,
            credential_ref=rem.credential_ref,
        )
        ev.event_id = f"ev-{month:02d}-r{sum(1 for e in self.events if e.month == month and e.kind == 'remediation'):02d}"
        if rem.action in ("revoke_grant", "downgrade_to_least_privilege"):
            targets = self._match_grants(ident, rem)
            if not targets:
                raise SimulationError(
                    f"remediation {rem.action} for {rem.identity_id} matches no active grant"
                )
            for g in targets:
                self.revoke(g, month, ev.event_id)
            ev.grants_removed = self.entries(targets)
        elif rem.action == "disable_identity":
            removed = [g for g in self.active_grants(ident.identity_id) if rem.cloud in (None, g.cloud)]
            for g in removed:
                self.revoke(g, month, ev.event_id)
            ev.grants_removed = self.entries(removed)
            for cred in self.credentials:
                if cred.identity_id == ident.identity_id and rem.cloud in (None, cred.cloud):
                    cred.active = False
            ident.disabled_clouds |= {c for c in ident.clouds if rem.cloud in (None, c)}
        elif rem.action == "remove_cloud_access":
            if rem.cloud is None:
                raise SimulationError("remove_cloud_access needs a cloud")
            removed = [g for g in self.active_grants(ident.identity_id) if g.cloud == rem.cloud]
            for g in removed:
                self.revoke(g, month, ev.event_id)
            ev.grants_removed = self.entries(removed)
            for cred in self.credentials:
                if cred.identity_id == ident.identity_id and cred.cloud == rem.cloud:
                    cred.active = False
            ident.removed_clouds.add(rem.cloud)
        elif rem.action == "rotate_or_disable_credential":
            self._disable_credential(ident, rem.credential_ref)
        else:  # pragma: no cover - REMEDIATION_ACTIONS is closed
            raise SimulationError(f"unsupported action {rem.action}")

    def _disable_credential(self, ident: Identity, credential_ref: str | None) -> None:
        """Deactivate one credential named either natively (`aws:key:AKIA…`, `gcp:sa_key:<id>`) or the
        way the normaliser names it from the credential report (`aws:key:<user>/key-<slot>`,
        `aws:password:<user>`)."""
        if not credential_ref:
            raise SimulationError("rotate_or_disable_credential needs a credential_ref")
        if credential_ref == f"aws:password:{ident.username}":
            ident.console_disabled = True
            return
        own = [c for c in self.credentials if c.identity_id == ident.identity_id and c.active]
        target = next((c for c in own if c.credential_ref == credential_ref), None)
        if target is None and credential_ref.startswith(f"aws:key:{ident.username}/key-"):
            slot = credential_ref.rsplit("-", 1)[-1]
            aws_keys = sorted((c for c in own if c.cloud == "aws"), key=lambda c: (c.created, c.key_id))
            if slot.isdigit() and 1 <= int(slot) <= len(aws_keys):
                target = aws_keys[int(slot) - 1]
        if target is None:
            raise SimulationError(f"remediation names unknown or inactive credential {credential_ref!r}")
        target.active = False
        target.rotated_by_remediation = True

    def _match_grants(self, ident: Identity, rem: RemediationSpec) -> list[Grant]:
        matched: list[Grant] = []
        for g in self.active_grants(ident.identity_id):
            if rem.cloud is not None and g.cloud != rem.cloud:
                continue
            pref = self.principal_ref(ident, g.cloud)
            for ref in rem.grant_refs:
                if ref.get("grant_ref") and ref["grant_ref"] == g.grant_ref:
                    matched.append(g)
                    break
                if ref.get("principal_ref") not in (None, pref):
                    continue
                if ref.get("granted_via") not in (None, g.granted_via):
                    continue
                if ref.get("scope_ref") not in (None, g.scope_ref, *g.native_scopes):
                    continue
                if ref.get("service") not in (None, "", *g.services):
                    continue
                if not any(k in ref for k in ("granted_via", "scope_ref")):
                    continue
                matched.append(g)
                break
        return matched


def simulate(
    seed: int,
    months: int,
    identities: int,
    remediations: Sequence[RemediationSpec] = (),
    horizon: int | None = None,
) -> EstateState:
    """Run the simulator in memory (tests and the ground-truth writer introspect the result).

    `horizon` is the window the estate was designed for (default `months`); `estate.advance_estate`
    passes the original value so months 1..N replay byte-identically (SPEC §4.7).
    """
    return Simulator(seed, months, identities, remediations, horizon).run()


def add_exception(sim: Simulator, entry: ExceptionEntry) -> None:
    sim.exceptions.append(entry)
