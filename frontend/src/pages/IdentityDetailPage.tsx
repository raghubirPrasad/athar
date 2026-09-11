import { useQuery } from "@tanstack/react-query";
import { useCallback, useMemo } from "react";
import { useParams, useSearchParams } from "react-router-dom";
import { getIdentity } from "../api/endpoints";
import { queryKeys } from "../api/queryKeys";
import type { Altitude, IdentityDetail } from "../api/types";
import { MonthBadge } from "../components/MonthBadge";
import { AltitudeToggle } from "../components/findings/AltitudeToggle";
import { AgentPanel } from "../components/identity/AgentPanel";
import { CausalTimeline } from "../components/identity/CausalTimeline";
import { EscalationChain } from "../components/identity/EscalationChain";
import { ExceptionPanel } from "../components/identity/ExceptionPanel";
import { GrantEvidence } from "../components/identity/GrantEvidence";
import { IdentityFindingCard } from "../components/identity/IdentityFindingCard";
import { RiskSparkline } from "../components/identity/RiskSparkline";
import { ScoreCard } from "../components/identity/ScoreCard";
import { UsageEvidence } from "../components/identity/UsageEvidence";
import { Badge } from "../components/ui/Badge";
import { Button, ButtonLink } from "../components/ui/Button";
import { Card } from "../components/ui/Card";
import { CloudIcons } from "../components/ui/CloudIcon";
import { CodeBlock } from "../components/ui/CodeBlock";
import { EmptyState } from "../components/ui/EmptyState";
import { ErrorState } from "../components/ui/ErrorState";
import { PageHeader } from "../components/ui/PageHeader";
import { Skeleton, SkeletonTiles } from "../components/ui/Skeleton";
import { StatTile } from "../components/ui/StatTile";
import { ALTITUDE_LABEL, atLeast, readAltitude } from "../lib/altitude";
import { prettyJson } from "../lib/download";
import { formatDate, formatInt, formatMonthLabel, formatPct, formatScore } from "../lib/format";

/** Cited grant ids across every finding — highlighted in the raw-snippet panel. */
function citedGrants(detail: IdentityDetail): Set<string> {
  const cited = new Set<string>();
  for (const finding of detail.findings) {
    for (const ref of finding.evidence_refs) {
      if (ref.kind === "grant") cited.add(ref.ref);
    }
  }
  return cited;
}

function scrollTo(id: string): void {
  const element = document.getElementById(id);
  element?.scrollIntoView?.({ behavior: "smooth", block: "start" });
}

/**
 * Identity drill-down (SPEC §14) — the screen the whole tool exists for.
 * One toggle changes the altitude (SPEC §10.2): a director reads sentences, a
 * risk officer reads causes, an engineer reads the provider JSON, the score line
 * items, the escalation chain and the Merkle leaf. Every number on the page
 * links to the section that evidences it.
 */
export function IdentityDetailPage() {
  const { identityId = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const altitude = readAltitude(params);

  const setAltitude = useCallback(
    (next: Altitude) => {
      const updated = new URLSearchParams(params);
      if (next === "headline") updated.delete("altitude");
      else updated.set("altitude", next);
      setParams(updated, { replace: true });
    },
    [params, setParams],
  );

  const goTo = useCallback(
    (id: string, min: Altitude) => {
      if (!atLeast(altitude, min)) setAltitude(min);
      window.setTimeout(() => scrollTo(id), 0);
    },
    [altitude, setAltitude],
  );

  const identity = useQuery({
    queryKey: queryKeys.identities.detail(identityId),
    queryFn: () => getIdentity(identityId),
    enabled: identityId.length > 0,
  });

  const detail = identity.data;
  const grantsById = useMemo(
    () => new Map((detail?.grants ?? []).map((grant) => [grant.grant_id, grant])),
    [detail],
  );
  const cited = useMemo(() => (detail ? citedGrants(detail) : new Set<string>()), [detail]);

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={detail?.display_name ?? identityId ?? "Identity"}
        description="Why this identity is flagged, since when, and what happens if we act."
        meta={
          detail && (
            <>
              <Badge mono title="Identity id">
                {detail.identity_id}
              </Badge>
              <Badge tone={detail.identity_type === "service" ? "info" : "neutral"}>
                {detail.identity_type === "service" ? "Service account" : "Human"}
              </Badge>
              <Badge tone="neutral">{detail.department}</Badge>
              <CloudIcons clouds={detail.clouds} />
              <Badge
                tone={
                  detail.employment_status === "departed"
                    ? "danger"
                    : detail.employment_status === "on_leave"
                      ? "warn"
                      : "neutral"
                }
              >
                {detail.employment_status === "on_leave"
                  ? "On leave"
                  : detail.employment_status === "departed"
                    ? `Departed${detail.departure_month ? ` · ${formatMonthLabel(detail.departure_month)}` : ""}`
                    : "Active"}
              </Badge>
              {detail.external && <Badge tone="warn">External</Badge>}
              <Badge tone={detail.mfa_enforced ? "ok" : "danger"}>
                <span aria-hidden="true">{detail.mfa_enforced ? "✓" : "✕"}</span>
                {detail.mfa_enforced ? "MFA enforced" : "No MFA"}
              </Badge>
              <MonthBadge month={detail.last_seen_month} />
            </>
          )
        }
        actions={
          <>
            <AltitudeToggle value={altitude} onChange={setAltitude} />
            <ButtonLink to="/identities">Back to identities</ButtonLink>
          </>
        }
      />

      {identity.isError && <ErrorState error={identity.error} onRetry={() => void identity.refetch()} />}

      {identity.isPending && (
        <>
          <SkeletonTiles />
          <Skeleton lines={6} />
        </>
      )}

      {detail && (
        <>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <StatTile
              label="Risk score"
              value={formatScore(detail.score?.score ?? 0)}
              hint={`${detail.severity} · see every term of the formula`}
              tone={detail.severity === "Critical" || detail.severity === "High" ? "danger" : "neutral"}
              onClick={() => goTo("score", "explanation")}
            />
            <StatTile
              label="Blast radius"
              value={formatPct(detail.blast_radius_pct, 1)}
              hint={`${formatInt(detail.score?.reachable_resources ?? 0)} resources reachable with control verbs`}
              onClick={() => goTo("score", "explanation")}
            />
            <StatTile
              label="Findings"
              value={formatInt(detail.findings.length)}
              hint="Rules that fired against this identity"
              onClick={() => goTo("findings", "headline")}
            />
            <StatTile
              label="Active grants"
              value={formatInt(detail.grants.length)}
              hint="Canonical rows, with the provider JSON behind each"
              onClick={() => goTo("grants", "evidence")}
            />
          </div>

          {altitude === "headline" && (
            <p className="rounded-lg border border-dashed border-border-strong bg-surface px-3 py-2 text-[13px] text-fg-muted">
              Showing <span className="font-semibold text-fg">{ALTITUDE_LABEL.headline}</span> — one sentence per
              finding. Switch the altitude for the causal history, the escalation chain and the raw provider JSON.
            </p>
          )}

          <section id="findings" className="flex flex-col gap-3">
            <h2 className="text-sm font-semibold text-fg">
              Findings <span className="tabular text-fg-muted">({detail.findings.length})</span>
            </h2>
            {detail.findings.length === 0 ? (
              <EmptyState
                title="Scored on blast radius alone — no rule fired"
                description={
                  `No detection rule matched this identity in the current scan. Its score of ` +
                  `${formatScore(detail.score?.score ?? 0)} is the formula applied to measured reach: ` +
                  `${formatPct(detail.blast_radius_pct, 1)} of the estate, ` +
                  `${formatInt(detail.score?.high_sensitivity_reached ?? 0)} high-sensitivity resources. ` +
                  `Every term of it is in the score card below.`
                }
                action={
                  <Button size="sm" onClick={() => goTo("score", "explanation")}>
                    See the score line items
                  </Button>
                }
              />
            ) : (
              detail.findings.map((finding) => (
                <IdentityFindingCard
                  key={finding.finding_key}
                  finding={finding}
                  altitude={altitude}
                  grantsById={grantsById}
                />
              ))
            )}
          </section>

          <div className="grid gap-4 lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
            {detail.score ? (
              <ScoreCard id="score" score={detail.score} altitude={altitude} />
            ) : (
              <Card id="score" title="Risk score">
                <EmptyState
                  compact
                  title="Not scored in this scan"
                  description="This identity has no score row for the current scan."
                />
              </Card>
            )}

            <Card title="Risk over twelve months" subtitle="Annotated with the events that moved it">
              <RiskSparkline points={detail.risk_history} />
            </Card>
          </div>

          {atLeast(altitude, "explanation") && (
            <div className="grid gap-4 lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
              <Card title="How it got here" subtitle="Causal history from the snapshot diff">
                <CausalTimeline steps={detail.causal_history} />
              </Card>
              <Card
                title="Governance exceptions"
                subtitle="The register is the only thing that can excuse a finding"
              >
                <ExceptionPanel exceptions={detail.exceptions} />
              </Card>
            </div>
          )}

          {atLeast(altitude, "evidence") && (
            <>
              <Card
                title="Escalation chain"
                subtitle="Reachability from this identity over grant, impersonate and admin edges"
              >
                <EscalationChain paths={detail.score?.escalation_paths ?? []} />
              </Card>

              <Card
                id="grants"
                title="Grants and the provider JSON behind them"
                subtitle="Canonical row → raw snippet, with the file and JSON pointer it came from"
              >
                <GrantEvidence grants={detail.grants} highlight={cited} />
              </Card>

              <Card title="Usage, credentials and identity linking">
                <UsageEvidence
                  activity={detail.activity}
                  credentials={detail.credentials}
                  principals={detail.principals}
                />
              </Card>

              <Card
                title="Cloud-side tags"
                subtitle="Displayed as evidence only — a tag never suppresses a finding"
              >
                {Object.keys(detail.tags).length === 0 ? (
                  <p className="text-[13px] text-fg-muted">No tags on this identity.</p>
                ) : (
                  <CodeBlock label="tags" value={prettyJson(detail.tags)} maxHeight="12rem" />
                )}
                <p className="mt-2 text-xs text-fg-muted">
                  Last activity {formatDate(detail.last_activity_at)} · first seen{" "}
                  {formatMonthLabel(detail.first_seen_month)} · employment {detail.employment_type}
                </p>
              </Card>
            </>
          )}

          {detail.findings.length > 0 && altitude === "headline" && (
            <Card title="Act on the top finding" subtitle="Investigate or ask for a least-privilege plan">
              {detail.findings[0] && <AgentPanel finding={detail.findings[0]} />}
            </Card>
          )}
        </>
      )}
    </div>
  );
}
