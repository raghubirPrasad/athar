import { Link } from "react-router-dom";
import type { RemediationPlanOut } from "../../api/types";
import { formatDate, formatPct, formatRatioPct } from "../../lib/format";
import { ruleLabel } from "../../lib/rules";
import { Badge } from "../ui/Badge";
import { Card, CardSection } from "../ui/Card";
import { DecisionTrail } from "./DecisionTrail";
import { PlanActions } from "./PlanActions";
import { PolicyDiffView } from "./PolicyDiffView";
import { actionLabel, planStatusLook } from "./planMeta";

export interface PlanCardProps {
  plan: RemediationPlanOut;
  /** Hide the identity line when the card already sits on that identity's page. */
  showIdentity?: boolean;
  className?: string;
}

/** "Proposed by ATHAR agent · model X · validated against rules" (SPEC §11.1). */
function provenance(plan: RemediationPlanOut): string {
  if (plan.proposed_by === "model") {
    const model = plan.model_id ?? "an unnamed model";
    return `Proposed by the ATHAR agent · ${model} · prompt ${plan.prompt_version ?? "v1"} · validated against the rule engine`;
  }
  return "Computed deterministically by the rule engine from ninety days of activity — no model involved";
}

/**
 * One proposed least-privilege change (SPEC §11.5, §14 remediation queue):
 * what it does, why, how much privilege it removes, the provider-native diff,
 * and the human decision it is waiting for.
 */
export function PlanCard({ plan, showIdentity = true, className }: PlanCardProps) {
  const status = planStatusLook(plan.status);
  const decisions = plan.decisions ?? [];

  return (
    <Card
      className={className}
      flush
      title={
        <span className="flex flex-wrap items-center gap-2">
          {actionLabel(plan.action)}
          <Badge tone={status.tone}>
            <span aria-hidden="true">{status.glyph}</span> {status.label}
          </Badge>
          <Badge tone="neutral" mono title="Plan id">
            {plan.plan_id}
          </Badge>
        </span>
      }
      subtitle={
        showIdentity ? (
          <span className="flex flex-wrap items-center gap-1.5">
            <Link to={`/identities/${encodeURIComponent(plan.identity_id)}`} className="text-accent-strong hover:underline">
              {plan.display_name}
            </Link>
            <span className="text-fg-muted">· {ruleLabel(plan.rule_id)}</span>
            <span className="text-fg-faint">· proposed {formatDate(plan.created_at)}</span>
          </span>
        ) : (
          <span>
            {ruleLabel(plan.rule_id)} · proposed {formatDate(plan.created_at)}
          </span>
        )
      }
    >
      <CardSection>
        <p className="text-[13px] leading-6 text-fg">{plan.rationale}</p>
        <p className="mt-1.5 text-xs text-fg-muted">
          {provenance(plan)} · confidence {formatRatioPct(plan.confidence, 0)}
        </p>
      </CardSection>

      <CardSection title="What it changes">
        <dl className="grid gap-2 sm:grid-cols-3">
          <div>
            <dt className="text-xs text-fg-muted">Privilege removed</dt>
            <dd className="tabular text-lg font-semibold text-fg">{formatPct(plan.privilege_reduction_pct, 1)}</dd>
          </div>
          <div>
            <dt className="text-xs text-fg-muted">Blast radius after</dt>
            <dd className="tabular text-lg font-semibold text-fg">
              {formatPct(plan.expected_blast_radius_after * 100, 1)}
            </dd>
          </div>
          <div>
            <dt className="text-xs text-fg-muted">Grants</dt>
            <dd className="text-[13px] text-fg">
              <span className="font-semibold">{plan.drop.length}</span> dropped ·{" "}
              <span className="font-semibold">{plan.keep.length}</span> kept
            </dd>
          </div>
        </dl>
        <div className="mt-2 flex flex-col gap-1 text-[12.5px]">
          {plan.drop.length > 0 && (
            <p className="text-fg-muted">
              <span className="font-semibold text-danger">Drop</span>{" "}
              <span className="font-mono text-fg">{plan.drop.join(", ")}</span>
            </p>
          )}
          {plan.keep.length > 0 && (
            <p className="text-fg-muted">
              <span className="font-semibold text-ok">Keep</span>{" "}
              <span className="font-mono text-fg">{plan.keep.join(", ")}</span>{" "}
              <span className="text-fg-faint">— used in the last 90 days, or read-only</span>
            </p>
          )}
        </div>
      </CardSection>

      <CardSection title="Policy diff">
        <PolicyDiffView diff={plan.policy_diff} />
      </CardSection>

      <CardSection title="Decision">
        <PlanActions plan={plan} />
        <div className="mt-3">
          <DecisionTrail decisions={decisions} />
        </div>
      </CardSection>
    </Card>
  );
}
