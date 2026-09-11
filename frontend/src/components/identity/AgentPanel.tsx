import { useMutation, useQueryClient } from "@tanstack/react-query";
import { investigateFinding, planRemediation } from "../../api/endpoints";
import { toProblem } from "../../api/problem";
import type { FindingOut, InvestigationOut, RemediationPlanOut } from "../../api/types";
import { RoleGate } from "../../auth/RoleGate";
import { formatRatioPct } from "../../lib/format";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { ErrorState } from "../ui/ErrorState";
import { useToast } from "../ui/toast/useToast";
import { PlanCard } from "../remediation/PlanCard";
import { actionLabel } from "../remediation/planMeta";

/** "Proposed by ATHAR agent · model X · validated against rules" (SPEC §11.1). */
function provenanceLine(source: {
  generated_by: "model" | "template";
  model_id?: string | null;
  prompt_version?: string | null;
  cached?: boolean;
}): string {
  const origin =
    source.generated_by === "model"
      ? `Written by ${source.model_id ?? "an unnamed model"}`
      : "Written from a deterministic template — no model was called";
  const prompt = source.prompt_version ? ` · prompt ${source.prompt_version}` : "";
  const cache = source.cached ? " · served from the cache" : " · generated now";
  return `${origin}${prompt}${cache}`;
}

function InvestigationView({ investigation }: { investigation: InvestigationOut }) {
  return (
    <div className="flex flex-col gap-2">
      <p className="text-[13px] leading-6 text-fg">{investigation.hypothesis}</p>
      <div className="flex flex-wrap items-center gap-1.5">
        <Badge tone={investigation.is_expected_for_role ? "ok" : "warn"}>
          {investigation.is_expected_for_role ? "Expected for this role" : "Not expected for this role"}
        </Badge>
        <Badge tone="neutral">Confidence {formatRatioPct(investigation.confidence, 0)}</Badge>
        <Badge tone="accent">Suggests: {actionLabel(investigation.recommended_action)}</Badge>
      </div>
      {investigation.rationale && <p className="text-[13px] text-fg-muted">{investigation.rationale}</p>}
      {investigation.evidence_cited.length > 0 && (
        <p className="text-xs text-fg-muted">
          Cites <span className="font-mono text-fg">{investigation.evidence_cited.join(", ")}</span>
        </p>
      )}
      <p className="text-xs text-fg-faint">{provenanceLine(investigation)}</p>
    </div>
  );
}

export interface AgentPanelProps {
  finding: FindingOut;
}

/**
 * Investigate and Plan remediation for one finding (SPEC §11, §14). Cached
 * output renders instantly because it arrives with the finding; Regenerate is
 * the only thing that calls the provider, so a demo never waits on a network
 * hop (PRD §8.6). The agent can neither create a finding nor change a severity.
 */
export function AgentPanel({ finding }: AgentPanelProps) {
  const queryClient = useQueryClient();
  const toast = useToast();

  const refreshFinding = () => {
    void queryClient.invalidateQueries({ queryKey: ["identities"] });
    void queryClient.invalidateQueries({ queryKey: ["findings"] });
    void queryClient.invalidateQueries({ queryKey: ["remediation"] });
  };

  const investigate = useMutation<InvestigationOut, unknown, boolean>({
    mutationFn: (regenerate: boolean) => investigateFinding(finding.finding_key, regenerate),
    onSuccess: (result) => {
      refreshFinding();
      toast.push({
        tone: "success",
        title: "Investigation ready",
        detail: provenanceLine(result),
      });
    },
    onError: (error) => {
      const problem = toProblem(error);
      toast.push({ tone: "danger", title: problem.title, detail: problem.detail ?? problem.code });
    },
  });

  const plan = useMutation<RemediationPlanOut, unknown, boolean>({
    mutationFn: (regenerate: boolean) => planRemediation(finding.finding_key, regenerate),
    onSuccess: (result) => {
      refreshFinding();
      toast.push({
        tone: "success",
        title: `Plan ${result.plan_id} proposed`,
        detail: `${actionLabel(result.action)} · ${result.privilege_reduction_pct.toFixed(1)}% privilege removed. An approver decides.`,
      });
    },
    onError: (error) => {
      const problem = toProblem(error);
      toast.push({ tone: "danger", title: problem.title, detail: problem.detail ?? problem.code });
    },
  });

  const investigation = investigate.data ?? finding.investigation ?? null;
  const proposal = plan.data ?? finding.plan ?? null;

  return (
    <div className="flex flex-col gap-3">
      <p className="text-xs text-fg-muted">
        The rule engine decided this finding, its severity and its score. The agent only explains it and picks one of
        the actions the rule allows:{" "}
        <span className="font-mono text-fg">{finding.allowed_actions.map(actionLabel).join(" · ")}</span>
      </p>

      <RoleGate
        min="analyst"
        fallback={
          <p className="text-xs text-fg-muted">
            Sign in as an analyst to run the investigation or ask for a remediation plan.
          </p>
        }
      >
        <div className="flex flex-wrap items-center gap-2">
          <Button
            size="sm"
            variant={investigation ? "secondary" : "primary"}
            loading={investigate.isPending}
            onClick={() => investigate.mutate(false)}
          >
            {investigation ? "Investigate again" : "Investigate"}
          </Button>
          {investigation && (
            <Button
              size="sm"
              variant="ghost"
              loading={investigate.isPending}
              onClick={() => investigate.mutate(true)}
              title="Bypass the LLM cache and call the provider again"
            >
              Regenerate
            </Button>
          )}
          <Button
            size="sm"
            variant={proposal ? "secondary" : "primary"}
            loading={plan.isPending}
            onClick={() => plan.mutate(false)}
          >
            {proposal ? "Re-plan remediation" : "Plan remediation"}
          </Button>
          {proposal && (
            <Button
              size="sm"
              variant="ghost"
              loading={plan.isPending}
              onClick={() => plan.mutate(true)}
              title="Bypass the LLM cache and call the provider again"
            >
              Regenerate plan
            </Button>
          )}
        </div>
      </RoleGate>

      {investigate.isError && <ErrorState compact error={investigate.error} />}
      {plan.isError && <ErrorState compact error={plan.error} />}

      {investigation && (
        <section className="rounded-md border border-border bg-surface-muted p-3">
          <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-fg-muted">Investigation</h4>
          <InvestigationView investigation={investigation} />
        </section>
      )}

      {proposal && <PlanCard plan={proposal} showIdentity={false} />}
    </div>
  );
}
