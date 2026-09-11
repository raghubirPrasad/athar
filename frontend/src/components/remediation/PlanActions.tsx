import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { applyPlan, approvePlan, rejectPlan } from "../../api/endpoints";
import { toProblem } from "../../api/problem";
import type { ApplyResult, RemediationPlanOut } from "../../api/types";
import { RoleGate } from "../../auth/RoleGate";
import { formatPct, formatScore } from "../../lib/format";
import { Button } from "../ui/Button";
import { ErrorState } from "../ui/ErrorState";
import { Modal } from "../ui/Modal";
import { useToast } from "../ui/toast/useToast";
import { actionLabel } from "./planMeta";

type Pending = "approve" | "reject" | "apply" | null;

/** A blast-radius share (0–1) as the percentage the rest of the UI shows. */
function blastPct(share: number): string {
  return formatPct(share * 100, 1);
}

/**
 * What the apply actually did: the re-scan's own before/after numbers (SPEC
 * §11.5 — measured, not the plan's prediction), and anything that stopped the
 * simulated estate from changing. A warning is not a success: it is shown as a
 * standing warn-toned line, because the decision is on the ledger either way.
 */
function ApplyOutcome({ result }: { result: ApplyResult }) {
  const warnings = result.warnings ?? [];
  return (
    <div className="flex flex-col gap-1.5">
      <p className="rounded-md border border-ok/40 bg-ok-soft px-2.5 py-1.5 text-[13px] leading-5 text-fg">
        <span aria-hidden="true">✓ </span>
        Applied. Risk <span className="tabular font-semibold">{formatScore(result.score_before)}</span> →{" "}
        <span className="tabular font-semibold">{formatScore(result.score_after)}</span>, blast radius{" "}
        <span className="tabular font-semibold">{blastPct(result.blast_radius_before)}</span> →{" "}
        <span className="tabular font-semibold">{blastPct(result.blast_radius_after)}</span>, measured by re-scan{" "}
        <span className="tabular">{result.scan_id}</span> · ledger {result.ledger_status.replace(/_/g, " ")}.
      </p>
      {warnings.length > 0 && (
        <div className="rounded-md border border-warn/40 bg-warn-soft px-2.5 py-1.5 text-[13px] leading-5 text-fg">
          <p className="font-semibold">
            <span aria-hidden="true">! </span>
            {warnings.length === 1 ? "One warning" : `${warnings.length} warnings`} from the apply — the decision is
            recorded, the estate may not have changed.
          </p>
          <ul className="mt-1 flex flex-col gap-0.5 pl-4">
            {warnings.map((warning) => (
              <li key={warning} className="list-disc marker:text-warn">
                {warning}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

const INVALIDATE = [
  "remediation",
  "findings",
  "identities",
  "estate",
  "ledger",
  "scans",
  "timeline",
  "departments",
] as const;

export interface PlanActionsProps {
  plan: RemediationPlanOut;
  /** Called after a decision lands, e.g. to close a drawer. */
  onDecided?: (plan: RemediationPlanOut) => void;
}

/**
 * Approve / Reject / Apply (SPEC §11.5, §15.1). Every one is a human decision
 * that ends up on chain, so every one goes through a confirmation dialog. The
 * server owns the rules — a plan cannot be approved by the user who proposed it,
 * and `apply` needs an approved plan — so its problem+json is shown inline here
 * rather than swallowed.
 */
export function PlanActions({ plan, onDecided }: PlanActionsProps) {
  const queryClient = useQueryClient();
  const toast = useToast();
  const [pending, setPending] = useState<Pending>(null);
  const [reason, setReason] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [applied, setApplied] = useState<ApplyResult | null>(null);

  const invalidate = () => {
    for (const key of INVALIDATE) void queryClient.invalidateQueries({ queryKey: [key] });
  };

  const settle = (result: RemediationPlanOut) => {
    invalidate();
    setPending(null);
    setError(null);
    onDecided?.(result);
  };

  const fail = (err: unknown) => {
    setPending(null);
    setError(err);
    const problem = toProblem(err);
    toast.push({ tone: "danger", title: problem.title, detail: problem.detail ?? problem.code });
  };

  const approve = useMutation<RemediationPlanOut, unknown, void>({
    mutationFn: () => approvePlan(plan.plan_id),
    onSuccess: (result) => {
      settle(result);
      toast.push({
        tone: "success",
        title: `Plan ${plan.plan_id} approved`,
        detail: "The decision is recorded with a Merkle proof.",
      });
    },
    onError: fail,
  });

  const reject = useMutation<RemediationPlanOut, unknown, string>({
    mutationFn: (why: string) => rejectPlan(plan.plan_id, why),
    onSuccess: (result) => {
      settle(result);
      setReason("");
      toast.push({ tone: "success", title: `Plan ${plan.plan_id} rejected`, detail: "The finding returns to open." });
    },
    onError: fail,
  });

  const applyMutation = useMutation<ApplyResult, unknown, void>({
    mutationFn: () => applyPlan(plan.plan_id),
    onSuccess: (result) => {
      settle(result.plan);
      setApplied(result);
      toast.push({
        tone: "success",
        title: `Applied to ${result.plan.display_name}`,
        detail:
          `Risk ${formatScore(result.score_before)} → ${formatScore(result.score_after)}, ` +
          `blast radius ${blastPct(result.blast_radius_before)} → ${blastPct(result.blast_radius_after)} ` +
          `measured by re-scan ${result.scan_id}.`,
      });
    },
    onError: fail,
  });

  const busy = approve.isPending || reject.isPending || applyMutation.isPending;
  const canDecide = plan.status === "proposed";
  const canApply = plan.status === "approved";

  // An applied plan keeps its panel for as long as this view lives, so the
  // measured result and any warning stay readable after the toast has gone.
  if (!applied && (plan.status === "rejected" || plan.status === "applied")) {
    return null;
  }

  return (
    <RoleGate
      min="approver"
      fallback={
        <p className="text-xs text-fg-muted">
          Only an approver can decide this plan. Sign in as the approver account to approve, reject or apply it.
        </p>
      }
    >
      <div className="flex flex-col gap-2">
        <div className="flex flex-wrap items-center gap-2">
          {canDecide && (
            <>
              <Button variant="primary" size="sm" disabled={busy} onClick={() => setPending("approve")}>
                Approve
              </Button>
              <Button variant="secondary" size="sm" disabled={busy} onClick={() => setPending("reject")}>
                Reject
              </Button>
            </>
          )}
          {canApply && (
            <Button variant="primary" size="sm" disabled={busy} onClick={() => setPending("apply")}>
              Apply
            </Button>
          )}
          {canDecide && (
            <span className="text-xs text-fg-muted">Apply becomes available once the plan is approved.</span>
          )}
        </div>

        {applied && <ApplyOutcome result={applied} />}

        {error != null && (
          <ErrorState
            compact
            error={error}
            action={
              <Button size="sm" variant="ghost" onClick={() => setError(null)}>
                Dismiss
              </Button>
            }
          />
        )}

        <Modal
          open={pending === "approve"}
          title={`Approve plan ${plan.plan_id}?`}
          description={`${actionLabel(plan.action)} for ${plan.display_name} (${plan.rule_id}).`}
          onClose={() => setPending(null)}
          size="sm"
          footer={
            <>
              <Button size="sm" onClick={() => setPending(null)}>
                Cancel
              </Button>
              <Button size="sm" variant="primary" loading={approve.isPending} onClick={() => approve.mutate()}>
                Approve plan
              </Button>
            </>
          }
        >
          <p className="text-[13px] text-fg-muted">
            Approving records a decision on the governance ledger with your actor hash and a proof that this finding
            was in the committed scan. It does not change any cloud yet — that is Apply.
          </p>
        </Modal>

        <Modal
          open={pending === "reject"}
          title={`Reject plan ${plan.plan_id}?`}
          description="The finding returns to open and a new plan can be proposed."
          onClose={() => setPending(null)}
          size="sm"
          footer={
            <>
              <Button size="sm" onClick={() => setPending(null)}>
                Cancel
              </Button>
              <Button
                size="sm"
                variant="danger"
                loading={reject.isPending}
                disabled={reason.trim().length < 5}
                onClick={() => reject.mutate(reason.trim())}
              >
                Reject plan
              </Button>
            </>
          }
        >
          <label className="block text-[13px] font-medium text-fg-muted" htmlFor={`reject-reason-${plan.plan_id}`}>
            Reason (recorded in the audit trail)
            <textarea
              id={`reject-reason-${plan.plan_id}`}
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              rows={3}
              className="mt-1 w-full rounded-md border border-border bg-surface px-2.5 py-1.5 text-sm text-fg"
              placeholder="Why is this change not right?"
            />
            {/* Say why the button is dead rather than leaving the approver to guess. */}
            <span className="mt-1 block text-xs font-normal text-fg-faint">
              {reason.trim().length < 5
                ? "At least five characters — the reason is recorded on the ledger, so it has to say something."
                : "This reason is recorded with the decision."}
            </span>
          </label>
        </Modal>

        <Modal
          open={pending === "apply"}
          title={`Apply plan ${plan.plan_id}?`}
          description={`${actionLabel(plan.action)} for ${plan.display_name}.`}
          onClose={() => setPending(null)}
          size="sm"
          footer={
            <>
              <Button size="sm" onClick={() => setPending(null)}>
                Cancel
              </Button>
              <Button size="sm" variant="primary" loading={applyMutation.isPending} onClick={() => applyMutation.mutate()}>
                Apply change
              </Button>
            </>
          }
        >
          <p className="text-[13px] text-fg-muted">
            Applying writes the change into the simulated estate, re-ingests and re-scans the current month, and
            records <code className="font-mono">remediation_applied</code> on the ledger. The before/after score and blast
            radius are reported when it finishes, measured by that re-scan rather than predicted.
          </p>
        </Modal>
      </div>
    </RoleGate>
  );
}
