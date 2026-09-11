import { useMutation, useQueryClient } from "@tanstack/react-query";
import { advanceMonth, runScan } from "../../api/endpoints";
import { toProblem } from "../../api/problem";
import { RoleGate } from "../../auth/RoleGate";
import { formatMonthLabel } from "../../lib/format";
import { Button } from "../ui/Button";
import { IconAdvance, IconScan } from "../icons";
import { useToast } from "../ui/toast/useToast";

/**
 * Analyst controls (SPEC §14 Overview). Both are POSTs, so the client adds
 * `X-Requested-With: athar`; on success every cached view of the estate is
 * invalidated so the new scan's numbers appear everywhere at once.
 */
export function ScanActions() {
  const queryClient = useQueryClient();
  const toast = useToast();

  const invalidateEstate = () => {
    for (const key of ["estate", "identities", "findings", "departments", "scans", "ledger", "timeline", "remediation"]) {
      void queryClient.invalidateQueries({ queryKey: [key] });
    }
  };

  const scan = useMutation({
    mutationFn: () => runScan(),
    onSuccess: (result) => {
      invalidateEstate();
      toast.push({
        tone: "success",
        title: `Scan ${result.scan_id} complete`,
        detail: `${result.finding_count} findings · ledger ${result.ledger_status}`,
      });
    },
    onError: (error) => {
      const problem = toProblem(error);
      toast.push({ tone: "danger", title: problem.title, detail: problem.detail ?? problem.code });
    },
  });

  const advance = useMutation({
    mutationFn: () => advanceMonth(),
    onSuccess: (result) => {
      invalidateEstate();
      toast.push({
        tone: "success",
        title: `Advanced to ${formatMonthLabel(result.new_month)}`,
        detail: `Scan ${result.scan.scan_id} · ${result.scan.finding_count} findings`,
      });
    },
    onError: (error) => {
      const problem = toProblem(error);
      toast.push({ tone: "danger", title: problem.title, detail: problem.detail ?? problem.code });
    },
  });

  return (
    <RoleGate min="analyst">
      <Button
        variant="secondary"
        loading={advance.isPending}
        disabled={scan.isPending}
        iconStart={<IconAdvance size={14} />}
        onClick={() => advance.mutate()}
      >
        Advance month
      </Button>
      <Button
        variant="primary"
        loading={scan.isPending}
        disabled={advance.isPending}
        iconStart={<IconScan size={14} />}
        onClick={() => scan.mutate()}
      >
        Run scan
      </Button>
    </RoleGate>
  );
}
