import { useMutation } from "@tanstack/react-query";
import { verifyLedgerScan } from "../../api/endpoints";
import { toProblem } from "../../api/problem";
import type { LedgerVerifyOut } from "../../api/types";
import { cn } from "../../lib/cn";
import { Button } from "../ui/Button";
import { CodeBlock } from "../ui/CodeBlock";
import { ErrorState } from "../ui/ErrorState";
import { useToast } from "../ui/toast/useToast";

export interface VerifyScanButtonProps {
  scanId: number;
  label?: string;
  size?: "sm" | "md";
  className?: string;
}

/**
 * Recompute a scan's Merkle root from the database and compare it with the root
 * the contract holds (SPEC §12.6). Both roots are printed, PASS or FAIL — the
 * point is that a judge can see the two values, not a green tick.
 */
export function VerifyScanButton({ scanId, label = "Verify on chain", size = "sm", className }: VerifyScanButtonProps) {
  const toast = useToast();
  const verify = useMutation<LedgerVerifyOut, unknown, void>({
    mutationFn: () => verifyLedgerScan(scanId),
    onSuccess: (result) => {
      toast.push({
        tone: result.passed ? "success" : "danger",
        title: result.passed ? `Scan ${scanId}: roots match` : `Scan ${scanId}: verification FAILED`,
        detail: result.detail,
      });
    },
    onError: (error) => {
      const problem = toProblem(error);
      toast.push({ tone: "danger", title: problem.title, detail: problem.detail ?? problem.code });
    },
  });

  const result = verify.data;

  return (
    <div className={cn("flex flex-col items-start gap-1.5", className)}>
      <Button size={size} variant="secondary" loading={verify.isPending} onClick={() => verify.mutate()}>
        {label}
      </Button>

      {verify.isError && <ErrorState compact error={verify.error} onRetry={() => verify.mutate()} />}

      {result && (
        <div
          role="status"
          className={cn(
            "w-full rounded-md border px-2 py-1.5 text-xs",
            result.passed ? "border-ok/40 bg-ok-soft" : "border-danger/40 bg-danger-soft",
          )}
        >
          <p className={cn("font-semibold", result.passed ? "text-ok" : "text-danger")}>
            <span aria-hidden="true">{result.passed ? "✓ " : "✕ "}</span>
            {result.passed ? "PASS" : "FAIL"} · {result.detail}
          </p>
          <dl className="mt-1 grid gap-1 sm:grid-cols-[8.5rem_minmax(0,1fr)]">
            <dt className="text-fg-muted">Recomputed root</dt>
            <dd>
              <CodeBlock inline value={result.computed_root ?? "—"} label="computed root" />
            </dd>
            <dt className="text-fg-muted">Root on chain</dt>
            <dd>
              <CodeBlock inline value={result.chain_root ?? "—"} label="chain root" />
            </dd>
            <dt className="text-fg-muted">Findings hashed</dt>
            <dd className="tabular text-fg">{result.finding_count}</dd>
          </dl>
        </div>
      )}
    </div>
  );
}
