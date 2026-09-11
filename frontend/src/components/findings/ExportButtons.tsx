import { useMutation } from "@tanstack/react-query";
import { exportFindings, type ExportFormat } from "../../api/endpoints";
import { toProblem } from "../../api/problem";
import type { ExportQuery } from "../../api/types";
import { saveBlob } from "../../lib/download";
import { Button } from "../ui/Button";
import { useToast } from "../ui/toast/useToast";

const FORMATS: readonly { format: ExportFormat; label: string; hint: string }[] = [
  { format: "csv", label: "CSV", hint: "Ticket-queue columns with the instance hash, root and tx" },
  { format: "pdf", label: "PDF", hint: "Board report; every page footed with the Merkle root and how to verify it" },
  { format: "json", label: "JSON", hint: "Each row's committed instance and its inclusion proof" },
];

export interface ExportButtonsProps {
  /** The filters currently on screen — the export matches what the user sees. */
  query: ExportQuery;
}

/**
 * Export the filtered findings (SPEC §16). The bytes come through the shared
 * client, so a failure renders as problem+json rather than a broken file.
 */
export function ExportButtons({ query }: ExportButtonsProps) {
  const toast = useToast();

  const download = useMutation<{ format: ExportFormat }, unknown, ExportFormat>({
    mutationFn: async (format: ExportFormat) => {
      const file = await exportFindings(format, query);
      saveBlob(file.blob, file.filename);
      return { format };
    },
    onSuccess: ({ format }) => {
      toast.push({
        tone: "success",
        title: `${format.toUpperCase()} export downloaded`,
        detail: "It carries the scan's Merkle root; verify it with `make verify`.",
      });
    },
    onError: (error) => {
      const problem = toProblem(error);
      toast.push({ tone: "danger", title: problem.title, detail: problem.detail ?? problem.code });
    },
  });

  return (
    <div className="flex flex-wrap items-center gap-2">
      <span className="text-xs text-fg-muted">Export these findings:</span>
      {FORMATS.map(({ format, label, hint }) => (
        <Button
          key={format}
          size="sm"
          variant="secondary"
          title={hint}
          loading={download.isPending && download.variables === format}
          disabled={download.isPending}
          onClick={() => download.mutate(format)}
        >
          {label}
        </Button>
      ))}
    </div>
  );
}
