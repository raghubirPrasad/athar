import { cn } from "../lib/cn";
import { formatMonthLabel } from "../lib/format";
import { IconCalendar } from "./icons";

export interface MonthBadgeProps {
  /** Simulated month index (1 = September 2025), as the API reports it. */
  month: number | null | undefined;
  /** The API's own label, preferred when present so UI and backend never disagree. */
  label?: string | null;
  className?: string;
}

/** Current simulated month (SPEC §4.2). The estate has no wall clock. */
export function MonthBadge({ month, label, className }: MonthBadgeProps) {
  const text = label ?? (typeof month === "number" ? formatMonthLabel(month) : "—");
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded border border-border bg-surface-muted px-2 py-0.5 text-xs font-medium text-fg-muted whitespace-nowrap",
        className,
      )}
      title={typeof month === "number" ? `Simulated month ${month} of the estate` : undefined}
    >
      <IconCalendar size={13} />
      <span className="sr-only">Current month: </span>
      {text}
      {typeof month === "number" && <span className="tabular text-fg-faint">· m{month}</span>}
    </span>
  );
}
