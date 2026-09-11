import type { ReactNode } from "react";
import { cn } from "../../lib/cn";

export interface EmptyStateProps {
  title: string;
  description?: ReactNode;
  action?: ReactNode;
  icon?: ReactNode;
  compact?: boolean;
  className?: string;
}

/** Designed empty state (SPEC §14 UI rules). Use for "no rows", "not yet scanned", etc. */
export function EmptyState({ title, description, action, icon, compact = false, className }: EmptyStateProps) {
  return (
    <div
      role="status"
      className={cn(
        "flex flex-col items-center justify-center rounded-lg border border-dashed border-border-strong bg-surface text-center",
        compact ? "gap-1 px-4 py-6" : "gap-2 px-6 py-12",
        className,
      )}
    >
      {icon && <div aria-hidden="true" className="mb-1 text-fg-faint">{icon}</div>}
      <p className="text-sm font-semibold text-fg">{title}</p>
      {description && <p className="max-w-md text-[13px] text-fg-muted">{description}</p>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
}
