import type { ReactNode } from "react";
import { toProblem } from "../../api/problem";
import { cn } from "../../lib/cn";
import { Badge } from "./Badge";
import { Button } from "./Button";

export interface ErrorStateProps {
  error: unknown;
  onRetry?: () => void;
  action?: ReactNode;
  compact?: boolean;
  className?: string;
}

/** Renders an RFC 7807 problem: title, detail, stable code. Never a stack trace. */
export function ErrorState({ error, onRetry, action, compact = false, className }: ErrorStateProps) {
  const p = toProblem(error);
  return (
    <div
      role="alert"
      className={cn(
        "rounded-lg border border-danger/40 bg-danger-soft text-fg",
        compact ? "px-3 py-2" : "px-4 py-3",
        className,
      )}
    >
      <div className="flex flex-wrap items-center gap-2">
        <span aria-hidden="true" className="font-semibold text-danger">
          !
        </span>
        <p className="text-sm font-semibold">{p.title}</p>
        {p.code && (
          <Badge tone="danger" mono title="Error code">
            {p.code}
          </Badge>
        )}
        {p.status && <span className="text-xs text-fg-muted">HTTP {p.status}</span>}
      </div>
      {p.detail && <p className="mt-1 text-[13px] text-fg-muted">{p.detail}</p>}
      {(onRetry || action) && (
        <div className="mt-2 flex gap-2">
          {onRetry && (
            <Button size="sm" variant="secondary" onClick={onRetry}>
              Retry
            </Button>
          )}
          {action}
        </div>
      )}
    </div>
  );
}
