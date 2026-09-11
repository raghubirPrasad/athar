import { cn } from "../../lib/cn";

export interface SkeletonProps {
  /** Number of stacked placeholder lines. */
  lines?: number;
  className?: string;
  /** Height of a single line block, e.g. "h-8". */
  height?: string;
}

/** Loading placeholder. Hidden from assistive tech; put aria-busy on the container. */
export function Skeleton({ lines = 1, className, height = "h-3.5" }: SkeletonProps) {
  return (
    <div className={cn("flex flex-col gap-2", className)} aria-hidden="true">
      {Array.from({ length: lines }, (_, i) => (
        <div
          key={i}
          className={cn("animate-pulse rounded bg-surface-muted", height)}
          style={{ width: lines > 1 && i === lines - 1 ? "60%" : "100%" }}
        />
      ))}
    </div>
  );
}

export function SkeletonTable({ rows = 8, cols = 5 }: { rows?: number; cols?: number }) {
  return (
    <div className="divide-y divide-border" aria-hidden="true">
      {Array.from({ length: rows }, (_, r) => (
        <div key={r} className="flex gap-3 px-3 py-2">
          {Array.from({ length: cols }, (_, c) => (
            <div key={c} className="h-3.5 flex-1 animate-pulse rounded bg-surface-muted" />
          ))}
        </div>
      ))}
    </div>
  );
}

export function SkeletonTiles({ count = 4 }: { count?: number }) {
  return (
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4" aria-hidden="true">
      {Array.from({ length: count }, (_, i) => (
        <div key={i} className="h-20 animate-pulse rounded-lg border border-border bg-surface-muted" />
      ))}
    </div>
  );
}
