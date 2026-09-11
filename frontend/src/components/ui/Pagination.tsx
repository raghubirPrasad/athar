import { formatInt } from "../../lib/format";
import { Button } from "./Button";

export interface PaginationProps {
  total: number;
  limit: number;
  offset: number;
  onOffsetChange: (offset: number) => void;
  /** Noun for the rows, e.g. "identities". */
  unit?: string;
}

/** Offset pagination over a server-side `Page[T]` (SPEC §13: limit ≤ 500). */
export function Pagination({ total, limit, offset, onOffsetChange, unit = "rows" }: PaginationProps) {
  const from = total === 0 ? 0 : offset + 1;
  const to = Math.min(total, offset + limit);
  const canPrev = offset > 0;
  const canNext = to < total;
  return (
    <div className="flex items-center justify-between gap-3 px-1 py-2">
      <p className="tabular text-xs text-fg-muted" aria-live="polite">
        {formatInt(from)}–{formatInt(to)} of {formatInt(total)} {unit}
      </p>
      <div className="flex items-center gap-2">
        <Button size="sm" disabled={!canPrev} onClick={() => onOffsetChange(Math.max(0, offset - limit))}>
          Previous
        </Button>
        <Button size="sm" disabled={!canNext} onClick={() => onOffsetChange(offset + limit)}>
          Next
        </Button>
      </div>
    </div>
  );
}
