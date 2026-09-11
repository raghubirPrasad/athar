import { Link } from "react-router-dom";
import type { HalfLifeLabel } from "../../api/types";
import { cn } from "../../lib/cn";
import { formatHalfLife } from "../../lib/format";

interface Look {
  className: string;
  glyph: string;
}

const LABEL_LOOK: Record<HalfLifeLabel, Look> = {
  Healthy: { className: "border-ok/40 bg-ok-soft text-ok", glyph: "✓" },
  Slow: { className: "border-warn/40 bg-warn-soft text-warn", glyph: "!" },
  Broken: { className: "border-danger/40 bg-danger-soft text-danger", glyph: "✕" },
};

/** A diagnosis this build does not know: shown plainly, never guessed at. */
const UNKNOWN_LOOK: Look = { className: "border-border bg-surface-muted text-fg-muted", glyph: "–" };

export interface HalfLifeValueProps {
  /** Median months a revoked grant survived; null is "Never" (SPEC §9.3). */
  months: number | null | undefined;
  label: HalfLifeLabel;
  /**
   * Where the grants and revocations behind this median are shown. Set it and
   * the value becomes a link (PRD §8.2: every number is a link to its
   * evidence); leave it off on the page that already *is* the evidence.
   */
  to?: string;
  /** Accessible name for that link, e.g. "Half-life evidence for Finance". */
  linkLabel?: string;
  className?: string;
}

/**
 * Permission Half-Life (SPEC §9.3): the organisational finding. `null` months is
 * "Never" — the sentence that changes what an agency does on Monday (PRD §2).
 */
export function HalfLifeValue({ months, label, to, linkLabel, className }: HalfLifeValueProps) {
  // A label the backend adds later must not unmount the page it appears on.
  const look = LABEL_LOOK[label] ?? UNKNOWN_LOOK;
  const body = (
    <>
      <span className="tabular text-sm font-semibold text-fg">{formatHalfLife(months)}</span>
      <span
        className={cn(
          "inline-flex items-center gap-1 rounded border px-1.5 py-px text-xs font-medium",
          look.className,
        )}
      >
        <span aria-hidden="true">{look.glyph}</span>
        {label}
      </span>
    </>
  );

  if (to) {
    return (
      <Link
        to={to}
        aria-label={linkLabel}
        className={cn(
          "inline-flex items-center gap-1.5 rounded-sm underline decoration-border decoration-dotted underline-offset-4",
          "hover:decoration-accent focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent",
          className,
        )}
      >
        {body}
      </Link>
    );
  }

  return <span className={cn("inline-flex items-center gap-1.5", className)}>{body}</span>;
}
