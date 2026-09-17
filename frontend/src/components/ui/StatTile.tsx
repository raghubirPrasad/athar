import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { cn } from "../../lib/cn";

export type StatTone = "neutral" | "accent" | "ok" | "warn" | "danger";

const VALUE_TONE: Record<StatTone, string> = {
  neutral: "text-fg",
  accent: "text-accent-strong",
  ok: "text-ok",
  warn: "text-warn",
  danger: "text-danger",
};

export interface StatTileProps {
  label: ReactNode;
  value: ReactNode;
  hint?: ReactNode;
  tone?: StatTone;
  icon?: ReactNode;
  /** Router destination for the evidence behind this number. */
  to?: string;
  /** Alternative to `to` when evidence opens in place (drawer, filter). */
  onClick?: () => void;
  className?: string;
}

const FRAME =
  "group relative flex w-full flex-col gap-1.5 overflow-hidden rounded-md border border-border bg-surface px-4 py-3.5 text-left shadow-card";
const INTERACTIVE =
  "cursor-pointer transition-all hover:border-accent hover:bg-accent-soft/30 hover:shadow-raise";
/** A hairline accent seam along the top edge — the small mark of a considered dashboard. */
const SEAM = "before:absolute before:inset-x-0 before:top-0 before:h-[2px] before:bg-accent/70 before:content-['']";

/**
 * KPI tile. PRD §8.2: every number is a link to its evidence — pass `to` or
 * `onClick`; a tile without either renders static and is meant for labels only.
 */
export function StatTile({ label, value, hint, tone = "neutral", icon, to, onClick, className }: StatTileProps) {
  const body = (
    <>
      <span className="flex items-center justify-between gap-2 text-xs font-medium uppercase tracking-wide text-fg-muted">
        {label}
        {icon && <span aria-hidden="true" className="text-fg-faint">{icon}</span>}
      </span>
      <span className={cn("tabular text-[30px] font-light leading-none tracking-tight", VALUE_TONE[tone])}>{value}</span>
      {hint && <span className="text-[13px] text-fg-muted group-hover:text-fg">{hint}</span>}
    </>
  );

  if (to) {
    return (
      <Link to={to} className={cn(FRAME, SEAM, INTERACTIVE, className)}>
        {body}
      </Link>
    );
  }
  if (onClick) {
    return (
      <button type="button" onClick={onClick} className={cn(FRAME, SEAM, INTERACTIVE, className)}>
        {body}
      </button>
    );
  }
  return <div className={cn(FRAME, SEAM, className)}>{body}</div>;
}
