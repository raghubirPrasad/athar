import { Link } from "react-router-dom";
import type { LedgerBadgeStatus } from "../api/types";
import { cn } from "../lib/cn";

/**
 * Governance-ledger status (SPEC §14 Overview, §12.1). Status is carried by a
 * word and a glyph as well as a colour, and the badge links to the ledger page,
 * which is where the limits of the anchoring are stated.
 */
interface Look {
  label: string;
  glyph: string;
  className: string;
  hint: string;
}

const LOOK: Record<LedgerBadgeStatus, Look> = {
  anchored: {
    label: "Anchored",
    glyph: "✓",
    className: "border-ok/40 bg-ok-soft text-ok",
    hint: "The latest scan's Merkle root is committed on chain",
  },
  pending: {
    label: "Pending",
    glyph: "◷",
    className: "border-warn/40 bg-warn-soft text-warn",
    hint: "A commit for the latest scan has been sent but not confirmed",
  },
  unanchored: {
    label: "Unanchored",
    glyph: "○",
    className: "border-border bg-surface-muted text-fg-muted",
    hint: "The latest scan has not been committed to the ledger",
  },
  verification_failed: {
    label: "Verification failed",
    glyph: "✕",
    className: "border-danger/40 bg-danger-soft text-danger",
    hint: "The recomputed root does not match the root on chain",
  },
  disabled: {
    label: "Ledger off",
    glyph: "–",
    className: "border-border bg-surface-muted text-fg-faint",
    hint: "Ledger anchoring is disabled in this deployment",
  },
};

export interface LedgerStatusBadgeProps {
  status: LedgerBadgeStatus;
  scanId?: number | null;
  /** Render as a link to the ledger page (default). */
  linked?: boolean;
  className?: string;
}

export function LedgerStatusBadge({ status, scanId, linked = true, className }: LedgerStatusBadgeProps) {
  const look = LOOK[status] ?? LOOK.unanchored;
  const body = (
    <>
      <span aria-hidden="true">{look.glyph}</span>
      <span className="sr-only">Ledger status: </span>
      Ledger: {look.label}
      {scanId != null && <span className="tabular text-fg-muted">· scan {scanId}</span>}
    </>
  );
  const classes = cn(
    "inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-xs font-medium whitespace-nowrap",
    look.className,
    className,
  );
  if (!linked) {
    return (
      <span className={classes} title={look.hint} data-ledger-status={status}>
        {body}
      </span>
    );
  }
  return (
    <Link to="/ledger" className={cn(classes, "hover:border-accent")} title={look.hint} data-ledger-status={status}>
      {body}
    </Link>
  );
}
