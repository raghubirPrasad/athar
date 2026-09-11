import { Link } from "react-router-dom";
import { APP_NAME } from "../../branding";
import type { EstateSummary } from "../../api/types";
import { LedgerStatusBadge } from "../LedgerStatusBadge";
import { MonthBadge } from "../MonthBadge";
import { IconMenu } from "../icons";
import { UserMenu } from "./UserMenu";

export interface TopBarProps {
  summary?: EstateSummary;
  onOpenNav: () => void;
}

/** Product name, customer, current simulated month, ledger status, user menu. */
export function TopBar({ summary, onOpenNav }: TopBarProps) {
  return (
    <header className="sticky top-0 z-20 flex h-12 items-center gap-3 border-b border-border bg-surface px-3">
      <button
        type="button"
        onClick={onOpenNav}
        aria-label="Open navigation"
        className="rounded-md border border-border p-1.5 text-fg-muted hover:bg-surface-muted md:hidden"
      >
        <IconMenu size={16} />
      </button>

      <Link to="/" className="flex min-w-0 items-baseline gap-2">
        <span className="shrink-0 text-sm font-semibold tracking-[0.14em] text-accent-strong">{APP_NAME}</span>
      </Link>

      <div className="ml-auto flex items-center gap-2">
        {summary && (
          <>
            {/*
              `max-sm:hidden`, not `hidden sm:inline-flex`: both badges carry
              `inline-flex` in their own base classes, and Tailwind emits
              `.inline-flex` after `.hidden`, so a plain `hidden` would lose.
              A variant always sorts after an unprefixed utility.
            */}
            <MonthBadge
              month={summary.current_month}
              label={summary.current_month_label}
              className="max-sm:hidden"
            />
            <LedgerStatusBadge
              status={summary.ledger.status}
              scanId={summary.ledger.last_scan_id}
              className="max-sm:hidden"
            />
          </>
        )}
        <UserMenu />
      </div>
    </header>
  );
}
