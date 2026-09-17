import { Link } from "react-router-dom";
import { ORG_NAME } from "../../branding";
import type { EstateSummary } from "../../api/types";
import { Brandmark } from "../Brandmark";
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
    <header className="chrome sticky top-0 z-20 flex h-14 items-center gap-3 border-b border-chrome-border px-3 lg:px-4">
      <button
        type="button"
        onClick={onOpenNav}
        aria-label="Open navigation"
        className="rounded-md border border-chrome-border p-1.5 text-chrome-fg-muted hover:bg-chrome-2 md:hidden"
      >
        <IconMenu size={16} />
      </button>

      <Link to="/" className="flex min-w-0 items-center gap-3" aria-label="ATHAR home">
        <span className="flex items-center gap-2">
          <span className="text-chrome-accent">
            <Brandmark size={20} />
          </span>
          <span className="text-[16px] font-normal tracking-[0.3em] text-chrome-fg">ATHAR</span>
        </span>
        <span className="hidden border-l border-chrome-border pl-3 text-[12px] leading-tight text-chrome-fg-muted lg:inline">
          {ORG_NAME}
        </span>
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
