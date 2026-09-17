import type { ReactNode } from "react";
import { cn } from "../../lib/cn";
import { usePageTitle } from "../../lib/usePageTitle";

export interface PageHeaderProps {
  title: string;
  /** One sentence saying what this page answers (PRD §6). */
  description?: ReactNode;
  actions?: ReactNode;
  meta?: ReactNode;
  className?: string;
}

/** Page title block; also owns `document.title` for the route (one per page). */
export function PageHeader({ title, description, actions, meta, className }: PageHeaderProps) {
  usePageTitle(title);
  return (
    <header className={cn("flex flex-wrap items-start justify-between gap-3", className)}>
      <div className="min-w-0">
        <h1 className="text-[26px] font-light leading-tight tracking-tight text-fg">{title}</h1>
        {description && <p className="mt-1 max-w-3xl text-[13px] text-fg-muted">{description}</p>}
        {meta && <div className="mt-2 flex flex-wrap items-center gap-2">{meta}</div>}
      </div>
      {/*
        Below `sm` the action cluster takes its own full-width line and wraps
        inside it; `shrink-0` there would hold it at max-content and push the
        body sideways (the identity drill-down carries a toggle and a link).
      */}
      {actions && (
        <div className="flex flex-wrap items-center gap-2 max-sm:w-full sm:shrink-0">{actions}</div>
      )}
    </header>
  );
}
