import type { ReactNode } from "react";
import { cn } from "../../lib/cn";

export interface CardProps {
  title?: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  children?: ReactNode;
  className?: string;
  /** Remove body padding for tables that should run edge to edge. */
  flush?: boolean;
  id?: string;
}

export function Card({ title, subtitle, actions, children, className, flush = false, id }: CardProps) {
  return (
    // `min-w-0`: a card holding a wide table or a JSON block is often a grid
    // item, and a grid item's automatic minimum size is its content's
    // min-content — which pushes the whole column, and the page, sideways on a
    // narrow screen. Zeroing it lets the card take the track it is given and
    // the panels inside it scroll on their own (`TableWrap`, `CodeBlock`).
    <section id={id} className={cn("min-w-0 rounded-md border border-border bg-surface shadow-card", className)}>
      {(title || actions) && (
        <header className="flex items-start justify-between gap-3 border-b border-border bg-surface-muted/40 px-4 py-3">
          <div className="min-w-0">
            {title && <h2 className="truncate text-[15px] font-medium text-fg">{title}</h2>}
            {subtitle && <p className="mt-0.5 text-[13px] text-fg-muted">{subtitle}</p>}
          </div>
          {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={flush ? undefined : "p-4"}>{children}</div>
    </section>
  );
}

/** Sub-block inside a card with its own small heading. */
export function CardSection({ title, children, className }: { title?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <div className={cn("border-t border-border px-4 py-3 first:border-t-0", className)}>
      {title && <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-fg-muted">{title}</h3>}
      {children}
    </div>
  );
}
