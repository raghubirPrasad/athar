import type { ReactNode } from "react";
import { cn } from "../../lib/cn";

export type BadgeTone = "neutral" | "accent" | "ok" | "warn" | "danger" | "info";

const TONE: Record<BadgeTone, string> = {
  neutral: "bg-surface-muted text-fg-muted border-border",
  accent: "bg-accent-soft text-accent-strong border-accent/30",
  ok: "bg-ok-soft text-ok border-ok/30",
  warn: "bg-warn-soft text-warn border-warn/30",
  danger: "bg-danger-soft text-danger border-danger/30",
  info: "bg-sev-low-soft text-sev-low border-sev-low/30",
};

export interface BadgeProps {
  tone?: BadgeTone;
  icon?: ReactNode;
  children: ReactNode;
  className?: string;
  title?: string;
  mono?: boolean;
}

/** Small inline label. Meaning must be carried by the text, never by the tone alone. */
export function Badge({ tone = "neutral", icon, children, className, title, mono = false }: BadgeProps) {
  return (
    <span
      title={title}
      className={cn(
        "inline-flex items-center gap-1 rounded border px-1.5 py-px text-xs font-medium leading-5 whitespace-nowrap",
        TONE[tone],
        mono && "font-mono",
        className,
      )}
    >
      {icon && <span aria-hidden="true" className="inline-flex">{icon}</span>}
      {children}
    </span>
  );
}
