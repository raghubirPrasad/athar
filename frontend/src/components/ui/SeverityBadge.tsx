import { cn } from "../../lib/cn";
import { severityTone } from "./severity";

export interface SeverityBadgeProps {
  severity: string | null | undefined;
  size?: "sm" | "md";
  className?: string;
}

/**
 * Severity chip: colour, a distinct glyph and the level word — never colour
 * alone (CLAUDE.md frontend conventions, PRD §8.5).
 */
export function SeverityBadge({ severity, size = "sm", className }: SeverityBadgeProps) {
  const tone = severityTone(severity);
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded border font-semibold whitespace-nowrap",
        size === "sm" ? "px-1.5 py-px text-xs leading-5" : "px-2 py-0.5 text-sm leading-6",
        tone.className,
        className,
      )}
      data-severity={tone.severity}
    >
      <span aria-hidden="true" className="text-[0.85em] leading-none">
        {tone.glyph}
      </span>
      <span className="sr-only">Severity: </span>
      {tone.label}
    </span>
  );
}
