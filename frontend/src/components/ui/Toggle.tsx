import { useRef, type ReactNode } from "react";
import { nextIndexFromKey } from "../../lib/keyboard";
import { cn } from "../../lib/cn";

export interface ToggleOption<T extends string> {
  value: T;
  label: string;
  /** Optional glyph so the selected option is not signalled by colour alone. */
  icon?: ReactNode;
  hint?: string;
}

export interface ToggleProps<T extends string> {
  /** Accessible name, e.g. "Altitude". */
  label: string;
  value: T;
  options: readonly ToggleOption<T>[];
  onChange: (value: T) => void;
  size?: "sm" | "md";
  className?: string;
}

/**
 * Segmented control (the Headline / Explanation / Evidence altitude switch,
 * PRD §6). WAI-ARIA radiogroup: arrow keys move and select, Home/End jump,
 * only the selected option is in the tab order.
 */
export function Toggle<T extends string>({
  label,
  value,
  options,
  onChange,
  size = "md",
  className,
}: ToggleProps<T>) {
  const refs = useRef<Array<HTMLButtonElement | null>>([]);
  const selected = Math.max(
    0,
    options.findIndex((o) => o.value === value),
  );

  function onKeyDown(event: React.KeyboardEvent<HTMLButtonElement>, index: number) {
    const next = nextIndexFromKey(event.key, index, options.length);
    if (next === null) return;
    event.preventDefault();
    const option = options[next];
    if (!option) return;
    onChange(option.value);
    refs.current[next]?.focus();
  }

  return (
    <div
      role="radiogroup"
      aria-label={label}
      className={cn(
        "inline-flex items-center gap-0.5 rounded-md border border-border bg-surface-muted p-0.5",
        className,
      )}
    >
      {options.map((option, index) => {
        const isSelected = index === selected;
        return (
          <button
            key={option.value}
            ref={(el) => {
              refs.current[index] = el;
            }}
            type="button"
            role="radio"
            aria-checked={isSelected}
            title={option.hint}
            tabIndex={isSelected ? 0 : -1}
            onClick={() => onChange(option.value)}
            onKeyDown={(e) => onKeyDown(e, index)}
            className={cn(
              "inline-flex items-center gap-1.5 rounded font-medium transition-colors",
              size === "sm" ? "h-6 px-2 text-xs" : "h-7 px-2.5 text-[13px]",
              isSelected
                ? "bg-surface text-fg shadow-card"
                : "text-fg-muted hover:bg-surface/60 hover:text-fg",
            )}
          >
            {option.icon && (
              <span aria-hidden="true" className="inline-flex">
                {option.icon}
              </span>
            )}
            {option.label}
          </button>
        );
      })}
    </div>
  );
}
