import { useRef, type ReactNode } from "react";
import { nextIndexFromKey } from "../../lib/keyboard";
import { cn } from "../../lib/cn";

export interface TabItem<T extends string> {
  value: T;
  label: string;
  /** Small count shown after the label, e.g. finding totals. */
  badge?: ReactNode;
}

export interface TabsProps<T extends string> {
  label: string;
  value: T;
  items: readonly TabItem<T>[];
  onChange: (value: T) => void;
  /** id prefix so panels can reference their tab (`<TabPanel idBase=… />`). */
  idBase: string;
  className?: string;
}

/** Underlined tab list. Panels are rendered by the caller with <TabPanel>. */
export function Tabs<T extends string>({ label, value, items, onChange, idBase, className }: TabsProps<T>) {
  const refs = useRef<Array<HTMLButtonElement | null>>([]);
  const selected = Math.max(
    0,
    items.findIndex((i) => i.value === value),
  );

  function onKeyDown(event: React.KeyboardEvent<HTMLButtonElement>, index: number) {
    const next = nextIndexFromKey(event.key, index, items.length);
    if (next === null) return;
    event.preventDefault();
    const item = items[next];
    if (!item) return;
    onChange(item.value);
    refs.current[next]?.focus();
  }

  return (
    // `flex-wrap`, not a scroll strip: on a narrow screen every tab has to stay
    // reachable without a horizontal gesture, and at desktop widths the row
    // fits on one line so nothing moves.
    <div role="tablist" aria-label={label} className={cn("flex flex-wrap gap-1 border-b border-border", className)}>
      {items.map((item, index) => {
        const isSelected = index === selected;
        return (
          <button
            key={item.value}
            ref={(el) => {
              refs.current[index] = el;
            }}
            type="button"
            role="tab"
            id={`${idBase}-tab-${item.value}`}
            aria-selected={isSelected}
            aria-controls={`${idBase}-panel-${item.value}`}
            tabIndex={isSelected ? 0 : -1}
            onClick={() => onChange(item.value)}
            onKeyDown={(e) => onKeyDown(e, index)}
            className={cn(
              "-mb-px inline-flex items-center gap-1.5 border-b-2 px-3 py-1.5 text-[13px] font-medium transition-colors",
              isSelected
                ? "border-accent text-fg"
                : "border-transparent text-fg-muted hover:border-border-strong hover:text-fg",
            )}
          >
            {item.label}
            {item.badge !== undefined && <span className="tabular text-fg-faint">{item.badge}</span>}
          </button>
        );
      })}
    </div>
  );
}

export function TabPanel({
  idBase,
  value,
  active,
  children,
  className,
}: {
  idBase: string;
  value: string;
  active: boolean;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div
      role="tabpanel"
      id={`${idBase}-panel-${value}`}
      aria-labelledby={`${idBase}-tab-${value}`}
      hidden={!active}
      tabIndex={0}
      className={className}
    >
      {active && children}
    </div>
  );
}
