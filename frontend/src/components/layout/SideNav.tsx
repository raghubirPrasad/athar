import { NavLink } from "react-router-dom";
import { cn } from "../../lib/cn";
import { NAV_ITEMS } from "./navItems";

export interface SideNavProps {
  /** Drawer mode always shows labels and closes the drawer on navigation. */
  expanded?: boolean;
  onNavigate?: () => void;
  className?: string;
}

/**
 * Primary navigation. Labels are always in the DOM: below 1024 px the rail
 * collapses to icons and the label is kept for assistive tech (`sr-only`).
 */
export function SideNav({ expanded = false, onNavigate, className }: SideNavProps) {
  return (
    <nav aria-label="Sections" className={cn("flex flex-col gap-0.5 p-2", className)}>
      {NAV_ITEMS.map((item) => {
        const Glyph = item.icon;
        return (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            onClick={onNavigate}
            title={item.hint}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-[13px] font-medium transition-colors",
                expanded ? "justify-start" : "justify-center lg:justify-start",
                isActive
                  ? "bg-chrome-accent-soft font-medium text-chrome-accent [box-shadow:inset_2px_0_0_var(--chrome-accent)]"
                  : "text-chrome-fg-muted hover:bg-chrome-2 hover:text-chrome-fg",
              )
            }
          >
            {({ isActive }) => (
              <>
                <Glyph size={17} />
                <span className={cn(expanded ? "inline" : "sr-only lg:not-sr-only")}>{item.label}</span>
                {isActive && <span className="sr-only">(current page)</span>}
              </>
            )}
          </NavLink>
        );
      })}
    </nav>
  );
}
