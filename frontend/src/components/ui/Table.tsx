import type { HTMLAttributes, ReactNode, TdHTMLAttributes, ThHTMLAttributes } from "react";
import { cn } from "../../lib/cn";

/**
 * Plain table styling for TanStack Table (page agents own the column model).
 * Dense rows, sticky header, numeric columns right-aligned with tabular digits.
 */

export function TableWrap({ children, className, ...rest }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={cn("w-full overflow-x-auto rounded-lg border border-border bg-surface", className)} {...rest}>
      {children}
    </div>
  );
}

export function Table({ children, className, ...rest }: HTMLAttributes<HTMLTableElement>) {
  return (
    <table className={cn("w-full border-collapse text-sm", className)} {...rest}>
      {children}
    </table>
  );
}

export function THead({ children, className, ...rest }: HTMLAttributes<HTMLTableSectionElement>) {
  return (
    <thead className={cn("sticky top-0 z-[1] bg-surface-muted text-left text-xs uppercase tracking-wide text-fg-muted", className)} {...rest}>
      {children}
    </thead>
  );
}

export function TBody({ children, className, ...rest }: HTMLAttributes<HTMLTableSectionElement>) {
  return (
    <tbody className={cn("divide-y divide-border", className)} {...rest}>
      {children}
    </tbody>
  );
}

export interface TrProps extends HTMLAttributes<HTMLTableRowElement> {
  selected?: boolean;
  clickable?: boolean;
}

export function Tr({ children, className, selected = false, clickable = false, ...rest }: TrProps) {
  return (
    <tr
      className={cn(
        "transition-colors",
        clickable && "cursor-pointer hover:bg-accent-soft/40 focus-within:bg-accent-soft/40",
        selected && "bg-accent-soft/60",
        className,
      )}
      aria-selected={selected || undefined}
      {...rest}
    >
      {children}
    </tr>
  );
}

export type SortDir = "asc" | "desc" | null;

export interface ThProps extends ThHTMLAttributes<HTMLTableCellElement> {
  numeric?: boolean;
  sortDir?: SortDir;
  onSort?: () => void;
}

export function Th({ children, className, numeric = false, sortDir, onSort, ...rest }: ThProps) {
  const ariaSort = sortDir === "asc" ? "ascending" : sortDir === "desc" ? "descending" : onSort ? "none" : undefined;
  const label: ReactNode = onSort ? (
    <button type="button" onClick={onSort} className="inline-flex items-center gap-1 hover:text-fg">
      {children}
      <span aria-hidden="true" className="text-fg-faint">{sortDir === "asc" ? "↑" : sortDir === "desc" ? "↓" : "↕"}</span>
    </button>
  ) : (
    children
  );
  return (
    <th
      scope="col"
      aria-sort={ariaSort}
      className={cn("px-3 py-2 font-semibold whitespace-nowrap", numeric && "text-right", className)}
      {...rest}
    >
      {label}
    </th>
  );
}

export interface TdProps extends TdHTMLAttributes<HTMLTableCellElement> {
  numeric?: boolean;
  mono?: boolean;
}

export function Td({ children, className, numeric = false, mono = false, ...rest }: TdProps) {
  return (
    <td className={cn("px-3 py-1.5 align-middle", numeric && "tabular text-right", mono && "font-mono text-[13px]", className)} {...rest}>
      {children}
    </td>
  );
}
