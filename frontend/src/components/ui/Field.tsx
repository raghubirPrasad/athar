import { useId } from "react";
import { cn } from "../../lib/cn";

const CONTROL =
  "h-7 rounded-md border border-border bg-surface px-2 text-[13px] text-fg " +
  "placeholder:text-fg-faint disabled:opacity-60";

export interface SelectOption {
  value: string;
  label: string;
}

export interface SelectProps {
  label: string;
  value: string;
  options: readonly SelectOption[];
  onChange: (value: string) => void;
  /** Label for the empty option; omit to make the select required. */
  anyLabel?: string;
  className?: string;
}

/** Labelled native select — keyboard and screen-reader behaviour for free. */
export function Select({ label, value, options, onChange, anyLabel, className }: SelectProps) {
  const id = useId();
  return (
    <span className={cn("inline-flex items-center gap-1.5", className)}>
      <label htmlFor={id} className="text-xs font-medium text-fg-muted">
        {label}
      </label>
      <select id={id} value={value} onChange={(e) => onChange(e.target.value)} className={CONTROL}>
        {anyLabel !== undefined && <option value="">{anyLabel}</option>}
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </span>
  );
}

export interface SearchInputProps {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  className?: string;
}

export function SearchInput({ label, value, onChange, placeholder, className }: SearchInputProps) {
  const id = useId();
  return (
    <span className={cn("inline-flex items-center gap-1.5", className)}>
      <label htmlFor={id} className="text-xs font-medium text-fg-muted">
        {label}
      </label>
      <input
        id={id}
        type="search"
        value={value}
        placeholder={placeholder}
        onChange={(e) => onChange(e.target.value)}
        className={cn(CONTROL, "w-44")}
      />
    </span>
  );
}
