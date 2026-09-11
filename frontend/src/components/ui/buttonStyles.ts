import { cn } from "../../lib/cn";

export type ButtonVariant = "primary" | "secondary" | "danger" | "ghost";
export type ButtonSize = "sm" | "md";

const BASE =
  "inline-flex items-center justify-center gap-1.5 rounded-md border font-medium whitespace-nowrap " +
  "transition-colors select-none disabled:cursor-not-allowed disabled:opacity-60";

const VARIANT: Record<ButtonVariant, string> = {
  primary: "bg-accent text-accent-fg border-accent hover:bg-accent-strong hover:border-accent-strong",
  secondary: "bg-surface text-fg border-border-strong hover:bg-surface-muted",
  danger: "bg-danger-solid text-white border-danger-solid hover:opacity-90",
  ghost: "bg-transparent text-fg border-transparent hover:bg-surface-muted",
};

const SIZE: Record<ButtonSize, string> = {
  sm: "h-7 px-2.5 text-[13px]",
  md: "h-8 px-3 text-sm",
};

/** Shared by <Button> and <ButtonLink> so a link action looks identical to a button. */
export function buttonClass(variant: ButtonVariant = "secondary", size: ButtonSize = "md", extra?: string) {
  return cn(BASE, VARIANT[variant], SIZE[size], extra);
}
