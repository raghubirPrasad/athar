import { useEffect, useId, useRef, type ReactNode } from "react";
import { cn } from "../../lib/cn";
import { Button } from "./Button";

export interface ModalProps {
  open: boolean;
  title: string;
  description?: ReactNode;
  onClose: () => void;
  footer?: ReactNode;
  children?: ReactNode;
  size?: "sm" | "md" | "lg";
  className?: string;
}

/**
 * The same 24/32/48 rem as `max-w-sm|lg|3xl`, but clamped to the viewport the
 * way the toast stack is: the dialog is `position: fixed`, so on a narrow
 * screen it must not take its width from anything but the screen itself.
 */
const SIZE = {
  sm: "max-w-[min(24rem,calc(100vw-2rem))]",
  md: "max-w-[min(32rem,calc(100vw-2rem))]",
  lg: "max-w-[min(48rem,calc(100vw-2rem))]",
} as const;

/**
 * Modal dialog: Escape closes, the backdrop closes, focus moves into the panel
 * on open and returns to the trigger on close.
 */
export function Modal({ open, title, description, onClose, footer, children, size = "md", className }: ModalProps) {
  const panelRef = useRef<HTMLDivElement>(null);
  const restoreRef = useRef<HTMLElement | null>(null);
  const titleId = useId();

  useEffect(() => {
    if (!open) return;
    restoreRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    panelRef.current?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.stopPropagation();
        onClose();
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      restoreRef.current?.focus();
    };
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto p-4 sm:p-8">
      <div
        aria-hidden="true"
        onClick={onClose}
        className="fixed inset-0 bg-[rgb(16_24_40/0.45)] backdrop-blur-[1px]"
      />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        className={cn(
          "relative z-10 w-full rounded-lg border border-border bg-surface shadow-card outline-none",
          SIZE[size],
          className,
        )}
      >
        <header className="flex items-start justify-between gap-3 border-b border-border px-4 py-3">
          <div className="min-w-0">
            <h2 id={titleId} className="text-sm font-semibold text-fg">
              {title}
            </h2>
            {description && <p className="mt-0.5 text-[13px] text-fg-muted">{description}</p>}
          </div>
          <Button size="sm" variant="ghost" onClick={onClose} aria-label="Close dialog">
            ✕
          </Button>
        </header>
        <div className="px-4 py-3">{children}</div>
        {footer && (
          <footer className="flex justify-end gap-2 border-t border-border px-4 py-3">{footer}</footer>
        )}
      </div>
    </div>
  );
}
