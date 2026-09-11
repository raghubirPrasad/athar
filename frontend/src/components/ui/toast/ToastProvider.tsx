import { useCallback, useMemo, useRef, useState, type ReactNode } from "react";
import { cn } from "../../../lib/cn";
import { ToastContext, type Toast, type ToastContextValue, type ToastInput, type ToastTone } from "./context";

const DEFAULT_DURATION = 5000;

/** Tone carries an icon and a word as well as colour (PRD §8.5). */
const TONE: Record<ToastTone, { className: string; glyph: string; label: string }> = {
  info: { className: "border-border bg-surface", glyph: "i", label: "Note" },
  success: { className: "border-ok/40 bg-ok-soft", glyph: "✓", label: "Done" },
  warn: { className: "border-warn/40 bg-warn-soft", glyph: "!", label: "Warning" },
  danger: { className: "border-danger/40 bg-danger-soft", glyph: "✕", label: "Failed" },
};

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<readonly Toast[]>([]);
  const nextId = useRef(1);

  const dismiss = useCallback((id: number) => {
    setToasts((current) => current.filter((t) => t.id !== id));
  }, []);

  const push = useCallback(
    ({ title, detail, tone = "info", duration = DEFAULT_DURATION }: ToastInput) => {
      const id = nextId.current++;
      setToasts((current) => [...current, { id, title, detail, tone }]);
      if (duration > 0) window.setTimeout(() => dismiss(id), duration);
      return id;
    },
    [dismiss],
  );

  const value = useMemo<ToastContextValue>(() => ({ toasts, push, dismiss }), [toasts, push, dismiss]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div
        role="status"
        aria-live="polite"
        className="pointer-events-none fixed bottom-4 right-4 z-50 flex w-[min(22rem,calc(100vw-2rem))] flex-col gap-2"
      >
        {toasts.map((toast) => {
          const tone = TONE[toast.tone];
          return (
            <div
              key={toast.id}
              className={cn(
                "pointer-events-auto flex items-start gap-2 rounded-lg border px-3 py-2 shadow-card",
                tone.className,
              )}
            >
              <span aria-hidden="true" className="mt-0.5 text-sm font-bold text-fg-muted">
                {tone.glyph}
              </span>
              <div className="min-w-0 flex-1">
                <p className="text-[13px] font-semibold text-fg">
                  <span className="sr-only">{tone.label}: </span>
                  {toast.title}
                </p>
                {toast.detail && <p className="mt-0.5 text-xs text-fg-muted">{toast.detail}</p>}
              </div>
              <button
                type="button"
                onClick={() => dismiss(toast.id)}
                aria-label="Dismiss notification"
                className="rounded px-1 text-fg-faint hover:text-fg"
              >
                ✕
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}
