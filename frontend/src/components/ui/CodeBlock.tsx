import { useCallback, useState } from "react";
import { cn } from "../../lib/cn";
import { shortHex } from "../../lib/format";
import { Button } from "./Button";

export interface CodeBlockProps {
  /** Raw text to show and copy. Objects should be stringified by the caller. */
  value: string;
  label?: string;
  /** Render on one line, truncating a long hash to `0xabcdef…123456`. */
  inline?: boolean;
  /** Hex characters kept each side when `inline` truncates. */
  keep?: number;
  maxHeight?: string;
  className?: string;
}

async function writeClipboard(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    /* clipboard blocked (permissions, insecure origin) — fall through */
  }
  return false;
}

const BLOCKED_HINT = "The browser blocked clipboard access — select the text and copy it by hand.";

/** Monospace evidence panel with a Copy button (SPEC §14: raw snippet, copyable). */
export function CodeBlock({ value, label, inline = false, keep = 6, maxHeight, className }: CodeBlockProps) {
  // A clipboard the browser refuses (insecure origin, denied permission) must
  // say so: a Copy button that does nothing at all reads as a broken control.
  const [copyState, setCopyState] = useState<"idle" | "copied" | "blocked">("idle");
  const shown = inline ? shortHex(value, keep) : value;
  const truncated = inline && shown !== value;

  const copy = useCallback(() => {
    void writeClipboard(value).then((ok) => {
      setCopyState(ok ? "copied" : "blocked");
      window.setTimeout(() => setCopyState("idle"), ok ? 1500 : 4000);
    });
  }, [value]);

  return (
    <div
      className={cn(
        "rounded-md border border-border bg-surface-muted",
        inline ? "inline-flex items-center gap-1 px-1.5 py-0.5 align-middle" : "overflow-hidden",
        className,
      )}
    >
      {!inline && (
        <div className="flex items-center justify-between gap-2 border-b border-border px-3 py-1.5">
          <span className="text-xs font-semibold uppercase tracking-wide text-fg-muted">
            {label ?? "Raw"}
          </span>
          <Button
            size="sm"
            variant="ghost"
            onClick={copy}
            aria-live="polite"
            title={copyState === "blocked" ? BLOCKED_HINT : undefined}
          >
            {copyState === "copied" ? "Copied" : copyState === "blocked" ? "Copy blocked" : "Copy"}
          </Button>
        </div>
      )}
      <code
        title={truncated ? value : undefined}
        className={cn(
          "block font-mono text-[12.5px] leading-5 text-fg",
          inline ? "whitespace-nowrap" : "overflow-auto whitespace-pre p-3",
        )}
        style={!inline && maxHeight ? { maxHeight } : undefined}
      >
        {shown}
      </code>
      {inline && (
        <button
          type="button"
          onClick={copy}
          aria-label={copyState === "blocked" ? `Copy ${label ?? "value"} — ${BLOCKED_HINT}` : `Copy ${label ?? "value"}`}
          title={copyState === "blocked" ? BLOCKED_HINT : undefined}
          className="rounded px-1 text-xs text-fg-muted hover:text-accent-strong"
        >
          {copyState === "copied" ? "✓" : copyState === "blocked" ? "✕" : "⧉"}
        </button>
      )}
    </div>
  );
}
