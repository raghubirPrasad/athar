import { Badge, type BadgeTone } from "../ui/Badge";

interface Look {
  label: string;
  glyph: string;
  tone: BadgeTone;
  hint: string;
}

/** Per-row anchoring state (SPEC §12.4: the ledger never blocks the pipeline). */
const LOOK: Record<string, Look> = {
  anchored: { label: "Anchored", glyph: "✓", tone: "ok", hint: "Committed and confirmed on chain" },
  already_anchored: {
    label: "Already anchored",
    glyph: "=",
    tone: "ok",
    hint: "An identical (snapshot, root, ruleset) was already committed — the second run is idempotent",
  },
  pending: { label: "Pending", glyph: "◷", tone: "warn", hint: "Transaction sent, not yet mined" },
  unanchored: { label: "Unanchored", glyph: "○", tone: "neutral", hint: "The node was unreachable; the scan still completed" },
  failed: { label: "Failed", glyph: "✕", tone: "danger", hint: "The commit transaction failed" },
};

export function LedgerRowStatusBadge({ status }: { status: string }) {
  const look = LOOK[status] ?? { label: status, glyph: "•", tone: "neutral" as BadgeTone, hint: status };
  return (
    <Badge tone={look.tone} title={look.hint}>
      <span aria-hidden="true">{look.glyph}</span> {look.label}
    </Badge>
  );
}
