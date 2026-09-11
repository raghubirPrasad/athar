import type { DecisionOut } from "../../api/types";
import { formatDate, shortHex } from "../../lib/format";
import { Badge } from "../ui/Badge";
import { CodeBlock } from "../ui/CodeBlock";
import { Table, TBody, Td, TableWrap, THead, Th, Tr } from "../ui/Table";
import { decisionLabel, decisionTone } from "./planMeta";

const LEDGER_LOOK: Record<string, { label: string; glyph: string; tone: "ok" | "warn" | "neutral" | "danger" }> = {
  anchored: { label: "Anchored", glyph: "✓", tone: "ok" },
  pending: { label: "Pending", glyph: "◷", tone: "warn" },
  unanchored: { label: "Unanchored", glyph: "○", tone: "neutral" },
  failed: { label: "Failed", glyph: "✕", tone: "danger" },
};

/**
 * Audit trail for the decisions taken on a plan (SPEC §10.3, §12.4): who, what,
 * when, and whether it reached the chain.
 */
export function DecisionTrail({ decisions }: { decisions: readonly DecisionOut[] }) {
  if (decisions.length === 0) {
    return <p className="text-[13px] text-fg-muted">No decision has been taken on this plan yet.</p>;
  }
  return (
    <TableWrap>
      <Table>
        <THead>
          <tr>
            <Th>Decision</Th>
            <Th>Actor</Th>
            <Th>When</Th>
            <Th>Evidence hash</Th>
            <Th>Ledger</Th>
          </tr>
        </THead>
        <TBody>
          {decisions.map((decision) => {
            const look = LEDGER_LOOK[decision.ledger_status] ?? LEDGER_LOOK.unanchored;
            return (
              <Tr key={decision.decision_id}>
                <Td>
                  <Badge tone={decisionTone(decision.decision)}>{decisionLabel(decision.decision)}</Badge>
                </Td>
                <Td>{decision.actor_email ?? decision.actor_user_id}</Td>
                <Td>{formatDate(decision.created_at)}</Td>
                <Td>
                  <CodeBlock inline value={decision.evidence_hash} label="evidence hash" />
                </Td>
                <Td>
                  <span className="flex flex-wrap items-center gap-1.5">
                    <Badge tone={look?.tone ?? "neutral"}>
                      <span aria-hidden="true">{look?.glyph}</span> {look?.label}
                    </Badge>
                    {decision.ledger_tx && (
                      <span className="font-mono text-[12px] text-fg-muted" title={decision.ledger_tx}>
                        {shortHex(decision.ledger_tx)}
                      </span>
                    )}
                  </span>
                </Td>
              </Tr>
            );
          })}
        </TBody>
      </Table>
    </TableWrap>
  );
}
