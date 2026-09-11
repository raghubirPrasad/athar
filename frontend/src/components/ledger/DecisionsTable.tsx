import { Link } from "react-router-dom";
import type { LedgerDecisionOut } from "../../api/types";
import { formatDate } from "../../lib/format";
import { decisionLabel, decisionTone } from "../remediation/planMeta";
import { Badge } from "../ui/Badge";
import { CodeBlock } from "../ui/CodeBlock";
import { EmptyState } from "../ui/EmptyState";
import { Table, TBody, Td, TableWrap, THead, Th, Tr } from "../ui/Table";
import { LedgerRowStatusBadge } from "./LedgerRowStatus";

/**
 * Decisions recorded on the ledger (SPEC §12.4). Each one carries the actor
 * hash, the evidence hash and the leaf it proved against — a decision cannot
 * reference a finding that was not in the committed scan.
 */
export function DecisionsTable({ decisions }: { decisions: readonly LedgerDecisionOut[] }) {
  if (decisions.length === 0) {
    return (
      <EmptyState
        compact
        title="No decisions yet"
        description="Approvals, rejections, applied remediations and granted exceptions appear here as they are taken."
      />
    );
  }

  return (
    <TableWrap>
      <Table>
        <THead>
          <tr>
            <Th>Decision</Th>
            <Th numeric>Code</Th>
            <Th>Finding</Th>
            <Th numeric>Scan</Th>
            <Th>Actor hash</Th>
            <Th>Evidence hash</Th>
            <Th>Leaf</Th>
            <Th>Transaction</Th>
            <Th>Status</Th>
            <Th>Recorded</Th>
          </tr>
        </THead>
        <TBody>
          {decisions.map((decision) => (
            <Tr key={decision.decision_id}>
              <Td>
                <Badge tone={decisionTone(decision.decision)}>{decisionLabel(decision.decision)}</Badge>
              </Td>
              <Td numeric>{decision.decision_code}</Td>
              <Td>
                <Link
                  to={`/findings?open=${encodeURIComponent(decision.finding_key)}&altitude=evidence`}
                  className="font-mono text-[12px] text-accent-strong hover:underline"
                  title={decision.finding_key}
                >
                  {decision.finding_key.slice(0, 12)}…
                </Link>
              </Td>
              <Td numeric>{decision.scan_id}</Td>
              <Td>
                <CodeBlock inline value={decision.actor_hash} label="actor hash" keep={5} />
              </Td>
              <Td>
                <CodeBlock inline value={decision.evidence_hash} label="evidence hash" keep={5} />
              </Td>
              <Td>{decision.leaf ? <CodeBlock inline value={decision.leaf} label="leaf" keep={5} /> : "—"}</Td>
              <Td>
                {decision.ledger_tx ? (
                  <CodeBlock inline value={decision.ledger_tx} label="transaction" keep={5} />
                ) : (
                  "—"
                )}
              </Td>
              <Td>
                <LedgerRowStatusBadge status={decision.ledger_status} />
              </Td>
              <Td>{formatDate(decision.created_at)}</Td>
            </Tr>
          ))}
        </TBody>
      </Table>
    </TableWrap>
  );
}
