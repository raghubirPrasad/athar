import { Link } from "react-router-dom";
import type { DecoyEval } from "../../api/types";
import { ruleLabel } from "../../lib/rules";
import { Badge } from "../ui/Badge";
import { EmptyState } from "../ui/EmptyState";
import { SeverityBadge } from "../ui/SeverityBadge";
import { Table, TBody, Td, TableWrap, THead, Th, Tr } from "../ui/Table";

/**
 * Decoys (SPEC §4.3): identities seeded to look risky that a naïve detector
 * flags. "Correctly handled" means the decoy stayed at or below Medium — the
 * legitimacy comes from the governance exception register, never a cloud tag.
 */
export function DecoyTable({ decoys }: { decoys: readonly DecoyEval[] }) {
  if (decoys.length === 0) {
    return <EmptyState compact title="No decoys" description="This estate carries no decoy identities." />;
  }

  return (
    <TableWrap>
      <Table>
        <THead>
          <tr>
            <Th>Identity</Th>
            <Th>Looks like</Th>
            <Th>Why it is legitimate</Th>
            <Th>Flagged at</Th>
            <Th>Handled</Th>
          </tr>
        </THead>
        <TBody>
          {decoys.map((decoy) => (
            <Tr key={decoy.identity_id}>
              <Td>
                <Link
                  to={`/identities/${encodeURIComponent(decoy.identity_id)}`}
                  className="text-accent-strong hover:underline"
                >
                  {decoy.display_name}
                </Link>
                <span className="ml-1.5 font-mono text-[11.5px] text-fg-faint">{decoy.identity_id}</span>
              </Td>
              <Td>
                <span className="flex flex-wrap gap-1">
                  {decoy.looks_like.map((rule) => (
                    <Badge key={rule} tone="neutral" title={ruleLabel(rule)}>
                      {rule}
                    </Badge>
                  ))}
                </span>
              </Td>
              <Td className="max-w-[24rem]">
                <span className="text-[13px] text-fg-muted">{decoy.why_legitimate}</span>
              </Td>
              <Td>{decoy.flagged_at ? <SeverityBadge severity={decoy.flagged_at} /> : <span className="text-fg-muted">Not flagged</span>}</Td>
              <Td>
                <Badge tone={decoy.correctly_handled ? "ok" : "danger"}>
                  <span aria-hidden="true">{decoy.correctly_handled ? "✓" : "✕"}</span>
                  {decoy.correctly_handled ? "Correct" : "False positive"}
                </Badge>
              </Td>
            </Tr>
          ))}
        </TBody>
      </Table>
    </TableWrap>
  );
}
