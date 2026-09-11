import { Link } from "react-router-dom";
import type { RuleEval } from "../../api/types";
import { formatRatioPct } from "../../lib/format";
import { ruleName, useRules } from "../../lib/rules";
import { EmptyState } from "../ui/EmptyState";
import { Table, TBody, Td, TableWrap, THead, Th, Tr } from "../ui/Table";

/** Per-rule confusion counts at the High+ threshold (SPEC §17). */
export function RuleConfusionTable({ rows }: { rows: readonly RuleEval[] }) {
  const rules = useRules();

  if (rows.length === 0) {
    return <EmptyState compact title="No per-rule breakdown" description="The harness reported no per-rule counts." />;
  }

  return (
    <TableWrap>
      <Table>
        <THead>
          <tr>
            <Th>Rule</Th>
            <Th numeric>True positives</Th>
            <Th numeric>False positives</Th>
            <Th numeric>False negatives</Th>
            <Th numeric>Precision</Th>
            <Th numeric>Recall</Th>
          </tr>
        </THead>
        <TBody>
          {rows.map((row) => (
            <Tr key={row.rule_id}>
              <Td>
                <Link to={`/findings?rule=${row.rule_id}`} className="text-accent-strong hover:underline">
                  {row.rule_id}
                </Link>
                <span className="ml-1.5 text-fg-muted">{ruleName(rules, row.rule_id) ?? ""}</span>
              </Td>
              <Td numeric>{row.tp}</Td>
              <Td numeric>{row.fp}</Td>
              <Td numeric>{row.fn}</Td>
              <Td numeric>{formatRatioPct(row.precision)}</Td>
              <Td numeric>{formatRatioPct(row.recall)}</Td>
            </Tr>
          ))}
        </TBody>
      </Table>
    </TableWrap>
  );
}
