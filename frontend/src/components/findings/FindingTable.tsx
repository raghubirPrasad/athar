import type { FindingOut } from "../../api/types";
import { formatMonthShort } from "../../lib/format";
import { ruleLabel } from "../../lib/rules";
import { Badge } from "../ui/Badge";
import { CloudIcons } from "../ui/CloudIcon";
import { ScoreBar } from "../ui/ScoreBar";
import { SeverityBadge } from "../ui/SeverityBadge";
import { Table, TBody, Td, TableWrap, THead, Th, Tr, type SortDir } from "../ui/Table";
import { findingStatusLook } from "./findingStatus";

/** Fields `GET /findings?sort=` accepts (SPEC §13). */
export const SORTABLE_FINDING_COLUMNS = [
  "display_name",
  "department",
  "rule_id",
  "severity",
  "score",
  "first_seen_month",
  "status",
] as const;

export type SortableFindingColumn = (typeof SORTABLE_FINDING_COLUMNS)[number];

function dirFor(sort: string, column: string): SortDir {
  if (sort === column) return "asc";
  if (sort === `-${column}`) return "desc";
  return null;
}

export interface FindingTableProps {
  rows: readonly FindingOut[];
  sort: string;
  onSortChange: (sort: string) => void;
  onOpen: (findingKey: string) => void;
  openKey?: string;
}

/**
 * Flat findings list (SPEC §14). A row is a finding, not an identity, so the
 * same person can appear once per rule — and each row opens that finding.
 */
export function FindingTable({ rows, sort, onSortChange, onOpen, openKey }: FindingTableProps) {
  const header = (column: SortableFindingColumn, label: string, numeric = false) => {
    const dir = dirFor(sort, column);
    return (
      <Th
        numeric={numeric}
        sortDir={dir}
        onSort={() => onSortChange(dir === "desc" ? column : `-${column}`)}
      >
        {label}
      </Th>
    );
  };

  return (
    <TableWrap>
      <Table>
        <THead>
          <tr>
            {header("display_name", "Identity")}
            {header("department", "Department")}
            <Th>Clouds</Th>
            {header("rule_id", "Rule")}
            {header("severity", "Severity")}
            {header("score", "Score")}
            {header("first_seen_month", "First seen")}
            {header("status", "Status")}
            <Th>Finding</Th>
          </tr>
        </THead>
        <TBody>
          {rows.map((finding) => {
            const status = findingStatusLook(finding.status);
            return (
              <Tr
                key={finding.finding_key}
                clickable
                tabIndex={0}
                selected={finding.finding_key === openKey}
                onClick={() => onOpen(finding.finding_key)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    onOpen(finding.finding_key);
                  }
                }}
              >
                <Td>
                  <span className="flex flex-col">
                    <span className="font-medium text-fg">{finding.display_name}</span>
                    <span className="font-mono text-[11.5px] text-fg-faint">{finding.identity_id}</span>
                  </span>
                </Td>
                <Td>{finding.department}</Td>
                <Td>
                  <CloudIcons clouds={finding.clouds} />
                </Td>
                <Td>
                  <span className="whitespace-nowrap text-[13px] text-fg-muted">
                    {ruleLabel(finding.rule_id, finding.rule_name)}
                  </span>
                </Td>
                <Td>
                  <SeverityBadge severity={finding.severity} />
                </Td>
                <Td>
                  <ScoreBar value={finding.score} severity={finding.severity} />
                </Td>
                <Td>{formatMonthShort(finding.first_seen_month)}</Td>
                <Td>
                  <Badge tone={status.tone}>
                    <span aria-hidden="true">{status.glyph}</span> {status.label}
                  </Badge>
                </Td>
                <Td className="max-w-[26rem]">
                  <span className="line-clamp-2 text-[13px] text-fg-muted">{finding.altitudes.headline}</span>
                </Td>
              </Tr>
            );
          })}
        </TBody>
      </Table>
    </TableWrap>
  );
}
