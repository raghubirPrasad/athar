import type { HalfLifeOut } from "../../api/types";
import { formatInt } from "../../lib/format";
import { HalfLifeValue } from "../overview/HalfLifeValue";
import { Badge } from "../ui/Badge";
import { EmptyState } from "../ui/EmptyState";
import { Table, TBody, Td, TableWrap, THead, Th, Tr } from "../ui/Table";
import { ALL_DEPARTMENTS, selectHalfLifeRows } from "./halfLifeRows";

/** Every trigger the diff emits (SPEC §9.1), so none renders as a raw key. */
const TRIGGER_LABEL: Record<string, string> = {
  all: "All grants",
  departure: "Offboarding",
  role_change: "Role change",
  incident_response: "Incident response",
  project_retirement: "Project retirement",
};

function triggerLabel(trigger: string): string {
  return TRIGGER_LABEL[trigger] ?? trigger.replace(/_/g, " ");
}

/** The API's aggregate row uses the sentinel department `all`. */
function departmentLabel(department: string): string {
  return department === ALL_DEPARTMENTS ? "All departments" : department;
}

export interface HalfLifeTableViewProps {
  rows: readonly HalfLifeOut[];
  /**
   * Department the table was opened for, from `?department=` — the rows are
   * narrowed to it (plus the estate-wide baseline) and its own rows are marked
   * as the current selection.
   */
  selected?: string | null;
}

/**
 * Half-life per department and trigger, with the engine's own diagnosis label
 * (SPEC §9.3). Offboarding is the headline number: "Finance granted 34
 * permissions and revoked two" is an organisational finding, not twelve people.
 *
 * This table is the evidence — grants and revocations sit next to the median
 * they produced — so the numbers in it link nowhere further.
 */
export function HalfLifeTableView({ rows, selected = null }: HalfLifeTableViewProps) {
  const visible = selectHalfLifeRows(rows, selected);

  if (visible.length === 0) {
    return (
      <EmptyState
        compact
        title={selected ? `No half-life data for ${selected}` : "No half-life data"}
        description="No revocations have been observed yet."
      />
    );
  }

  return (
    <TableWrap>
      <Table>
        <THead>
          <tr>
            <Th>Department</Th>
            <Th>Trigger</Th>
            <Th numeric>Grants</Th>
            <Th numeric>Revocations</Th>
            <Th>Half-life</Th>
          </tr>
        </THead>
        <TBody>
          {visible.map((row) => {
            const isSelected = selected != null && row.department === selected;
            return (
              <Tr
                key={`${row.department}:${row.trigger}`}
                selected={isSelected}
                aria-current={isSelected ? "true" : undefined}
              >
                <Td>{departmentLabel(row.department)}</Td>
                <Td>
                  <Badge tone={row.trigger === "departure" ? "accent" : "neutral"}>{triggerLabel(row.trigger)}</Badge>
                </Td>
                <Td numeric>{formatInt(row.grants)}</Td>
                <Td numeric>{formatInt(row.revocations)}</Td>
                <Td>
                  <HalfLifeValue months={row.half_life_months} label={row.label} />
                </Td>
              </Tr>
            );
          })}
        </TBody>
      </Table>
    </TableWrap>
  );
}
