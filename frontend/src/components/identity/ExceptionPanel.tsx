import type { ExceptionOut } from "../../api/types";
import { formatDate } from "../../lib/format";
import { Badge } from "../ui/Badge";
import { Table, TBody, Td, TableWrap, THead, Th, Tr } from "../ui/Table";
import { exceptionTypeLabel } from "./exceptionTypes";

/** Valid / expired chip for one register entry (SPEC §4.3). */
export function ExceptionBadge({ exception }: { exception: ExceptionOut }) {
  return (
    <Badge tone={exception.valid ? "ok" : "danger"} title={exception.justification}>
      <span aria-hidden="true">{exception.valid ? "✓" : "✕"}</span>
      {exceptionTypeLabel(exception.exception_type)}
      {exception.valid ? " exception" : " exception expired"}
    </Badge>
  );
}

/**
 * The governance exception register (SPEC §4.3) — the only thing that can excuse
 * a finding. A cloud-side tag is displayed as evidence elsewhere on this page and
 * never suppresses anything.
 */
export function ExceptionPanel({ exceptions }: { exceptions: readonly ExceptionOut[] }) {
  if (exceptions.length === 0) {
    return (
      <p className="text-[13px] text-fg-muted">
        No entry in the governance exception register for this identity. Cloud-side tags are shown as evidence but
        never excuse a finding.
      </p>
    );
  }

  return (
    <div className="flex flex-col gap-2">
      <TableWrap>
        <Table>
          <THead>
            <tr>
              <Th>Type</Th>
              <Th>State</Th>
              <Th>Approved by</Th>
              <Th>Approved on</Th>
              <Th>Review date</Th>
              <Th>Expires</Th>
              <Th>Source</Th>
            </tr>
          </THead>
          <TBody>
            {exceptions.map((exception) => (
              <Tr key={exception.exception_id}>
                <Td>{exceptionTypeLabel(exception.exception_type)}</Td>
                <Td>
                  <Badge tone={exception.valid ? "ok" : "danger"}>
                    <span aria-hidden="true">{exception.valid ? "✓" : "✕"}</span>
                    {exception.valid ? "Valid" : "Expired"}
                  </Badge>
                </Td>
                <Td>{exception.approved_by}</Td>
                <Td>{formatDate(exception.approved_on)}</Td>
                <Td>{formatDate(exception.review_date)}</Td>
                <Td>{formatDate(exception.expires_on)}</Td>
                <Td>
                  <Badge tone="neutral">{exception.source === "workflow" ? "ATHAR workflow" : "HR register"}</Badge>
                </Td>
              </Tr>
            ))}
          </TBody>
        </Table>
      </TableWrap>
      <ul className="flex flex-col gap-1">
        {exceptions.map((exception) => (
          <li key={`${exception.exception_id}-why`} className="text-[13px] text-fg-muted">
            <span className="font-semibold text-fg">{exceptionTypeLabel(exception.exception_type)}:</span>{" "}
            {exception.justification}
          </li>
        ))}
      </ul>
    </div>
  );
}
