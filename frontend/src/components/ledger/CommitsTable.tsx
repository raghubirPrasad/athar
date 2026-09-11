import { Link } from "react-router-dom";
import type { LedgerScanOut } from "../../api/types";
import { formatInt, formatMonthLabel } from "../../lib/format";
import { CodeBlock } from "../ui/CodeBlock";
import { EmptyState } from "../ui/EmptyState";
import { Table, TBody, Td, TableWrap, THead, Th, Tr } from "../ui/Table";
import { LedgerRowStatusBadge } from "./LedgerRowStatus";
import { VerifyScanButton } from "./VerifyScanButton";

/**
 * One row per anchored scan (SPEC §12.2): the root that was committed, the
 * transaction that committed it, and a Verify that recomputes the root from the
 * database and compares the two.
 */
export function CommitsTable({ scans }: { scans: readonly LedgerScanOut[] }) {
  if (scans.length === 0) {
    return (
      <EmptyState
        title="No commits yet"
        description="Run a scan; each one hashes its findings into a Merkle root and commits that root."
      />
    );
  }

  // A deployment whose receipts carry no block number gets no column of dashes:
  // an empty column reads as missing data rather than as data this chain has not.
  const showBlock = scans.some((scan) => scan.block_number != null);

  return (
    <TableWrap>
      <Table>
        <THead>
          <tr>
            <Th numeric>Scan</Th>
            <Th>Month</Th>
            <Th numeric>Findings</Th>
            <Th>Merkle root</Th>
            <Th>Transaction</Th>
            {showBlock && <Th numeric>Block</Th>}
            <Th>Status</Th>
            <Th>Verify</Th>
          </tr>
        </THead>
        <TBody>
          {scans.map((scan) => (
            <Tr key={scan.scan_id}>
              <Td numeric>{scan.scan_id}</Td>
              <Td>{formatMonthLabel(scan.snapshot_month)}</Td>
              <Td numeric>
                {/* The count that went into this root, and the rows it hashed. */}
                <Link
                  to={`/findings?month=${scan.snapshot_month}`}
                  aria-label={`${formatInt(scan.finding_count)} findings committed in scan ${scan.scan_id}`}
                  className="rounded-sm underline decoration-border decoration-dotted underline-offset-4 hover:decoration-accent focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent"
                >
                  {formatInt(scan.finding_count)}
                </Link>
              </Td>
              <Td>{scan.merkle_root ? <CodeBlock inline value={scan.merkle_root} label="root" /> : "—"}</Td>
              <Td>{scan.ledger_tx ? <CodeBlock inline value={scan.ledger_tx} label="transaction" /> : "—"}</Td>
              {showBlock && <Td numeric>{scan.block_number ?? "—"}</Td>}
              <Td>
                <LedgerRowStatusBadge status={scan.ledger_status} />
              </Td>
              <Td className="min-w-[17rem]">
                <VerifyScanButton scanId={scan.scan_id} label="Verify" />
              </Td>
            </Tr>
          ))}
        </TBody>
      </Table>
    </TableWrap>
  );
}
