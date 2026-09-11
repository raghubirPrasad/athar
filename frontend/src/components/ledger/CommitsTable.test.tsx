import { screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { LedgerScanOut } from "../../api/types";
import { renderWithProviders } from "../../test/render";
import { CommitsTable } from "./CommitsTable";

vi.mock("../../api/endpoints", () => ({
  verifyLedgerScan: () => Promise.reject(new Error("not used in this test")),
}));

const SCAN: LedgerScanOut = {
  scan_id: 12,
  snapshot_month: 12,
  merkle_root: "0xa0ceabf08775328fd203cee44a687d5e6097f318b3c9e6e5e073fef4a86a3eaa",
  snapshot_hash: "0x00264eb1b669ce2dbbe086ea83cebe91f8c41f4e5f5c3c69fe008e700dd948ac",
  ruleset_hash: "0xa718ba3762fd4f0a1b6e87677bee94b5d3d7ffb78521c4d89953c43594d453df",
  finding_count: 94,
  ledger_scan_index: 11,
  ledger_tx: "0x158b7414aa71f068d8b46be6559f73797c5dac58237c1351a6f05034863eb396",
  ledger_status: "anchored",
  block_number: null,
  chain_root: "0xa0ceabf08775328fd203cee44a687d5e6097f318b3c9e6e5e073fef4a86a3eaa",
  timestamp: 1789086982,
};

describe("CommitsTable", () => {
  it("hides the block column when no commit carries a block number", () => {
    renderWithProviders(<CommitsTable scans={[SCAN, { ...SCAN, scan_id: 11, snapshot_month: 11 }]} />);

    expect(screen.queryByRole("columnheader", { name: "Block" })).not.toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Transaction" })).toBeInTheDocument();
  });

  it("leaves no dead column of dashes behind when the block number is hidden", () => {
    // `LedgerScanOut.block_number` is null for every commit on this chain: the
    // contract's ScanCommit struct carries no block number and nothing persists
    // the receipt's. Filling it needs a backend change; until then the column
    // must be absent, not present and empty.
    renderWithProviders(<CommitsTable scans={[SCAN, { ...SCAN, scan_id: 11, snapshot_month: 11 }]} />);

    const headers = screen.getAllByRole("columnheader");
    const rows = screen.getAllByRole("row").slice(1);
    expect(headers).toHaveLength(7);
    for (const row of rows) expect(within(row).getAllByRole("cell")).toHaveLength(headers.length);
  });

  it("shows the block column as soon as one commit has a block number", () => {
    renderWithProviders(<CommitsTable scans={[SCAN, { ...SCAN, scan_id: 11, block_number: 4211 }]} />);

    expect(screen.getByRole("columnheader", { name: "Block" })).toBeInTheDocument();
    expect(screen.getByText("4211")).toBeInTheDocument();
    // The commit without one still gets a cell, so the rows stay aligned.
    expect(screen.getAllByText("—").length).toBeGreaterThan(0);
  });

  it("links a commit's finding count to the findings that were hashed into it", () => {
    renderWithProviders(<CommitsTable scans={[SCAN]} />);

    const link = screen.getByRole("link", { name: "94 findings committed in scan 12" });
    expect(link).toHaveAttribute("href", "/findings?month=12");
  });
});
