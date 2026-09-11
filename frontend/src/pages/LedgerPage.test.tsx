import { fireEvent, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type {
  EstateSummary,
  LedgerDecisionPage,
  LedgerInfo,
  LedgerScanPage,
  LedgerVerifyOut,
} from "../api/types";
import { shortHex } from "../lib/format";
import { renderWithProviders } from "../test/render";
import { LedgerPage } from "./LedgerPage";

const INFO: LedgerInfo = {
  enabled: true,
  contract_address: "0x5FbDB2315678afecb367f032d93F642f64180aa3",
  chain_id: 31337,
  writer_address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
  purpose: "Defends against post-hoc alteration of findings or decisions in the scanner's own database.",
  limits: "Does not defend against a compromised API host holding the writer key.",
  what_is_on_chain: ["Merkle root of finding instances per scan"],
  what_is_not_on_chain: ["identity names, emails or principals"],
};

const SCANS: LedgerScanPage = {
  items: [
    {
      scan_id: 12,
      snapshot_month: 12,
      merkle_root: "0x9034586d078bc42c7f3fe579ffc7dac848656aec227ad1ef9e4078443ff9e42e",
      snapshot_hash: "0x6948fb92",
      ruleset_hash: "0xa718ba37",
      finding_count: 49,
      ledger_scan_index: 11,
      ledger_tx: "0xcc4145bf",
      ledger_status: "anchored",
      block_number: 184,
      chain_root: "0x9034586d078bc42c7f3fe579ffc7dac848656aec227ad1ef9e4078443ff9e42e",
      timestamp: 1788253200,
    },
  ],
  total: 1,
  limit: 50,
  offset: 0,
};

const DECISIONS: LedgerDecisionPage = { items: [], total: 0, limit: 50, offset: 0 };
const SUMMARY = { ledger: { status: "anchored", last_scan_id: 12 } } as unknown as EstateSummary;

const VERIFY: LedgerVerifyOut = {
  scan_id: 12,
  passed: true,
  computed_root: SCANS.items[0]!.merkle_root ?? null,
  chain_root: SCANS.items[0]!.chain_root ?? null,
  scan_index: 11,
  finding_count: 49,
  detail: "PASS: recomputed root matches getCommit(scanIndex).findingsRoot",
};

vi.mock("../api/endpoints", () => ({
  getLedgerInfo: () => Promise.resolve(INFO),
  listLedgerScans: () => Promise.resolve(SCANS),
  listLedgerDecisions: () => Promise.resolve(DECISIONS),
  getEstateSummary: () => Promise.resolve(SUMMARY),
  verifyLedgerScan: () => Promise.resolve(VERIFY),
}));

describe("LedgerPage", () => {
  it("names the contract, the chain and the one writer that signs", async () => {
    renderWithProviders(<LedgerPage />, { route: "/ledger" });

    // Inline hex is shortened to its ends; the full value is on the copy control.
    expect(await screen.findByText(shortHex(INFO.contract_address))).toBeInTheDocument();
    expect(screen.getAllByText(String(INFO.chain_id)).length).toBeGreaterThan(0);
    expect(screen.getByText(shortHex(INFO.writer_address))).toBeInTheDocument();
    expect(screen.getByText(/nothing else signs/)).toBeInTheDocument();
    // The purpose-and-limits statement lives in the threat model and the report now, not here.
    expect(screen.queryByText(/Protects against/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Does not protect against/)).not.toBeInTheDocument();
  });

  it("lists the commit with its root, transaction, block and status", async () => {
    renderWithProviders(<LedgerPage />, { route: "/ledger" });

    expect(await screen.findByText("184")).toBeInTheDocument();
    expect(screen.getByText("Anchored")).toBeInTheDocument();
    expect(screen.getByText("August 2026")).toBeInTheDocument();
  });

  it("verifies a scan and shows PASS with both roots", async () => {
    renderWithProviders(<LedgerPage />, { route: "/ledger" });

    fireEvent.click(await screen.findByRole("button", { name: "Verify" }));

    expect(await screen.findByText(/PASS · PASS: recomputed root matches/)).toBeInTheDocument();
    expect(screen.getByText("Recomputed root")).toBeInTheDocument();
    expect(screen.getByText("Root on chain")).toBeInTheDocument();
  });
});
