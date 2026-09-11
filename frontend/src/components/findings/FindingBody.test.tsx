import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { EvidenceRefOut, FindingOut, GrantOut } from "../../api/types";
import { FINDING, GRANT } from "../../test/fixtures";
import { groupCitedRows } from "./citedRows";
import { FindingBody } from "./FindingBody";

/** 25 grants citing the same statement, plus two that differ — the R1 shape. */
function estate(sameCount: number): { finding: FindingOut; grants: Map<string, GrantOut> } {
  const grants = new Map<string, GrantOut>();
  const refs: EvidenceRefOut[] = [];
  for (let index = 0; index < sameCount; index += 1) {
    const id = `grant-same-${index}`;
    grants.set(id, { ...GRANT, grant_id: id, raw_snippet: { PolicyName: "AdministratorAccess" } });
    refs.push({ kind: "grant", ref: id, note: "aws admin" });
  }
  for (const name of ["BillingFullAccess", "SecurityAudit", "NetworkAdmin", "DataOwner", "KeyAdmin"]) {
    const id = `grant-${name}`;
    grants.set(id, { ...GRANT, grant_id: id, raw_snippet: { PolicyName: name } });
    refs.push({ kind: "grant", ref: id, note: "aws admin" });
  }
  return { finding: { ...FINDING, evidence_refs: refs }, grants };
}

describe("groupCitedRows", () => {
  it("folds rows whose provider JSON is byte-identical", () => {
    const { finding, grants } = estate(25);

    const groups = groupCitedRows(finding.evidence_refs, grants);

    expect(groups).toHaveLength(6);
    expect(groups[0]?.duplicates).toHaveLength(24);
    expect(groups[1]?.duplicates).toHaveLength(0);
  });

  it("keeps rows it cannot compare separate", () => {
    const refs: EvidenceRefOut[] = [
      { kind: "event", ref: "evt-1", note: "" },
      { kind: "event", ref: "evt-2", note: "" },
    ];

    expect(groupCitedRows(refs, new Map())).toHaveLength(2);
  });
});

describe("FindingBody at the evidence altitude", () => {
  it("caps the raw snippets and collapses the rest behind a disclosure", () => {
    const { finding, grants } = estate(25);

    render(<FindingBody finding={finding} altitude="evidence" grantsById={grants} />);

    // Four distinct snippets drawn, the rest reachable but not on the page.
    expect(screen.getAllByRole("button", { name: "Copy" }).length).toBeLessThanOrEqual(5);
    expect(screen.getByText("Show the other 2 cited rows")).toBeInTheDocument();
    expect(screen.getByText(/30 rows cited, 6 distinct provider snippets/)).toBeInTheDocument();
  });

  it("says how many further rows carry the same snippet, so nothing is lost", () => {
    const { finding, grants } = estate(25);

    render(<FindingBody finding={finding} altitude="evidence" grantsById={grants} />);

    expect(screen.getByText(/24 further cited rows have this exact snippet/)).toBeInTheDocument();
  });

  it("draws a small finding in full, with no disclosure at all", () => {
    const grants = new Map([[GRANT.grant_id, GRANT]]);

    render(<FindingBody finding={FINDING} altitude="evidence" grantsById={grants} />);

    expect(screen.queryByText(/Show the other/)).not.toBeInTheDocument();
    expect(screen.getByText(`${GRANT.source_file} ${GRANT.source_pointer}`)).toBeInTheDocument();
  });
});
