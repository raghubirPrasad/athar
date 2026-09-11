import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { GrantOut } from "../../api/types";
import { GRANT } from "../../test/fixtures";
import { GrantEvidence } from "./GrantEvidence";

const GRANTS: GrantOut[] = Array.from({ length: 95 }, (_, index) => ({
  ...GRANT,
  grant_id: `grant-${index}`,
  scope_ref: `arn:aws:s3:::bucket-${index}`,
  // Most rows repeat the same wildcard statement, as a real export does.
  raw_snippet: index % 20 === 0 ? { PolicyName: `Policy-${index}` } : { PolicyName: "AdministratorAccess" },
}));

describe("GrantEvidence", () => {
  it("draws a bounded number of rows and collapses the rest", () => {
    render(<GrantEvidence grants={GRANTS} />);

    expect(screen.getByText("Show the other 87 grants")).toBeInTheDocument();
    expect(screen.getByText(/95 grants on this identity/)).toBeInTheDocument();
    // Every grant is still listed — the tail is collapsed, not dropped.
    expect(screen.getAllByRole("listitem")).toHaveLength(95);
  });

  it("prints a repeated provider snippet once and points at the row that has it", () => {
    render(<GrantEvidence grants={GRANTS} />);

    expect(screen.getAllByRole("button", { name: "Copy" })).toHaveLength(2);
    expect(screen.getAllByText(/Same provider JSON as/).length).toBeGreaterThan(0);
  });

  it("puts the rows a rule cited first", () => {
    render(<GrantEvidence grants={GRANTS} highlight={new Set(["grant-90"])} />);

    const first = screen.getAllByRole("listitem")[0];
    expect(first).toHaveTextContent("grant-90");
    expect(first).toHaveTextContent("cited by a rule");
  });

  it("shows a short list in full, with no disclosure", () => {
    render(<GrantEvidence grants={GRANTS.slice(0, 3)} />);

    expect(screen.queryByText(/Show the other/)).not.toBeInTheDocument();
    expect(screen.queryByText(/grants on this identity/)).not.toBeInTheDocument();
  });
});
