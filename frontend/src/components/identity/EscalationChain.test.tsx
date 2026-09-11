import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { PathEdgeOut } from "../../api/types";
import { EscalationChain } from "./EscalationChain";
import { pathNodes } from "./escalationPath";

const PATH: PathEdgeOut[] = [
  { src: "emp-0022", verb: "write", dst: "aws:role/AppDeployer", grant_id: "grant-emp-0022-04" },
  { src: "aws:role/AppDeployer", verb: "grant", dst: "aws:policy/*", grant_id: null },
  { src: "aws:policy/*", verb: "admin", dst: "aws:account", grant_id: "grant-emp-0022-07" },
];

describe("pathNodes", () => {
  it("returns the source of the first edge and then every destination", () => {
    expect(pathNodes(PATH)).toEqual([
      "emp-0022",
      "aws:role/AppDeployer",
      "aws:policy/*",
      "aws:account",
    ]);
  });

  it("returns nothing for an empty path rather than throwing", () => {
    expect(pathNodes([])).toEqual([]);
  });
});

describe("EscalationChain", () => {
  it("renders the hops as an ordered list, in path order", () => {
    render(<EscalationChain paths={[PATH]} />);

    const list = screen.getByRole("list", { name: "Escalation path 1" });
    const items = within(list).getAllByRole("listitem");
    expect(items).toHaveLength(4);
    expect(items[0]).toHaveTextContent("emp-0022");
    expect(items[1]).toHaveTextContent("aws:role/AppDeployer");
    expect(items[2]).toHaveTextContent("aws:policy/*");
    expect(items[3]).toHaveTextContent("aws:account");
  });

  it("labels the first node as the identity and the last as what it reaches", () => {
    render(<EscalationChain paths={[PATH]} />);
    const items = within(screen.getByRole("list", { name: "Escalation path 1" })).getAllByRole("listitem");
    expect(items[0]).toHaveTextContent("Identity");
    expect(items[3]).toHaveTextContent("Reaches");
  });

  it("names the verb of every hop and cites the grant that permits it", () => {
    render(<EscalationChain paths={[PATH]} />);

    expect(screen.getByText("write")).toBeInTheDocument();
    expect(screen.getByText("grant")).toBeInTheDocument();
    expect(screen.getByText("admin")).toBeInTheDocument();
    expect(screen.getByText("grant-emp-0022-04")).toBeInTheDocument();
    expect(screen.getByText("grant-emp-0022-07")).toBeInTheDocument();
  });

  it("says so when the graph found no path, instead of drawing an empty chain", () => {
    render(<EscalationChain paths={[]} />);
    expect(screen.getByText("No escalation path")).toBeInTheDocument();
  });

  it("summarises the paths it did not draw", () => {
    render(<EscalationChain paths={[PATH, PATH, PATH, PATH]} max={2} />);
    expect(screen.getByText(/2 further paths/)).toBeInTheDocument();
  });
});
