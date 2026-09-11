import { describe, expect, it } from "vitest";
import { DEFAULT_LIMIT, DEFAULT_SORT, readFilters, toQuery, writeFilters } from "./filters";

const read = (search: string) => readFilters(new URLSearchParams(search));

describe("identity filter state", () => {
  it("defaults to the whole estate sorted by score descending", () => {
    const state = read("");
    expect(state.sort).toBe(DEFAULT_SORT);
    expect(state.limit).toBe(DEFAULT_LIMIT);
    expect(state.offset).toBe(0);
    expect(state.department).toBe("");
  });

  it("reads filters out of the URL and clamps the page size to the API's ceiling", () => {
    const state = read("severity=Critical&cloud=gcp&department=Finance&rule=R3&q=al&limit=9000&offset=50");
    expect(state).toMatchObject({
      severity: "Critical",
      cloud: "gcp",
      department: "Finance",
      rule: "R3",
      q: "al",
      limit: 500,
      offset: 50,
    });
  });

  it("ignores a junk limit rather than paging one row at a time", () => {
    expect(read("limit=abc").limit).toBe(DEFAULT_LIMIT);
    expect(read("limit=").limit).toBe(DEFAULT_LIMIT);
    expect(read("limit=0").limit).toBe(1);
  });

  it("writes only non-default values back to the URL", () => {
    expect(writeFilters(read("")).toString()).toBe("");
    expect(writeFilters(read("severity=High&offset=10")).toString()).toBe("severity=High&offset=10");
  });

  it("drops values the API's ListFilters would reject", () => {
    const query = toQuery(read("cloud=oracle&severity=Catastrophic&rule=R4"));
    expect(query.cloud).toBeUndefined();
    expect(query.severity).toBeUndefined();
    expect(query.rule).toBe("R4");
    expect(query.sort).toBe(DEFAULT_SORT);
  });
});
