import { useEffect, useState } from "react";
import type { PlanStatus } from "../../api/types";
import { useDebounced } from "../../lib/useDebounced";
import { SearchInput, Select } from "../ui/Field";
import { Tabs, type TabItem } from "../ui/Tabs";
import { PLAN_STATUS } from "./planMeta";

export interface PlanFilterState {
  status: string;
  department: string;
  q: string;
}

const STATUS_ORDER: readonly PlanStatus[] = ["proposed", "approved", "applied", "rejected"];

export interface PlanFiltersProps {
  value: PlanFilterState;
  onChange: (patch: Partial<PlanFilterState>) => void;
  counts: Record<string, number>;
  total: number;
  departments: readonly string[];
}

/** Queue filters (SPEC §13 vocabulary): status tabs first — the approver's job. */
export function PlanFilters({ value, onChange, counts, total, departments }: PlanFiltersProps) {
  const [search, setSearch] = useState(value.q);
  const debounced = useDebounced(search);

  useEffect(() => {
    if (debounced !== value.q) onChange({ q: debounced });
  }, [debounced, value.q, onChange]);

  useEffect(() => {
    setSearch((current) => (current === value.q ? current : value.q));
  }, [value.q]);

  const items: TabItem<string>[] = [
    { value: "", label: "All", badge: total },
    ...STATUS_ORDER.map((status) => ({
      value: status,
      label: PLAN_STATUS[status].label,
      badge: counts[status] ?? 0,
    })),
  ];

  return (
    <div className="flex flex-col gap-2">
      <Tabs
        label="Plan status"
        idBase="plan-status"
        value={value.status}
        items={items}
        onChange={(status) => onChange({ status })}
      />
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <SearchInput label="Identity" value={search} onChange={setSearch} placeholder="Search by name" />
        <Select
          label="Department"
          anyLabel="All"
          value={value.department}
          options={departments.map((d) => ({ value: d, label: d }))}
          onChange={(department) => onChange({ department })}
        />
      </div>
    </div>
  );
}
