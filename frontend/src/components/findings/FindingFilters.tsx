import { useEffect, useMemo, useState } from "react";
import { formatMonthShort } from "../../lib/format";
import { ruleOptions, useRules } from "../../lib/rules";
import { useDebounced } from "../../lib/useDebounced";
import { Button } from "../ui/Button";
import { SearchInput, Select, type SelectOption } from "../ui/Field";
import { FINDING_STATUSES, findingStatusLook } from "./findingStatus";
import { DEFAULT_SORT, isFindingFilterDirty, type FindingFilterState } from "./filters";

const CLOUDS: SelectOption[] = [
  { value: "aws", label: "AWS" },
  { value: "azure", label: "Azure" },
  { value: "gcp", label: "GCP" },
];
const SEVERITIES: SelectOption[] = ["Critical", "High", "Medium", "Low"].map((s) => ({ value: s, label: s }));
const STATUSES: SelectOption[] = FINDING_STATUSES.map((status) => ({
  value: status,
  label: findingStatusLook(status).label,
}));

export interface FindingFiltersProps {
  value: FindingFilterState;
  onChange: (patch: Partial<FindingFilterState>) => void;
  departments: readonly string[];
  /** Highest simulated month with data, so the month select never invents one. */
  currentMonth: number;
}

/** Server-side filters for the findings list (SPEC §13). */
export function FindingFilters({ value, onChange, departments, currentMonth }: FindingFiltersProps) {
  const [search, setSearch] = useState(value.q);
  const debounced = useDebounced(search);
  const rules = useRules();
  // The catalogue is the API's (SPEC §7); a rule already in the URL stays
  // selectable even if the catalogue has not arrived yet.
  const ruleFilterOptions: SelectOption[] = useMemo(() => {
    const options = ruleOptions(rules);
    return options.some((option) => option.value === value.rule) || value.rule === ""
      ? options
      : [...options, { value: value.rule, label: value.rule }];
  }, [rules, value.rule]);

  useEffect(() => {
    if (debounced !== value.q) onChange({ q: debounced, offset: 0 });
  }, [debounced, value.q, onChange]);

  useEffect(() => {
    setSearch((current) => (current === value.q ? current : value.q));
  }, [value.q]);

  const months: SelectOption[] = Array.from({ length: Math.max(0, currentMonth) }, (_, index) => {
    const month = currentMonth - index;
    return { value: String(month), label: `${formatMonthShort(month)} (m${month})` };
  });

  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-2 rounded-lg border border-border bg-surface px-3 py-2">
      <SearchInput label="Name" value={search} onChange={setSearch} placeholder="Search identities" />
      <Select
        label="Cloud"
        anyLabel="Any"
        value={value.cloud}
        options={CLOUDS}
        onChange={(cloud) => onChange({ cloud, offset: 0 })}
      />
      <Select
        label="Department"
        anyLabel="All"
        value={value.department}
        options={departments.map((d) => ({ value: d, label: d }))}
        onChange={(department) => onChange({ department, offset: 0 })}
      />
      <Select
        label="Rule"
        anyLabel="Any"
        value={value.rule}
        options={ruleFilterOptions}
        onChange={(rule) => onChange({ rule, offset: 0 })}
      />
      <Select
        label="Severity"
        anyLabel="Any"
        value={value.severity}
        options={SEVERITIES}
        onChange={(severity) => onChange({ severity, offset: 0 })}
      />
      <Select
        label="Month"
        anyLabel="Current"
        value={value.month}
        options={months}
        onChange={(month) => onChange({ month, offset: 0 })}
      />
      <Select
        label="Status"
        anyLabel="Any"
        value={value.status}
        options={STATUSES}
        onChange={(status) => onChange({ status, offset: 0 })}
      />
      {isFindingFilterDirty(value) && (
        <Button
          size="sm"
          variant="ghost"
          onClick={() =>
            onChange({
              cloud: "",
              department: "",
              rule: "",
              severity: "",
              status: "",
              month: "",
              q: "",
              sort: DEFAULT_SORT,
              offset: 0,
            })
          }
        >
          Clear filters
        </Button>
      )}
    </div>
  );
}
