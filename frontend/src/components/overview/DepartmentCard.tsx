import { Link } from "react-router-dom";
import type { DepartmentRollup } from "../../api/types";
import { formatInt } from "../../lib/format";
import { SeverityBadge } from "../ui/SeverityBadge";
import { HalfLifeValue } from "./HalfLifeValue";

/**
 * "Finance · 12 findings · 3 critical · offboarding half-life: Never" (SPEC §14).
 * Every number links to the rows behind it (PRD §8.2).
 */
export function DepartmentCard({ row }: { row: DepartmentRollup }) {
  const dept = encodeURIComponent(row.department);
  return (
    <article className="flex flex-col gap-2 rounded-lg border border-border bg-surface p-3 shadow-card">
      <div className="flex items-baseline justify-between gap-2">
        <h3 className="truncate text-sm font-semibold text-fg">{row.department}</h3>
        <Link
          to={`/identities?department=${dept}`}
          className="shrink-0 text-xs text-fg-muted hover:text-accent-strong hover:underline"
        >
          {formatInt(row.identities)} identities
        </Link>
      </div>

      <div className="flex flex-wrap items-center gap-1.5">
        <Link
          to={`/findings?department=${dept}`}
          className="tabular rounded border border-border bg-surface-muted px-1.5 py-px text-xs font-medium text-fg hover:border-accent"
        >
          {formatInt(row.findings)} findings
        </Link>
        {row.critical > 0 && (
          <Link to={`/findings?department=${dept}&severity=Critical`} className="hover:opacity-80">
            <SeverityBadge severity="Critical" />
            <span className="tabular ml-1 text-xs text-fg-muted">{row.critical}</span>
          </Link>
        )}
        {row.high > 0 && (
          <Link to={`/findings?department=${dept}&severity=High`} className="hover:opacity-80">
            <SeverityBadge severity="High" />
            <span className="tabular ml-1 text-xs text-fg-muted">{row.high}</span>
          </Link>
        )}
      </div>

      <p className="flex flex-wrap items-center gap-1.5 text-xs text-fg-muted">
        Offboarding half-life:{" "}
        <HalfLifeValue
          months={row.offboarding_half_life}
          label={row.half_life_label}
          to={`/timeline?department=${dept}`}
          linkLabel={`Half-life evidence for ${row.department}`}
        />
      </p>
    </article>
  );
}
