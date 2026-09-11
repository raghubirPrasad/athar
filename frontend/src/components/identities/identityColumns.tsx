import { createColumnHelper } from "@tanstack/react-table";
import type { IdentityRow } from "../../api/types";
import { formatDate, formatPct } from "../../lib/format";
import { ruleLabel } from "../../lib/rules";
import { Badge } from "../ui/Badge";
import { CloudIcons } from "../ui/CloudIcon";
import { ScoreBar } from "../ui/ScoreBar";
import { SeverityBadge } from "../ui/SeverityBadge";

const column = createColumnHelper<IdentityRow>();

/** Column ids match the API's field names (see ./sort.ts for what is sortable). */
export const identityColumns = [
  column.accessor("display_name", {
    header: "Name",
    cell: (info) => (
      <span className="flex flex-col">
        <span className="font-medium text-fg">{info.getValue()}</span>
        <span className="font-mono text-[11.5px] text-fg-faint">{info.row.original.identity_id}</span>
      </span>
    ),
  }),
  column.accessor("identity_type", {
    header: "Type",
    cell: (info) => (
      <Badge tone={info.getValue() === "service" ? "info" : "neutral"}>
        {info.getValue() === "service" ? "Service" : "Human"}
      </Badge>
    ),
  }),
  column.accessor("department", { header: "Department" }),
  column.accessor("clouds", {
    header: "Clouds",
    cell: (info) => <CloudIcons clouds={info.getValue()} />,
  }),
  column.accessor("score", {
    header: "Score",
    cell: (info) => <ScoreBar value={info.getValue()} severity={info.row.original.severity} />,
  }),
  column.accessor("severity", {
    header: "Severity",
    cell: (info) => <SeverityBadge severity={info.getValue()} />,
  }),
  column.accessor("top_rule", {
    header: "Top rule",
    cell: (info) => {
      const ruleId = info.getValue();
      // An identity can be Critical on blast radius alone (SPEC §8.3): the
      // formula, not a rule, produced the score. An em dash reads as missing
      // data, so the cell says which of the two it is.
      if (!ruleId) {
        return (
          <span
            className="block max-w-[14rem] text-[13px] text-fg-muted"
            title="No detection rule matched this identity; its score is the scoring formula on measured blast radius."
          >
            scored on blast radius alone — no rule fired
          </span>
        );
      }
      return (
        <span className="whitespace-nowrap text-[13px] text-fg-muted">
          {ruleLabel(ruleId, info.row.original.top_rule_name)}
        </span>
      );
    },
  }),
  column.accessor("blast_radius_pct", {
    header: "Blast radius",
    cell: (info) => <span className="tabular">{formatPct(info.getValue(), 1)}</span>,
  }),
  column.accessor("last_activity_at", {
    header: "Last activity",
    cell: (info) => <span className="whitespace-nowrap">{formatDate(info.getValue())}</span>,
  }),
  column.accessor("status", {
    header: "Status",
    cell: (info) => {
      const status = info.getValue();
      return (
        <Badge tone={status === "departed" ? "danger" : status === "on_leave" ? "warn" : "neutral"}>
          {status === "on_leave" ? "On leave" : status === "departed" ? "Departed" : "Active"}
        </Badge>
      );
    },
  }),
];
