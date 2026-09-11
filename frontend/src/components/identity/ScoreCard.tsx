import type { Altitude, ScoreOut } from "../../api/types";
import { atLeast } from "../../lib/altitude";
import { prettyJson } from "../../lib/download";
import { formatInt, formatPct } from "../../lib/format";
import { Card } from "../ui/Card";
import { CodeBlock } from "../ui/CodeBlock";
import { ScoreBar } from "../ui/ScoreBar";
import { SeverityBadge } from "../ui/SeverityBadge";
import { Table, TBody, Td, TableWrap, THead, Th, Tr } from "../ui/Table";
import { transparencyLine } from "./scoreLine";

export interface ScoreCardProps {
  score: ScoreOut;
  altitude: Altitude;
  id?: string;
}

/**
 * Risk score with every term of the formula on screen (SPEC §8.3). The number at
 * the top of the identity table is this card; nothing is scored off-screen.
 */
export function ScoreCard({ score, altitude, id }: ScoreCardProps) {
  return (
    <Card
      id={id}
      title="Risk score"
      subtitle="Measured blast radius, not an invented point value"
      actions={<SeverityBadge severity={score.severity} size="md" />}
    >
      <div className="flex flex-wrap items-center gap-4">
        <span className="flex items-baseline gap-2">
          <span className="tabular text-3xl font-semibold text-fg">{score.score}</span>
          <span className="text-xs text-fg-muted">of 100</span>
        </span>
        <ScoreBar value={score.score} severity={score.severity} />
        <span className="text-[13px] text-fg-muted">
          Reaches{" "}
          <span className="font-semibold text-fg">{formatPct(score.blast_radius * 100, 1)}</span> of the estate —{" "}
          {formatInt(score.reachable_resources)} resources, {formatInt(score.high_sensitivity_reached)} of them
          high-sensitivity.
        </span>
      </div>

      <p className="mt-3 rounded-md border border-border bg-surface-muted px-3 py-2 font-mono text-[12.5px] leading-6 text-fg">
        {transparencyLine(score)}
      </p>

      {atLeast(altitude, "explanation") && (
        <div className="mt-3">
          <TableWrap>
            <Table>
              <THead>
                <tr>
                  <Th>Term</Th>
                  <Th>Line item</Th>
                  <Th numeric>Value</Th>
                </tr>
              </THead>
              <TBody>
                {score.line_items.map((item) => (
                  <Tr key={`${item.term}:${item.label}`}>
                    <Td mono>{item.term}</Td>
                    <Td>
                      <span className="text-[13px] text-fg">{item.label}</span>
                      {atLeast(altitude, "evidence") && item.detail && Object.keys(item.detail).length > 0 && (
                        <CodeBlock className="mt-1" label={`${item.term} detail`} value={prettyJson(item.detail)} />
                      )}
                    </Td>
                    <Td numeric>{item.value.toFixed(2)}</Td>
                  </Tr>
                ))}
              </TBody>
            </Table>
          </TableWrap>
        </div>
      )}
    </Card>
  );
}
