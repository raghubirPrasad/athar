import type { Altitude, FindingOut, GrantOut } from "../../api/types";
import { atLeast } from "../../lib/altitude";
import { formatMonthLabel } from "../../lib/format";
import { ruleLabel } from "../../lib/rules";
import { FindingBody } from "../findings/FindingBody";
import { findingStatusLook } from "../findings/findingStatus";
import { VerifyScanButton } from "../ledger/VerifyScanButton";
import { Badge } from "../ui/Badge";
import { Card, CardSection } from "../ui/Card";
import { SeverityBadge } from "../ui/SeverityBadge";
import { AgentPanel } from "./AgentPanel";
import { ExceptionBadge } from "./ExceptionPanel";

export interface IdentityFindingCardProps {
  finding: FindingOut;
  altitude: Altitude;
  grantsById: ReadonlyMap<string, GrantOut>;
}

/**
 * One finding on the drill-down, rendered at the reader's altitude with the
 * actions that move it through its lifecycle (SPEC §10.2, §10.3, §14).
 */
export function IdentityFindingCard({ finding, altitude, grantsById }: IdentityFindingCardProps) {
  const status = findingStatusLook(finding.status);

  return (
    <Card
      flush
      title={
        <span className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={finding.severity} />
          {ruleLabel(finding.rule_id, finding.rule_name)}
        </span>
      }
      subtitle={
        <span className="flex flex-wrap items-center gap-1.5">
          <Badge tone={status.tone}>
            <span aria-hidden="true">{status.glyph}</span> {status.label}
          </Badge>
          <span className="text-fg-muted">Since {formatMonthLabel(finding.first_seen_month)}</span>
          {finding.exception && <ExceptionBadge exception={finding.exception} />}
        </span>
      }
      actions={
        <span className="tabular text-xs text-fg-muted" title="Risk score of the identity at this scan">
          score {finding.score}
        </span>
      }
    >
      <CardSection>
        <FindingBody
          finding={finding}
          altitude={altitude}
          grantsById={grantsById}
          ledgerAction={<VerifyScanButton scanId={finding.scan_id} label="Verify this scan on chain" />}
        />
      </CardSection>

      {atLeast(altitude, "explanation") && (
        <CardSection title="Agent">
          <AgentPanel finding={finding} />
        </CardSection>
      )}
    </Card>
  );
}
