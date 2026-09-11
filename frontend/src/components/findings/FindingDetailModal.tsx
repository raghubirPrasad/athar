import type { Altitude, FindingOut } from "../../api/types";
import { formatMonthLabel } from "../../lib/format";
import { ruleLabel } from "../../lib/rules";
import { ExceptionBadge } from "../identity/ExceptionPanel";
import { VerifyScanButton } from "../ledger/VerifyScanButton";
import { Badge } from "../ui/Badge";
import { ButtonLink } from "../ui/Button";
import { CloudIcons } from "../ui/CloudIcon";
import { Modal } from "../ui/Modal";
import { SeverityBadge } from "../ui/SeverityBadge";
import { AltitudeToggle } from "./AltitudeToggle";
import { FindingBody } from "./FindingBody";
import { findingStatusLook } from "./findingStatus";

export interface FindingDetailModalProps {
  finding: FindingOut | null;
  altitude: Altitude;
  onAltitudeChange: (altitude: Altitude) => void;
  onClose: () => void;
}

/**
 * A finding opened from the flat list, at the reader's altitude (SPEC §10.2).
 * The full drill-down — score line items, escalation chain, agent actions —
 * lives on the identity page, one click away.
 */
export function FindingDetailModal({ finding, altitude, onAltitudeChange, onClose }: FindingDetailModalProps) {
  if (!finding) return null;
  const status = findingStatusLook(finding.status);

  return (
    <Modal
      open
      size="lg"
      onClose={onClose}
      title={`${finding.display_name} · ${ruleLabel(finding.rule_id, finding.rule_name)}`}
      description={
        <span className="flex flex-wrap items-center gap-1.5">
          <SeverityBadge severity={finding.severity} />
          <Badge tone={status.tone}>
            <span aria-hidden="true">{status.glyph}</span> {status.label}
          </Badge>
          <Badge tone="neutral">{finding.department}</Badge>
          <CloudIcons clouds={finding.clouds} />
          <span className="text-fg-muted">Since {formatMonthLabel(finding.first_seen_month)}</span>
          {finding.exception && <ExceptionBadge exception={finding.exception} />}
        </span>
      }
      footer={
        <>
          <ButtonLink to={`/identities/${encodeURIComponent(finding.identity_id)}?altitude=${altitude}`} variant="primary">
            Open the identity drill-down
          </ButtonLink>
        </>
      }
    >
      <div className="mb-3 flex items-center justify-between gap-2">
        <AltitudeToggle value={altitude} onChange={onAltitudeChange} size="sm" />
        <span className="font-mono text-[11.5px] text-fg-faint" title="Finding key">
          {finding.finding_key}
        </span>
      </div>
      <FindingBody
        finding={finding}
        altitude={altitude}
        ledgerAction={<VerifyScanButton scanId={finding.scan_id} label="Verify this scan on chain" />}
      />
    </Modal>
  );
}
