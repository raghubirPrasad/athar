import type { LedgerInfo } from "../../api/types";
import { Badge } from "../ui/Badge";
import { Card } from "../ui/Card";
import { CodeBlock } from "../ui/CodeBlock";

/**
 * The contract this deployment anchors to: address, chain and the one writer
 * that signs. What the ledger does and does not protect against is stated in
 * docs/THREAT_MODEL.md and the submission report rather than on this page.
 */
/** Anchor for the "Chain id" tile: the chain, contract and writer live here. */
export const LEDGER_INFO_ANCHOR = "ledger-contract";

export function LedgerInfoCard({ info }: { info: LedgerInfo }) {
  return (
    <Card
      id={LEDGER_INFO_ANCHOR}
      title="Governance ledger contract"
      subtitle="Every scan's findings root and every decision is anchored here"
      actions={
        <Badge tone={info.enabled ? "ok" : "neutral"}>
          <span aria-hidden="true">{info.enabled ? "✓" : "–"}</span>
          {info.enabled ? "Anchoring enabled" : "Anchoring disabled"}
        </Badge>
      }
    >
      <dl className="grid gap-2 text-[13px] sm:grid-cols-[9rem_minmax(0,1fr)]">
        <dt className="text-fg-muted">Contract</dt>
        <dd>{info.contract_address ? <CodeBlock inline value={info.contract_address} label="contract" /> : "—"}</dd>
        <dt className="text-fg-muted">Chain id</dt>
        <dd className="tabular text-fg">{info.chain_id ?? "—"}</dd>
        <dt className="text-fg-muted">Writer address</dt>
        <dd>
          {info.writer_address ? (
            <span className="flex flex-wrap items-center gap-2">
              <CodeBlock inline value={info.writer_address} label="writer" />
              <span className="text-xs text-fg-muted">
                One writer owns the key and the nonce; nothing else signs.
              </span>
            </span>
          ) : (
            "—"
          )}
        </dd>
      </dl>
    </Card>
  );
}
