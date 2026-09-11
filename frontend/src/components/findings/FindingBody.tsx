import { useMemo, type ReactNode } from "react";
import type { Altitude, FindingOut, GrantOut } from "../../api/types";
import { atLeast } from "../../lib/altitude";
import { prettyJson } from "../../lib/download";
import { formatMonthLabel } from "../../lib/format";
import { Badge } from "../ui/Badge";
import { CodeBlock } from "../ui/CodeBlock";
import { groupCitedRows, type CitedRowGroup } from "./citedRows";
import { instanceObject, ledgerRef, rulesFired } from "./evidence";

export interface FindingBodyProps {
  finding: FindingOut;
  altitude: Altitude;
  /** Cited grants by id, so the evidence altitude can show the raw snippet. */
  grantsById?: ReadonlyMap<string, GrantOut>;
  /** Rendered under the ledger leaf, e.g. a "Verify on chain" button. */
  ledgerAction?: ReactNode;
}

const REF_LABEL: Record<string, string> = {
  grant: "Grant",
  credential: "Credential",
  activity: "Activity",
  event: "Event",
  principal: "Principal",
  exception: "Exception",
  identity: "Identity",
  resource: "Resource",
  path: "Path",
  project: "Project",
};

/** Distinct provider snippets shown in full before the rest collapse. */
const MAX_SNIPPETS = 4;

/** One cited row: the canonical reference, then the provider JSON behind it. */
function CitedRow({ group }: { group: CitedRowGroup }) {
  const { ref, grant, snippet, duplicates } = group;
  return (
    <li className="flex flex-col gap-1">
      <span className="flex flex-wrap items-center gap-1.5 text-[13px]">
        <Badge tone="neutral">{REF_LABEL[ref.kind] ?? ref.kind}</Badge>
        <code className="font-mono text-[12.5px] text-fg">{ref.ref}</code>
        {ref.note && <span className="text-fg-muted">· {ref.note}</span>}
        {duplicates.length > 0 && (
          <span className="text-fg-muted" title={duplicates.slice(0, 20).join(", ")}>
            · {duplicates.length} further cited {duplicates.length === 1 ? "row has" : "rows have"} this exact
            snippet
          </span>
        )}
      </span>
      {grant && snippet && (
        <CodeBlock label={`${grant.source_file} ${grant.source_pointer}`} value={snippet} maxHeight="14rem" />
      )}
    </li>
  );
}

/**
 * One finding rendered at the reader's altitude (SPEC §10.2) from the same
 * facts: a sentence, then why and since when, then the rows the rule cited and
 * the leaf those rows hash into. The cited rows are folded by the snippet behind
 * them and capped, the way the escalation chain caps paths: a rule that cites
 * the same wildcard statement two hundred times has one piece of evidence.
 */
export function FindingBody({ finding, altitude, grantsById, ledgerAction }: FindingBodyProps) {
  const evidence = finding.altitudes.evidence;
  const leaf = ledgerRef(evidence);
  const fired = rulesFired(evidence);
  const instance = instanceObject(evidence);
  const groups = useMemo(
    () => groupCitedRows(finding.evidence_refs, grantsById),
    [finding.evidence_refs, grantsById],
  );
  const shown = groups.slice(0, MAX_SNIPPETS);
  const rest = groups.slice(MAX_SNIPPETS);

  return (
    <div className="flex flex-col gap-3">
      <p className="text-[13.5px] leading-6 text-fg">{finding.altitudes.headline}</p>

      {atLeast(altitude, "explanation") && (
        <>
          <p className="text-[13px] leading-6 text-fg-muted">{finding.altitudes.explanation}</p>
          <p className="text-xs text-fg-muted">
            First seen in {formatMonthLabel(finding.first_seen_month)} · still present in{" "}
            {formatMonthLabel(finding.snapshot_month)}
          </p>
          {(finding.attack_techniques.length > 0 || finding.control_refs.length > 0) && (
            <div className="flex flex-wrap items-center gap-1.5">
              {finding.attack_techniques.map((technique) => (
                <Badge key={technique} tone="neutral" title="MITRE ATT&CK technique">
                  {technique}
                </Badge>
              ))}
              {finding.control_refs.map((control) => (
                <Badge key={control} tone="neutral" title="Control reference">
                  {control}
                </Badge>
              ))}
            </div>
          )}
        </>
      )}

      {atLeast(altitude, "evidence") && (
        <div className="flex flex-col gap-3 border-t border-border pt-3">
          <div>
            <h4 className="text-xs font-semibold uppercase tracking-wide text-fg-muted">
              Rows this rule cited
            </h4>
            {finding.evidence_refs.length === 0 ? (
              <p className="mt-1 text-[13px] text-fg-muted">
                No rows cited — the engine does not emit a finding without evidence.
              </p>
            ) : (
              <>
                {(groups.length < finding.evidence_refs.length || rest.length > 0) && (
                  <p className="mt-1 text-xs text-fg-muted">
                    {finding.evidence_refs.length} rows cited, {groups.length} distinct provider{" "}
                    {groups.length === 1 ? "snippet" : "snippets"}
                    {rest.length > 0 ? ` · the first ${shown.length} are shown` : ""}.
                  </p>
                )}
                <ul className="mt-1.5 flex flex-col gap-2">
                  {shown.map((group) => (
                    <CitedRow key={`${group.ref.kind}:${group.ref.ref}`} group={group} />
                  ))}
                </ul>
                {rest.length > 0 && (
                  <details className="mt-2 rounded-md border border-border bg-surface-muted px-3 py-2">
                    <summary className="cursor-pointer text-[13px] font-medium text-fg">
                      Show the other {rest.length} cited {rest.length === 1 ? "row" : "rows"}
                    </summary>
                    <ul className="mt-2 flex flex-col gap-1.5">
                      {rest.map((group) => (
                        <li
                          key={`rest-${group.ref.kind}:${group.ref.ref}`}
                          className="flex flex-wrap items-center gap-1.5 text-[13px]"
                        >
                          <Badge tone="neutral">{REF_LABEL[group.ref.kind] ?? group.ref.kind}</Badge>
                          <code className="font-mono text-[12.5px] text-fg">{group.ref.ref}</code>
                          {group.ref.note && <span className="text-fg-muted">· {group.ref.note}</span>}
                          {group.duplicates.length > 0 && (
                            <span className="text-fg-muted">
                              · same snippet as {group.duplicates.length} more
                            </span>
                          )}
                        </li>
                      ))}
                    </ul>
                  </details>
                )}
              </>
            )}
          </div>

          {fired.length > 0 && (
            <p className="text-xs text-fg-muted">
              Rules fired: <span className="font-mono text-fg">{fired.join(", ")}</span> · the rule engine
              decided this, not a model.
            </p>
          )}

          {instance && (
            <div>
              <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-fg-muted">
                Committed instance
              </h4>
              <CodeBlock label="canonical instance" value={prettyJson(instance)} maxHeight="16rem" />
            </div>
          )}

          <div className="flex flex-col gap-1.5">
            <h4 className="text-xs font-semibold uppercase tracking-wide text-fg-muted">Ledger</h4>
            <dl className="grid gap-1.5 text-[13px] sm:grid-cols-[10rem_minmax(0,1fr)]">
              <dt className="text-fg-muted">Instance hash</dt>
              <dd>
                <CodeBlock inline value={finding.instance_hash} label="instance hash" />
              </dd>
              <dt className="text-fg-muted">Leaf</dt>
              <dd>
                <CodeBlock inline value={leaf?.leaf ?? finding.leaf} label="leaf" />
              </dd>
              {leaf?.merkleRoot && (
                <>
                  <dt className="text-fg-muted">Root of scan {leaf.scanId ?? finding.scan_id}</dt>
                  <dd>
                    <CodeBlock inline value={leaf.merkleRoot} label="merkle root" />
                  </dd>
                </>
              )}
              <dt className="text-fg-muted">Inclusion proof</dt>
              <dd className="text-fg-muted">
                {finding.proof.length} sibling {finding.proof.length === 1 ? "hash" : "hashes"}
              </dd>
            </dl>
            {ledgerAction && <div className="mt-1">{ledgerAction}</div>}
          </div>
        </div>
      )}
    </div>
  );
}
