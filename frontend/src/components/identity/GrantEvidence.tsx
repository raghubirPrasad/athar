import type { GrantOut } from "../../api/types";
import { prettyJson } from "../../lib/download";
import { formatMonthLabel } from "../../lib/format";
import { Badge } from "../ui/Badge";
import { CloudIcon } from "../ui/CloudIcon";
import { CodeBlock } from "../ui/CodeBlock";
import { EmptyState } from "../ui/EmptyState";

const CONTROL_VERBS = new Set(["admin", "grant", "impersonate", "delete", "write"]);

/** Rows drawn in full before the rest collapse; an identity can hold ninety. */
const MAX_ROWS = 8;

/** Cited rows first, then the order the API returned (`sort` is stable). */
function citedFirst(grants: readonly GrantOut[], highlight?: ReadonlySet<string>): GrantOut[] {
  return [...grants].sort(
    (a, b) => Number(highlight?.has(b.grant_id) ?? false) - Number(highlight?.has(a.grant_id) ?? false),
  );
}

/**
 * Canonical rows next to the provider JSON they came from (SPEC §5.2:
 * `raw_snippet` + `source_file` + JSON pointer is kept on every row). This is
 * the panel an engineer asks for when they do not believe the finding — which
 * means the rows a rule cited come first, the snippet is printed once per
 * distinct statement, and the long tail is a disclosure rather than a mile of
 * page. Nothing is dropped: every grant is still listed.
 */
export function GrantEvidence({ grants, highlight }: { grants: readonly GrantOut[]; highlight?: ReadonlySet<string> }) {
  if (grants.length === 0) {
    return (
      <EmptyState compact title="No grants" description="This identity holds no active grant in this snapshot." />
    );
  }

  const ordered = citedFirst(grants, highlight);
  const shown = ordered.slice(0, MAX_ROWS);
  const rest = ordered.slice(MAX_ROWS);
  const snippetOwner = new Map<string, string>();

  return (
    <div className="flex flex-col gap-3">
      {rest.length > 0 && (
        <p className="text-xs text-fg-muted">
          {grants.length} grants on this identity · the {shown.length} drawn below are the rows a rule cited, with
          their provider JSON.
        </p>
      )}

      <ul className="flex flex-col gap-3">
        {shown.map((grant) => {
          const cited = highlight?.has(grant.grant_id) ?? false;
          const snippet = prettyJson(grant.raw_snippet);
          const duplicateOf = snippetOwner.get(snippet);
          if (duplicateOf === undefined) snippetOwner.set(snippet, grant.grant_id);
          return (
            <li
              key={grant.grant_id}
              className={
                cited
                  ? "rounded-md border border-accent/40 bg-accent-soft/30 p-2.5"
                  : "rounded-md border border-border p-2.5"
              }
            >
              <div className="flex flex-wrap items-center gap-1.5">
                <CloudIcon cloud={grant.cloud} size={15} />
                <Badge tone={CONTROL_VERBS.has(grant.verb) ? "danger" : "neutral"} title="Canonical verb">
                  {grant.verb}
                </Badge>
                <Badge tone="neutral" title="Service category">
                  {grant.service_category}
                </Badge>
                <Badge tone="neutral" title="Scope level">
                  {grant.scope_level}
                </Badge>
                {grant.region && (
                  <Badge tone="neutral" title="Region">
                    {grant.region}
                  </Badge>
                )}
                {grant.effect === "deny" && <Badge tone="ok">deny</Badge>}
                {!grant.active && <Badge tone="neutral">inactive</Badge>}
                {cited && <Badge tone="accent">cited by a rule</Badge>}
                <span className="ml-auto font-mono text-[11.5px] text-fg-faint">{grant.grant_id}</span>
              </div>

              <p className="mt-1 truncate font-mono text-[12.5px] text-fg" title={grant.scope_ref}>
                {grant.scope_ref}
              </p>
              <p className="mt-0.5 text-xs text-fg-muted">
                granted via <span className="font-mono text-fg">{grant.granted_via}</span> · principal{" "}
                <span className="font-mono text-fg">{grant.principal_ref}</span> ·{" "}
                {formatMonthLabel(grant.snapshot_month)}
              </p>

              {duplicateOf === undefined ? (
                <CodeBlock
                  className="mt-2"
                  label={`${grant.source_file} ${grant.source_pointer}`}
                  value={snippet}
                  maxHeight="14rem"
                />
              ) : (
                <p className="mt-2 text-xs text-fg-muted">
                  Same provider JSON as <span className="font-mono text-fg">{duplicateOf}</span> above.
                </p>
              )}
            </li>
          );
        })}
      </ul>

      {rest.length > 0 && (
        <details className="rounded-md border border-border bg-surface-muted px-3 py-2">
          <summary className="cursor-pointer text-[13px] font-medium text-fg">
            Show the other {rest.length} {rest.length === 1 ? "grant" : "grants"}
          </summary>
          <ul className="mt-2 flex flex-col gap-1.5">
            {rest.map((grant) => (
              <li key={grant.grant_id} className="flex flex-wrap items-center gap-1.5 text-[13px]">
                <CloudIcon cloud={grant.cloud} size={14} />
                <Badge tone={CONTROL_VERBS.has(grant.verb) ? "danger" : "neutral"}>{grant.verb}</Badge>
                <Badge tone="neutral">{grant.service_category}</Badge>
                <span className="truncate font-mono text-[12px] text-fg" title={grant.scope_ref}>
                  {grant.scope_ref}
                </span>
                <span className="ml-auto font-mono text-[11.5px] text-fg-faint">{grant.grant_id}</span>
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
}
