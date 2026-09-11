import type { PathEdgeOut } from "../../api/types";
import { EmptyState } from "../ui/EmptyState";
import { pathNodes } from "./escalationPath";

function nodeRole(index: number, count: number): string {
  if (index === 0) return "Identity";
  if (index === count - 1) return "Reaches";
  return "Via";
}

export interface EscalationChainProps {
  paths: readonly (readonly PathEdgeOut[])[];
  /** Cap the number of paths rendered; the rest are summarised. */
  max?: number;
}

/**
 * Self-escalation paths as a horizontal card chain (SPEC §14 — explicitly not a
 * force graph). The chain *is* the evidence for R5: each hop names the verb and,
 * where one exists, the grant row that permits it.
 */
export function EscalationChain({ paths, max = 3 }: EscalationChainProps) {
  const shown = paths.filter((path) => path.length > 0).slice(0, max);

  if (shown.length === 0) {
    return (
      <EmptyState
        compact
        title="No escalation path"
        description="The graph finds no route from this identity to control of another principal within four hops."
      />
    );
  }

  return (
    <div className="flex flex-col gap-4">
      {shown.map((path, pathIndex) => {
        const nodes = pathNodes(path);
        return (
          <div key={`path-${pathIndex}-${nodes.join(">")}`} className="flex flex-col gap-1.5">
            {shown.length > 1 && (
              <p className="text-xs font-semibold uppercase tracking-wide text-fg-muted">Path {pathIndex + 1}</p>
            )}
            <ol className="flex flex-wrap items-stretch gap-1.5" aria-label={`Escalation path ${pathIndex + 1}`}>
              {nodes.map((node, index) => {
                const edge = path[index];
                return (
                  <li key={`${node}-${index}`} className="flex items-stretch gap-1.5">
                    <div className="flex min-w-[9rem] max-w-[16rem] flex-col justify-center rounded-md border border-border bg-surface px-2.5 py-1.5 shadow-card">
                      <span className="text-[10.5px] font-semibold uppercase tracking-wide text-fg-faint">
                        {nodeRole(index, nodes.length)}
                      </span>
                      <span className="truncate font-mono text-[12.5px] text-fg" title={node}>
                        {node}
                      </span>
                    </div>
                    {edge && (
                      <div className="flex flex-col items-center justify-center px-0.5">
                        <span className="rounded border border-accent/30 bg-accent-soft px-1.5 py-px text-[11.5px] font-semibold text-accent-strong">
                          {edge.verb}
                        </span>
                        <span aria-hidden="true" className="text-sm leading-4 text-fg-faint">
                          →
                        </span>
                        {edge.grant_id && (
                          <span className="font-mono text-[10.5px] text-fg-faint" title={`Evidence: ${edge.grant_id}`}>
                            {edge.grant_id}
                          </span>
                        )}
                      </div>
                    )}
                  </li>
                );
              })}
            </ol>
          </div>
        );
      })}
      {paths.length > shown.length && (
        <p className="text-xs text-fg-muted">
          {paths.length - shown.length} further {paths.length - shown.length === 1 ? "path" : "paths"} of equal or
          greater length are not drawn.
        </p>
      )}
    </div>
  );
}
