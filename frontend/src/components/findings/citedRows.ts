import type { EvidenceRefOut, GrantOut } from "../../api/types";
import { prettyJson } from "../../lib/download";

export interface CitedRowGroup {
  /** The row shown for this group — the first one cited with this snippet. */
  ref: EvidenceRefOut;
  /** The canonical grant behind it, when the page holds one for this ref. */
  grant?: GrantOut;
  /** The provider JSON, pretty-printed; null when the row carries none. */
  snippet: string | null;
  /** Ids of the other cited rows whose provider JSON is byte-identical. */
  duplicates: string[];
}

/**
 * Cited rows folded by the provider JSON behind them. A rule that cites a
 * wildcard statement attached to two hundred resources cites the same snippet
 * two hundred times; printing it two hundred times is not more evidence, it is
 * the same evidence at length. The duplicate ids are kept so nothing the rule
 * cited disappears (CLAUDE.md: evidence or it did not fire).
 */
export function groupCitedRows(
  refs: readonly EvidenceRefOut[],
  grantsById?: ReadonlyMap<string, GrantOut>,
): CitedRowGroup[] {
  const groups = new Map<string, CitedRowGroup>();
  refs.forEach((ref, index) => {
    const grant = ref.kind === "grant" ? grantsById?.get(ref.ref) : undefined;
    const snippet = grant && grant.raw_snippet != null ? prettyJson(grant.raw_snippet) : null;
    // Rows with no snippet cannot be compared, so each keeps its own group.
    const key = snippet === null ? `${ref.kind}:${ref.ref}:${index}` : `snippet:${snippet}`;
    const existing = groups.get(key);
    if (existing) existing.duplicates.push(ref.ref);
    else groups.set(key, { ref, grant, snippet, duplicates: [] });
  });
  return [...groups.values()];
}
