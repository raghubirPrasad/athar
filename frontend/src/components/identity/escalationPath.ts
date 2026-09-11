import type { PathEdgeOut } from "../../api/types";

/**
 * Nodes of an escalation path, in order: the source of the first edge, then
 * every destination. The chain the UI draws is exactly this list (SPEC §8.1).
 */
export function pathNodes(path: readonly PathEdgeOut[]): string[] {
  const first = path[0];
  if (!first) return [];
  return [first.src, ...path.map((edge) => edge.dst)];
}
