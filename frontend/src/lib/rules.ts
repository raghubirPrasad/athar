/**
 * The detection catalogue (SPEC §7) as the API serves it. `GET /rules` is the
 * only place rule ids and names come from: a table maintained here drifts from
 * the engine the first time a rule is added or renamed, and it silently omits
 * ids the engine does emit — `R0`, the unmapped-permission rule, was missing
 * from every filter for exactly that reason.
 */
import { useQuery } from "@tanstack/react-query";
import { listRules } from "../api/endpoints";
import { queryKeys } from "../api/queryKeys";
import type { RuleOut } from "../api/types";

/** Rule metadata is static for the life of a ruleset, so it is fetched once. */
export function useRules(): readonly RuleOut[] {
  const rules = useQuery({
    queryKey: queryKeys.rules.catalogue(),
    queryFn: listRules,
    staleTime: Infinity,
  });
  return rules.data ?? [];
}

/** `{ value: "R3", label: "R3 · Orphaned identity" }` for a filter dropdown. */
export function ruleOptions(rules: readonly RuleOut[]): { value: string; label: string }[] {
  return rules.map((rule) => ({ value: rule.rule_id, label: ruleLabel(rule.rule_id, rule.name) }));
}

/** The name the catalogue gives a rule, or null while it is still loading. */
export function ruleName(rules: readonly RuleOut[], ruleId: string | null | undefined): string | null {
  if (!ruleId) return null;
  return rules.find((rule) => rule.rule_id === ruleId)?.name ?? null;
}

/**
 * "R3 · Orphaned identity". Rows carry their own `rule_name`; anything else
 * falls back to the bare id rather than to a name this file invented.
 */
export function ruleLabel(ruleId: string | null | undefined, name?: string | null): string {
  if (!ruleId) return "—";
  return name ? `${ruleId} · ${name}` : ruleId;
}
