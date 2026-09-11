/**
 * Readers for the evidence altitude's free-form payload (`AltitudesOut.evidence`
 * is `{[key: string]: unknown}` in the OpenAPI schema, SPEC §10.2). Everything
 * is narrowed here so no page has to reach into an untyped object.
 */

export interface EvidenceLedgerRef {
  leaf: string | null;
  scanId: number | null;
  merkleRoot: string | null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function str(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function num(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

export function evidenceRecord(evidence: unknown): Record<string, unknown> {
  return isRecord(evidence) ? evidence : {};
}

/** The rule ids the engine says fired for this finding. */
export function rulesFired(evidence: unknown): string[] {
  const raw = evidenceRecord(evidence).rules_fired;
  if (!Array.isArray(raw)) return [];
  return raw.filter((r): r is string => typeof r === "string");
}

/** Ledger leaf and root for this finding instance (SPEC §12.3). */
export function ledgerRef(evidence: unknown): EvidenceLedgerRef | null {
  const raw = evidenceRecord(evidence).ledger;
  if (!isRecord(raw)) return null;
  return { leaf: str(raw.leaf), scanId: num(raw.scan_id), merkleRoot: str(raw.merkle_root) };
}

/** The canonical facts the rule engine used — displayed verbatim as JSON. */
export function evidenceFacts(evidence: unknown): Record<string, unknown> | null {
  const raw = evidenceRecord(evidence).facts;
  return isRecord(raw) ? raw : null;
}

/**
 * The committed instance (SPEC §10.1) — the exact object whose canonical JSON is
 * hashed into the Merkle leaf, so an auditor can recompute it.
 */
export function instanceObject(evidence: unknown): Record<string, unknown> | null {
  const facts = evidenceFacts(evidence);
  const raw = facts?.instance;
  return isRecord(raw) ? raw : null;
}
