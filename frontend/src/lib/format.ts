/**
 * Pure formatting helpers. Month arithmetic mirrors backend `athar.clock`:
 * month 1 == 2025-09-01, so formatMonthLabel(1) === "September 2025".
 * Month names are fixed (not Intl) so output is identical across locales.
 */

export const EPOCH_YEAR = 2025;
export const EPOCH_MONTH = 9; // September

const MONTHS_LONG = [
  "January", "February", "March", "April", "May", "June",
  "July", "August", "September", "October", "November", "December",
] as const;
const MONTHS_SHORT = MONTHS_LONG.map((m) => m.slice(0, 3));

export interface YearMonth {
  year: number;
  month: number; // 1..12
}

/** Simulated month index (1-based) → calendar year/month, like athar.clock.month_start. */
export function monthToYearMonth(month: number): YearMonth {
  if (!Number.isInteger(month) || month < 1) throw new RangeError("month must be an integer >= 1");
  const idx = EPOCH_YEAR * 12 + (EPOCH_MONTH - 1) + (month - 1);
  return { year: Math.floor(idx / 12), month: (idx % 12) + 1 };
}

/** "September 2025" for month 1; "August 2026" for month 12. */
export function formatMonthLabel(month: number): string {
  const { year, month: m } = monthToYearMonth(month);
  return `${MONTHS_LONG[m - 1] ?? "?"} ${year}`;
}

/** "Sep 2025" — for dense axes and badges. */
export function formatMonthShort(month: number): string {
  const { year, month: m } = monthToYearMonth(month);
  return `${MONTHS_SHORT[m - 1] ?? "?"} ${year}`;
}

/** Percent value already on a 0–100 scale (e.g. blast_radius_pct) → "12%". */
export function formatPct(value: number | null | undefined, digits = 0): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  return `${value.toFixed(digits)}%`;
}

/** Ratio on 0–1 (precision/recall) → "83.3%". */
export function formatRatioPct(ratio: number | null | undefined, digits = 1): string {
  if (ratio === null || ratio === undefined || Number.isNaN(ratio)) return "—";
  return formatPct(ratio * 100, digits);
}

/** Risk score is an integer 0–100 on the backend; render it as such. */
export function formatScore(score: number | null | undefined): string {
  if (score === null || score === undefined || Number.isNaN(score)) return "—";
  return String(Math.round(score));
}

/** "0xabcdef…123456": keeps `n` hex chars each side, preserves a 0x prefix. */
export function shortHex(hash: string | null | undefined, n = 6): string {
  if (!hash) return "—";
  const prefix = hash.startsWith("0x") ? "0x" : "";
  const body = prefix ? hash.slice(2) : hash;
  if (body.length <= n * 2 + 1) return hash;
  return `${prefix}${body.slice(0, n)}…${body.slice(-n)}`;
}

/** ISO date / datetime string or Date → "14 Sep 2025" (UTC, locale-independent). */
export function formatDate(value: string | Date | null | undefined): string {
  if (!value) return "—";
  const d = typeof value === "string" ? new Date(value) : value;
  if (Number.isNaN(d.getTime())) return "—";
  return `${d.getUTCDate()} ${MONTHS_SHORT[d.getUTCMonth()] ?? "?"} ${d.getUTCFullYear()}`;
}

/**
 * Permission Half-Life (SPEC §9.3): a median in months, or "Never" when fewer
 * than one grant in ten is ever revoked and no median can be taken. One helper
 * so the Overview card, the timeline grid and the half-life table cannot drift
 * apart; `short` is the dense-grid form ("5.0 mo") of the same value.
 */
export function formatHalfLife(months: number | null | undefined, short = false): string {
  if (months === null || months === undefined || Number.isNaN(months)) return "Never";
  return `${months.toFixed(1)} ${short ? "mo" : "months"}`;
}

/** Integer with thousands separators, deterministic across locales. */
export function formatInt(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  return Math.round(value).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}
