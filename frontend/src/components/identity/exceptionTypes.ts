/** Exception types in the governance register (SPEC §4.3), in readable English. */
export const EXCEPTION_TYPE_LABEL: Record<string, string> = {
  "break-glass": "Break-glass",
  "dr-failover": "DR failover",
  "approved-privileged-role": "Approved privileged role",
  "time-boxed": "Time-boxed",
};

export function exceptionTypeLabel(type: string): string {
  return EXCEPTION_TYPE_LABEL[type] ?? type;
}
