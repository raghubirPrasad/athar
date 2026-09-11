/**
 * Roles (SPEC §13): viewer < analyst < approver. The API enforces authorisation;
 * this is only for hiding controls the current user cannot use. The role union
 * itself comes from the generated schema — the order is the local part.
 */
import type { Role } from "../api/types";

export type { Role };

export const ROLES = ["viewer", "analyst", "approver"] as const satisfies readonly Role[];

export function isRole(value: unknown): value is Role {
  return typeof value === "string" && (ROLES as readonly string[]).includes(value);
}

/** Unknown roles rank below viewer so they see nothing that is gated. */
export function roleRank(role: string | null | undefined): number {
  return isRole(role) ? ROLES.indexOf(role) : -1;
}

export function hasRole(user: { role: string } | null | undefined, min: Role): boolean {
  if (!user) return false;
  return roleRank(user.role) >= roleRank(min);
}

export const ROLE_LABEL: Record<Role, string> = {
  viewer: "Viewer",
  analyst: "Analyst",
  approver: "Approver",
};
