import type { ReactNode } from "react";
import { useAuth } from "./useAuth";
import { hasRole, type Role } from "./roles";

/**
 * Hides children unless the current user has at least `min` role.
 * Visual only — the API enforces RBAC and separation of duties (SPEC §15.1).
 */
export function RoleGate({
  min,
  fallback = null,
  children,
}: {
  min: Role;
  fallback?: ReactNode;
  children: ReactNode;
}) {
  const { user } = useAuth();
  return <>{hasRole(user, min) ? children : fallback}</>;
}
