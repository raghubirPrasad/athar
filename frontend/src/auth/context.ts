import { createContext } from "react";
import type { UserOut } from "../api/types";

/**
 * Session context (SPEC §13, §15.1). Lives apart from the provider component so
 * neither file mixes a component export with a value export (react-refresh).
 */
export interface AuthContextValue {
  user: UserOut | null;
  /** True only during the initial /auth/me bootstrap. */
  loading: boolean;
  login: (email: string, password: string) => Promise<UserOut>;
  logout: () => Promise<void>;
}

export const AuthContext = createContext<AuthContextValue | null>(null);
