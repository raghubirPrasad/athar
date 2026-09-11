import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useMemo, type ReactNode } from "react";
import { isApiError, UNAUTHENTICATED_EVENT } from "../api/client";
import { getMe, login as postLogin, logout as postLogout } from "../api/endpoints";
import { queryKeys } from "../api/queryKeys";
import type { LoginRequest, UserOut } from "../api/types";
import { AuthContext, type AuthContextValue } from "./context";

/**
 * Session state (SPEC §13, §15.1). The JWT lives in an httpOnly cookie owned by
 * the API; the browser never sees it. All we hold is the `UserOut` the API
 * returns from /auth/me, kept in TanStack Query so it is server state like
 * everything else. A 401 anywhere (client.ts dispatches `athar:unauthenticated`)
 * drops the user and every cached query.
 */

async function fetchMe(): Promise<UserOut | null> {
  try {
    return await getMe();
  } catch (err) {
    if (isApiError(err) && err.status === 401) return null;
    throw err;
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const meKey = queryKeys.auth.me();

  const me = useQuery({
    queryKey: meKey,
    queryFn: fetchMe,
    retry: false,
    staleTime: Infinity,
  });

  const dropSession = useCallback(() => {
    // Forget everything the previous session was allowed to see.
    queryClient.removeQueries({ predicate: (q) => q.queryKey[0] !== "auth" });
    queryClient.setQueryData<UserOut | null>(meKey, null);
  }, [queryClient, meKey]);

  useEffect(() => {
    const onUnauthenticated = () => {
      if (queryClient.getQueryData<UserOut | null>(meKey)) dropSession();
    };
    window.addEventListener(UNAUTHENTICATED_EVENT, onUnauthenticated);
    return () => window.removeEventListener(UNAUTHENTICATED_EVENT, onUnauthenticated);
  }, [queryClient, meKey, dropSession]);

  const loginMutation = useMutation({
    mutationFn: (body: LoginRequest) => postLogin(body),
    onSuccess: (user) => queryClient.setQueryData<UserOut | null>(meKey, user),
  });

  const logoutMutation = useMutation({
    mutationFn: () => postLogout(),
    onSettled: dropSession,
  });

  const { mutateAsync: loginAsync } = loginMutation;
  const { mutateAsync: logoutAsync } = logoutMutation;

  const value = useMemo<AuthContextValue>(
    () => ({
      user: me.data ?? null,
      loading: me.isPending,
      login: (email, password) => loginAsync({ email, password }),
      logout: async () => {
        await logoutAsync();
      },
    }),
    [me.data, me.isPending, loginAsync, logoutAsync],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
