import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, type RenderResult } from "@testing-library/react";
import type { ReactElement, ReactNode } from "react";
import { MemoryRouter } from "react-router-dom";
import { AuthContext, type AuthContextValue } from "../auth/context";
import { ToastProvider } from "../components/ui/toast/ToastProvider";
import type { UserOut } from "../api/types";

/** A query client that never retries or caches between tests. */
export function testQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0, staleTime: 0 } },
  });
}

export interface RenderOptions {
  route?: string;
  user?: UserOut | null;
  loading?: boolean;
  client?: QueryClient;
}

/** Render a component with the providers every page assumes. */
export function renderWithProviders(ui: ReactElement, options: RenderOptions = {}): RenderResult {
  const { route = "/", user = null, loading = false, client = testQueryClient() } = options;
  const auth: AuthContextValue = {
    user,
    loading,
    login: () => Promise.reject(new Error("not used in this test")),
    logout: () => Promise.resolve(),
  };
  // ToastProvider is part of the shell every page assumes: mutations push toasts.
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[route]}>
        <AuthContext.Provider value={auth}>
          <ToastProvider>{children}</ToastProvider>
        </AuthContext.Provider>
      </MemoryRouter>
    </QueryClientProvider>
  );
  return render(ui, { wrapper });
}
