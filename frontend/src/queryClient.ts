import { QueryClient } from "@tanstack/react-query";

/**
 * Server state is TanStack Query's; nothing is duplicated into component state.
 * A scan takes seconds, so a 30 s stale time keeps the demo snappy without
 * showing a month-old estate; window focus never refetches during a pitch.
 */
export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 30_000,
        retry: 1,
        refetchOnWindowFocus: false,
      },
      mutations: { retry: 0 },
    },
  });
}
