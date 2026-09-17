import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Outlet, useLocation } from "react-router-dom";
import { getEstateSummary } from "../../api/endpoints";
import { queryKeys } from "../../api/queryKeys";
import { SideNav } from "./SideNav";
import { TopBar } from "./TopBar";

/**
 * Authenticated layout: a left rail (icons only between 768 px and 1024 px, a
 * drawer below that) and a top bar carrying the month and ledger badges. The
 * estate summary is fetched once here and shared with the Overview page through
 * the query cache.
 */
export function AppShell() {
  const [navOpen, setNavOpen] = useState(false);
  const location = useLocation();

  const summary = useQuery({
    queryKey: queryKeys.estate.summary(),
    queryFn: getEstateSummary,
  });

  useEffect(() => setNavOpen(false), [location.pathname]);

  return (
    <div className="min-h-screen bg-bg text-fg">
      <div className="brand-rule h-[3px] w-full" aria-hidden="true" />
      <TopBar summary={summary.data} onOpenNav={() => setNavOpen(true)} />

      <div className="flex">
        <aside className="chrome sticky top-14 hidden h-[calc(100vh-3.5rem)] shrink-0 border-r border-chrome-border md:block md:w-14 lg:w-56">
          <SideNav />
        </aside>

        {navOpen && (
          <div className="fixed inset-0 z-30 md:hidden">
            <div
              aria-hidden="true"
              className="absolute inset-0 bg-[rgb(16_24_40/0.45)]"
              onClick={() => setNavOpen(false)}
            />
            <div className="chrome relative h-full w-60 border-r border-chrome-border shadow-card">
              <div className="flex items-center justify-between border-b border-chrome-border px-3 py-2">
                <span className="text-xs font-semibold uppercase tracking-wide text-chrome-fg-muted">Sections</span>
                <button
                  type="button"
                  onClick={() => setNavOpen(false)}
                  aria-label="Close navigation"
                  className="rounded px-1.5 text-chrome-fg-muted hover:text-chrome-fg"
                >
                  ✕
                </button>
              </div>
              <SideNav expanded onNavigate={() => setNavOpen(false)} />
            </div>
          </div>
        )}

        <main className="min-w-0 flex-1 px-4 py-4 lg:px-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
