import type { ReactNode } from "react";
import { Navigate, Outlet, useLocation } from "react-router-dom";
import { Skeleton } from "../components/ui/Skeleton";
import type { RedirectState } from "./redirect";
import { useAuth } from "./useAuth";

/**
 * Gate for authenticated routes. Works both as a wrapper (`children`) and as
 * a layout route (renders <Outlet/> when no children are given).
 */
export function RequireAuth({ children }: { children?: ReactNode }) {
  const { user, loading } = useAuth();
  const location = useLocation();

  if (loading) {
    return (
      <div className="p-6" aria-busy="true" aria-label="Checking session">
        <Skeleton lines={3} />
      </div>
    );
  }
  if (!user) {
    const from = `${location.pathname}${location.search}${location.hash}`;
    return <Navigate to="/login" replace state={{ from } satisfies RedirectState} />;
  }
  return children !== undefined ? <>{children}</> : <Outlet />;
}
