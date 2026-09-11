import { QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider } from "./auth/AuthProvider";
import { RequireAuth } from "./auth/RequireAuth";
import { AppShell } from "./components/layout/AppShell";
import { ToastProvider } from "./components/ui/toast/ToastProvider";
import { EvaluationPage } from "./pages/EvaluationPage";
import { FindingsPage } from "./pages/FindingsPage";
import { IdentitiesPage } from "./pages/IdentitiesPage";
import { IdentityDetailPage } from "./pages/IdentityDetailPage";
import { LedgerPage } from "./pages/LedgerPage";
import { LoginPage } from "./pages/LoginPage";
import { NotFoundPage } from "./pages/NotFoundPage";
import { OverviewPage } from "./pages/OverviewPage";
import { RemediationPage } from "./pages/RemediationPage";
import { SettingsPage } from "./pages/SettingsPage";
import { TimelinePage } from "./pages/TimelinePage";
import { createQueryClient } from "./queryClient";

const queryClient = createQueryClient();

/** Routes are SPEC §14 exactly; every one but /login sits behind RequireAuth. */
export function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route element={<RequireAuth />}>
        <Route element={<AppShell />}>
          <Route index element={<OverviewPage />} />
          <Route path="identities" element={<IdentitiesPage />} />
          <Route path="identities/:identityId" element={<IdentityDetailPage />} />
          <Route path="findings" element={<FindingsPage />} />
          <Route path="remediation" element={<RemediationPage />} />
          <Route path="ledger" element={<LedgerPage />} />
          <Route path="timeline" element={<TimelinePage />} />
          <Route path="evaluation" element={<EvaluationPage />} />
          <Route path="settings" element={<SettingsPage />} />
          <Route path="404" element={<NotFoundPage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Route>
      <Route path="*" element={<Navigate to="/404" replace />} />
    </Routes>
  );
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AuthProvider>
          <ToastProvider>
            <AppRoutes />
          </ToastProvider>
        </AuthProvider>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
