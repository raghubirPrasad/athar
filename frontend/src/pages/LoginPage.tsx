import { useState, type FormEvent } from "react";
import { Navigate, useLocation } from "react-router-dom";
import { DEMO_ACCOUNTS } from "../auth/demoAccounts";
import { redirectTarget } from "../auth/redirect";
import { ROLE_LABEL } from "../auth/roles";
import { useAuth } from "../auth/useAuth";
import { ORG_NAME, TAGLINE } from "../branding";
import { Brandmark } from "../components/Brandmark";
import { Button } from "../components/ui/Button";
import { ErrorState } from "../components/ui/ErrorState";
import { usePageTitle } from "../lib/usePageTitle";

const FIELD =
  "mt-1 w-full rounded-md border border-border bg-surface px-2.5 py-1.5 text-sm text-fg placeholder:text-fg-faint";

/** Sign-in (SPEC §15.1). The API sets an httpOnly cookie; nothing is stored here. */
export function LoginPage() {
  usePageTitle("Sign in");
  const { user, loading, login } = useAuth();
  const location = useLocation();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  if (!loading && user) return <Navigate to={redirectTarget(location.state)} replace />;

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await login(email.trim(), password);
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="relative flex min-h-screen items-center justify-center overflow-hidden bg-bg p-4">
      <div className="brand-rule absolute inset-x-0 top-0 h-[3px]" aria-hidden="true" />
      <div className="w-full max-w-sm">
        <div className="mb-5 flex flex-col items-center text-center">
          <Brandmark size={40} />
          <p className="mt-2.5 text-[24px] font-normal tracking-[0.3em] text-fg">ATHAR</p>
          <p className="mt-1 text-[13px] italic text-fg-muted">{TAGLINE}</p>
        </div>

        <form
          onSubmit={onSubmit}
          className="rounded-md border border-border bg-surface p-5 shadow-card"
          aria-labelledby="signin-heading"
        >
          <h1 id="signin-heading" className="text-sm font-semibold text-fg">
            Sign in
          </h1>

          <label className="mt-3 block text-[13px] font-medium text-fg-muted" htmlFor="email">
            Email
            <input
              id="email"
              name="email"
              type="email"
              autoComplete="username"
              required
              autoFocus
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className={FIELD}
              placeholder="analyst@athar.local"
            />
          </label>

          <label className="mt-3 block text-[13px] font-medium text-fg-muted" htmlFor="password">
            Password
            <input
              id="password"
              name="password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className={FIELD}
            />
          </label>

          {error != null && <ErrorState className="mt-3" error={error} compact />}

          <Button type="submit" variant="primary" className="mt-4 w-full" loading={busy}>
            Sign in
          </Button>
        </form>

        <section className="mt-3 rounded-md border border-dashed border-border-strong bg-surface p-3">
          <h2 className="text-xs font-semibold uppercase tracking-wide text-fg-muted">Demo accounts</h2>
          <ul className="mt-1.5 space-y-1">
            {DEMO_ACCOUNTS.map((account) => (
              <li key={account.email} className="flex flex-col">
                <button
                  type="button"
                  title="Use this email"
                  onClick={() => setEmail(account.email)}
                  className="text-left font-mono text-[12.5px] text-accent-strong hover:underline"
                >
                  {account.email}
                </button>
                <span className="text-xs text-fg-muted">
                  {ROLE_LABEL[account.role]} · {account.blurb}
                </span>
              </li>
            ))}
          </ul>
          <p className="mt-2 text-xs text-fg-faint">
            Passwords come from the deployment&rsquo;s <code>.env</code> and are printed by{" "}
            <code>make demo</code>.
          </p>
        </section>

        <p className="mt-4 text-center text-[11px] uppercase tracking-[0.16em] text-fg-faint">{ORG_NAME}</p>
      </div>
    </main>
  );
}
