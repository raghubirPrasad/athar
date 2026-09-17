import { useEffect, useRef, useState } from "react";
import { useAuth } from "../../auth/useAuth";
import { ROLE_LABEL, isRole } from "../../auth/roles";
import { cn } from "../../lib/cn";
import { Badge } from "../ui/Badge";
import { Button } from "../ui/Button";
import { IconChevron, IconLogout } from "../icons";

/** Signed-in user: email, role chip and sign out. RBAC itself is server-side. */
export function UserMenu() {
  const { user, logout } = useAuth();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const wrapRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onPointerDown = (event: PointerEvent) => {
      if (!wrapRef.current?.contains(event.target as Node)) setOpen(false);
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [open]);

  if (!user) return null;
  const roleLabel = isRole(user.role) ? ROLE_LABEL[user.role] : user.role;

  return (
    <div ref={wrapRef} className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        aria-haspopup="menu"
        className={cn(
          "inline-flex items-center gap-2 rounded-md border border-chrome-border px-2 py-1 text-[13px] text-chrome-fg-muted transition-colors hover:bg-chrome-2",
          open && "bg-chrome-2",
        )}
      >
        <span className="hidden max-w-[16ch] truncate text-chrome-fg sm:inline">{user.email}</span>
        <Badge tone="accent">{roleLabel}</Badge>
        <IconChevron size={14} />
      </button>
      {open && (
        <div
          role="menu"
          className="absolute right-0 z-30 mt-1 w-64 rounded-lg border border-border bg-surface p-3 shadow-card"
        >
          <p className="truncate text-[13px] font-semibold text-fg" title={user.email}>
            {user.email}
          </p>
          <p className="mt-0.5 text-xs text-fg-muted">
            Role {roleLabel} · session in an httpOnly cookie
          </p>
          <Button
            className="mt-3 w-full"
            variant="secondary"
            size="sm"
            loading={busy}
            iconStart={<IconLogout size={14} />}
            onClick={() => {
              setBusy(true);
              void logout().finally(() => {
                setBusy(false);
                setOpen(false);
              });
            }}
          >
            Sign out
          </Button>
        </div>
      )}
    </div>
  );
}
