import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState, type FormEvent } from "react";
import { updateSettings } from "../../api/endpoints";
import { queryKeys } from "../../api/queryKeys";
import type { SettingsOut, SettingsUpdate } from "../../api/types";
import { hasRole } from "../../auth/roles";
import { useAuth } from "../../auth/useAuth";
import { Button } from "../ui/Button";
import { Card, CardSection } from "../ui/Card";
import { ErrorState } from "../ui/ErrorState";
import { useToast } from "../ui/toast/useToast";

interface FormState {
  dormantDays: string;
  staleKeyDays: string;
  regions: string;
  autoRemediate: boolean;
}

function toForm(settings: SettingsOut): FormState {
  return {
    dormantDays: String(settings.dormant_days),
    staleKeyDays: String(settings.stale_key_days),
    regions: settings.approved_regions.join(", "),
    autoRemediate: settings.auto_remediate_departed,
  };
}

function parseRegions(value: string): string[] {
  return value
    .split(",")
    .map((region) => region.trim())
    .filter((region) => region.length > 0);
}

const NUMBER_FIELD =
  "mt-1 w-32 rounded-md border border-border bg-surface px-2.5 py-1.5 text-sm text-fg disabled:opacity-60";
const TEXT_FIELD =
  "mt-1 w-full rounded-md border border-border bg-surface px-2.5 py-1.5 text-sm text-fg disabled:opacity-60";

/**
 * Detection thresholds, approved regions and the auto-remediation switch
 * (SPEC §14 settings, §7). Thresholds are runtime config: changing them
 * re-scores without a new ingest. Only an approver may touch
 * `auto_remediate_departed` — the API enforces that (SPEC §15.1) and the form
 * only sends the field when it actually changed.
 */
export function SettingsForm({ settings }: { settings: SettingsOut }) {
  const queryClient = useQueryClient();
  const toast = useToast();
  const { user } = useAuth();
  const canEdit = hasRole(user, "analyst");
  const canToggleAuto = hasRole(user, "approver");

  const [form, setForm] = useState<FormState>(() => toForm(settings));
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    setForm(toForm(settings));
  }, [settings]);

  const save = useMutation<SettingsOut, unknown, SettingsUpdate>({
    mutationFn: (body: SettingsUpdate) => updateSettings(body),
    onSuccess: (updated) => {
      setError(null);
      queryClient.setQueryData(queryKeys.settings.current(), updated);
      for (const key of ["estate", "identities", "findings", "departments", "scans"]) {
        void queryClient.invalidateQueries({ queryKey: [key] });
      }
      toast.push({
        tone: "success",
        title: "Settings saved",
        detail: `Dormant ${updated.dormant_days} days · stale keys ${updated.stale_key_days} days · ${updated.approved_regions.length} approved regions.`,
      });
    },
    onError: (err) => setError(err),
  });

  function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);

    const body: SettingsUpdate = {};
    const dormant = Number(form.dormantDays);
    const stale = Number(form.staleKeyDays);
    if (Number.isFinite(dormant) && dormant !== settings.dormant_days) body.dormant_days = Math.floor(dormant);
    if (Number.isFinite(stale) && stale !== settings.stale_key_days) body.stale_key_days = Math.floor(stale);

    const regions = parseRegions(form.regions);
    if (regions.join(",") !== settings.approved_regions.join(",")) body.approved_regions = regions;

    // Only an approver may send this field, so only send it when it changed.
    if (form.autoRemediate !== settings.auto_remediate_departed) body.auto_remediate_departed = form.autoRemediate;

    if (Object.keys(body).length === 0) {
      toast.push({ tone: "info", title: "Nothing to save", detail: "No setting on this form has changed." });
      return;
    }
    save.mutate(body);
  }

  return (
    <form onSubmit={onSubmit}>
      <Card
        flush
        title="Detection settings"
        subtitle="Runtime configuration — changing a threshold re-scores in memory, without a new ingest"
        actions={
          <Button type="submit" variant="primary" size="sm" loading={save.isPending} disabled={!canEdit}>
            Save settings
          </Button>
        }
      >
        {!canEdit && (
          <CardSection>
            <p className="text-[13px] text-fg-muted">
              You are signed in as a viewer. Settings are read-only for this role; sign in as an analyst to change a
              threshold, or as an approver to change auto-remediation.
            </p>
          </CardSection>
        )}

        <CardSection title="Thresholds">
          <div className="flex flex-wrap gap-6">
            <label className="block text-[13px] font-medium text-fg-muted" htmlFor="dormant-days">
              Dormant after (days)
              <input
                id="dormant-days"
                type="number"
                min={1}
                max={3650}
                inputMode="numeric"
                disabled={!canEdit}
                value={form.dormantDays}
                onChange={(event) => setForm((current) => ({ ...current, dormantDays: event.target.value }))}
                className={NUMBER_FIELD}
              />
              <span className="mt-1 block text-xs font-normal text-fg-faint">
                R2 fires when nothing has been used for this long (default 90).
              </span>
            </label>

            <label className="block text-[13px] font-medium text-fg-muted" htmlFor="stale-key-days">
              Stale credential after (days)
              <input
                id="stale-key-days"
                type="number"
                min={1}
                max={3650}
                inputMode="numeric"
                disabled={!canEdit}
                value={form.staleKeyDays}
                onChange={(event) => setForm((current) => ({ ...current, staleKeyDays: event.target.value }))}
                className={NUMBER_FIELD}
              />
              <span className="mt-1 block text-xs font-normal text-fg-faint">
                R6 fires for an active credential older than this (default 180).
              </span>
            </label>
          </div>
        </CardSection>

        <CardSection title="Approved regions">
          <label className="block text-[13px] font-medium text-fg-muted" htmlFor="approved-regions">
            Comma-separated region identifiers
            <input
              id="approved-regions"
              type="text"
              disabled={!canEdit}
              value={form.regions}
              onChange={(event) => setForm((current) => ({ ...current, regions: event.target.value }))}
              className={TEXT_FIELD}
              placeholder="me-central-1, uaenorth, uaecentral, me-central1"
            />
            <span className="mt-1 block text-xs font-normal text-fg-faint">
              R8 (data-residency drift) fires for a high-sensitivity resource outside this list.
            </span>
          </label>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {parseRegions(form.regions).map((region) => (
              <span
                key={region}
                className="rounded border border-border bg-surface-muted px-1.5 py-px font-mono text-xs text-fg"
              >
                {region}
              </span>
            ))}
          </div>
        </CardSection>

        <CardSection title="Auto-remediation">
          <label className="flex items-start gap-2 text-[13px] text-fg" htmlFor="auto-remediate">
            <input
              id="auto-remediate"
              type="checkbox"
              disabled={!canToggleAuto}
              checked={form.autoRemediate}
              onChange={(event) => setForm((current) => ({ ...current, autoRemediate: event.target.checked }))}
              className="mt-0.5 h-4 w-4 accent-[var(--accent)]"
            />
            <span>
              <span className="font-medium">Disable departed human identities automatically</span>
              <span className="mt-0.5 block text-xs text-fg-muted">
                Only R3 findings on humans departed for 30 days or more, with no unexpired entry in the exception
                register. Always logged, always on chain, always reversible by granting an exception.
                {!canToggleAuto && " Only an approver may change this."}
              </span>
            </span>
          </label>
        </CardSection>

        {error != null && (
          <CardSection>
            <ErrorState compact error={error} />
          </CardSection>
        )}
      </Card>
    </form>
  );
}
