import { useQuery } from "@tanstack/react-query";
import { getSettings } from "../api/endpoints";
import { queryKeys } from "../api/queryKeys";
import { SettingsForm } from "../components/settings/SettingsForm";
import { Badge } from "../components/ui/Badge";
import { Card } from "../components/ui/Card";
import { ErrorState } from "../components/ui/ErrorState";
import { PageHeader } from "../components/ui/PageHeader";
import { Skeleton } from "../components/ui/Skeleton";
import { formatDate, formatInt } from "../lib/format";

const PROVIDER_LABEL: Record<string, string> = {
  gemini: "Gemini (hosted)",
  ollama: "Ollama (local)",
  none: "Templates only",
};

/**
 * Settings (SPEC §14): the thresholds the rules read, the approved regions the
 * residency rule reads, the auto-remediation switch only an approver may move,
 * and which model — if any — is writing the prose.
 */
export function SettingsPage() {
  const settings = useQuery({ queryKey: queryKeys.settings.current(), queryFn: getSettings });
  const data = settings.data;
  const llm = data?.llm;

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Settings"
        description="Detection thresholds, approved regions and the auto-remediation switch. Everything here is runtime configuration; nothing is hard-coded in a rule."
        meta={
          data && (
            <span className="text-xs text-fg-muted">
              {data.updated_by
                ? `Last changed by ${data.updated_by}${data.updated_at ? ` on ${formatDate(data.updated_at)}` : ""}`
                : "Never changed since this deployment started"}
            </span>
          )
        }
      />

      {settings.isError && <ErrorState error={settings.error} onRetry={() => void settings.refetch()} />}
      {settings.isPending && <Skeleton lines={8} height="h-6" />}

      {data && <SettingsForm settings={data} />}

      {llm && (
        <Card
          title="Language model"
          subtitle="Explanations and rationales only — the rule engine decides every finding, severity and score"
          actions={
            <Badge tone={llm.reachable === false ? "danger" : llm.reachable ? "ok" : "neutral"}>
              <span aria-hidden="true">{llm.reachable === false ? "✕" : llm.reachable ? "✓" : "?"}</span>
              {llm.reachable === false ? "Unreachable" : llm.reachable ? "Reachable" : "Not probed"}
            </Badge>
          }
        >
          <dl className="grid gap-2 text-[13px] sm:grid-cols-[10rem_minmax(0,1fr)]">
            <dt className="text-fg-muted">Provider</dt>
            <dd className="text-fg">{PROVIDER_LABEL[llm.provider] ?? llm.provider}</dd>
            <dt className="text-fg-muted">Model</dt>
            <dd className="font-mono text-fg">{llm.model || "—"}</dd>
            <dt className="text-fg-muted">Cached responses</dt>
            <dd className="tabular text-fg">{formatInt(llm.cache_entries)}</dd>
          </dl>
          <p className="mt-2 text-xs text-fg-muted">
            The demo runs warm: cached agent output renders instantly and only an explicit Regenerate calls the
            provider, so nothing on stage depends on a network hop.
          </p>
        </Card>
      )}
    </div>
  );
}
