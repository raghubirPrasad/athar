import { useQuery } from "@tanstack/react-query";
import { getEval } from "../api/endpoints";
import { queryKeys } from "../api/queryKeys";
import type { EvalOut } from "../api/types";
import { DecoyTable } from "../components/evaluation/DecoyTable";
import { RegisterCards } from "../components/evaluation/RegisterCards";
import { RuleConfusionTable } from "../components/evaluation/RuleConfusionTable";
import { Badge } from "../components/ui/Badge";
import { Card } from "../components/ui/Card";
import { ErrorState } from "../components/ui/ErrorState";
import { PageHeader } from "../components/ui/PageHeader";
import { Skeleton, SkeletonTiles } from "../components/ui/Skeleton";
import { StatTile } from "../components/ui/StatTile";
import { formatInt, formatRatioPct } from "../lib/format";

/**
 * Which estate produced these numbers, said in the vocabulary of SPEC §17. The
 * report also carries `generated_from`, which is a path on the API host: a
 * server's filesystem layout is not something a browser client should print
 * (CLAUDE.md: never return an internal path to an API client).
 */
function provenanceLabel(result: Pick<EvalOut, "seed" | "held_out">): string {
  return `${result.held_out ? "held-out" : "tuning"} seed ${result.seed}`;
}

/**
 * Evaluation (SPEC §14, §17). Measured against the generator's own ground truth
 * on a held-out seed: the scoring constants were tuned on seed 42 and never saw
 * this estate, which is the difference between an evaluation and a demo.
 */
export function EvaluationPage() {
  const evaluation = useQuery({ queryKey: queryKeys.eval.report(), queryFn: getEval });
  const result = evaluation.data;

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Evaluation"
        description="Precision, recall and F1 at High and above, against the ground truth the generator wrote — including decoys designed to fool a naïve detector."
        meta={
          result && (
            <>
              <Badge tone={result.held_out ? "ok" : "warn"}>
                <span aria-hidden="true">{result.held_out ? "✓" : "!"}</span>
                {result.held_out ? `Held-out seed ${result.seed}` : `Tuning seed ${result.seed}`}
              </Badge>
              <Badge tone="neutral">Threshold: {result.threshold}</Badge>
              <Badge tone="neutral" title="Where these numbers came from">
                Source: {provenanceLabel(result)}
              </Badge>
            </>
          )
        }
      />

      {evaluation.isError && <ErrorState error={evaluation.error} onRetry={() => void evaluation.refetch()} />}
      {evaluation.isPending && (
        <>
          <SkeletonTiles />
          <Skeleton lines={6} />
        </>
      )}

      {result && !result.computed && (
        <div className="rounded-lg border border-warn/40 bg-warn-soft px-4 py-3 text-[13px] leading-6 text-fg">
          <p className="font-semibold">No evaluation has been run on this deployment.</p>
          <p className="mt-1">
            Precision, recall and the decoy table are measured by a separate harness against the generator&rsquo;s own
            ground truth, on held-out seed {result.seed} &mdash; an estate the scoring constants never saw. Nothing
            has measured it here yet, so there are no numbers to show. Showing zeros would read as an engine that
            scored nothing, which is a different claim entirely.
          </p>
          <p className="mt-2">
            Run <code className="rounded bg-surface-2 px-1 py-0.5 font-mono text-[12px]">make eval</code> and reload.
          </p>
        </div>
      )}

      {result && result.computed && (
        <>
          <p
            className={
              result.held_out
                ? "rounded-lg border border-ok/40 bg-ok-soft px-3 py-2 text-[13px] leading-6 text-fg"
                : "rounded-lg border border-warn/40 bg-warn-soft px-3 py-2 text-[13px] leading-6 text-fg"
            }
          >
            {result.held_out ? (
              <>
                These numbers come from <span className="font-semibold">held-out seed {result.seed}</span>. The scoring
                constants were tuned on the tuning seed and never saw this estate, so this is a measurement rather than
                a rehearsal.
              </>
            ) : (
              <>
                These numbers come from <span className="font-semibold">seed {result.seed}</span>, the same estate the
                scoring constants were tuned on. Read them as a sanity check, not as held-out accuracy.
              </>
            )}
          </p>

          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <StatTile
              label="Precision"
              value={formatRatioPct(result.precision)}
              hint={`${formatInt(result.tp)} of ${formatInt(result.tp + result.fp)} flagged are genuine`}
              to="/findings?severity=High"
            />
            <StatTile
              label="Recall"
              value={formatRatioPct(result.recall)}
              hint={`${formatInt(result.fn)} ground-truth positives missed`}
              to="/findings?severity=Critical"
            />
            <StatTile label="F1" value={formatRatioPct(result.f1)} hint="Harmonic mean at High+" to="/findings" />
            <StatTile
              label="Decoys handled"
              value={`${formatInt(result.decoys.filter((d) => d.correctly_handled).length)} / ${formatInt(result.decoys.length)}`}
              hint="Legitimate-but-risky-looking identities kept at or below Medium"
              onClick={() => document.getElementById("decoys")?.scrollIntoView?.({ behavior: "smooth" })}
            />
          </div>

          <RegisterCards result={result} />

          <Card title="Per-rule confusion" subtitle="Where the engine is precise and where it over-fires" flush>
            <div className="p-3">
              <RuleConfusionTable rows={result.per_rule} />
            </div>
          </Card>

          <Card
            id="decoys"
            title="Decoys"
            subtitle="Seeded to look risky; legitimacy recorded in the governance register, never in a cloud tag"
            flush
          >
            <div className="p-3">
              <DecoyTable decoys={result.decoys} />
            </div>
          </Card>
        </>
      )}
    </div>
  );
}
