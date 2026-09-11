import { useCallback, useEffect, useState } from "react";
import { formatMonthLabel } from "../../lib/format";
import { Button } from "../ui/Button";

export interface MonthSliderProps {
  min: number;
  max: number;
  value: number;
  onChange: (month: number) => void;
  /** Milliseconds per step while playing. */
  intervalMs?: number;
}

/**
 * Month slider with a Play control (SPEC §14 timeline). This is the "watch it
 * drift" beat of the demo (PRD §9): the estate was not authored over-privileged,
 * it became that way month by month.
 */
export function MonthSlider({ min, max, value, onChange, intervalMs = 900 }: MonthSliderProps) {
  const [playing, setPlaying] = useState(false);

  useEffect(() => {
    if (!playing) return undefined;
    if (value >= max) {
      setPlaying(false);
      return undefined;
    }
    const id = window.setTimeout(() => onChange(value + 1), intervalMs);
    return () => window.clearTimeout(id);
  }, [playing, value, max, intervalMs, onChange]);

  const togglePlay = useCallback(() => {
    if (playing) {
      setPlaying(false);
      return;
    }
    if (value >= max) onChange(min);
    setPlaying(true);
  }, [playing, value, max, min, onChange]);

  return (
    <div className="flex flex-wrap items-center gap-3 rounded-lg border border-border bg-surface px-3 py-2">
      <Button
        variant="primary"
        size="sm"
        onClick={togglePlay}
        aria-pressed={playing}
        iconStart={<span aria-hidden="true">{playing ? "❙❙" : "▶"}</span>}
      >
        {playing ? "Pause" : "Play"}
      </Button>

      <label className="flex flex-1 items-center gap-2 text-xs text-fg-muted" htmlFor="timeline-month">
        <span className="whitespace-nowrap">Month</span>
        <input
          id="timeline-month"
          type="range"
          min={min}
          max={max}
          step={1}
          value={value}
          onChange={(event) => {
            setPlaying(false);
            onChange(Number(event.target.value));
          }}
          className="h-1.5 min-w-[12rem] flex-1 accent-[var(--accent)]"
          aria-valuetext={formatMonthLabel(value)}
        />
      </label>

      <output
        htmlFor="timeline-month"
        aria-live="polite"
        aria-label="Selected month"
        className="tabular min-w-[11rem] text-right text-[13px] font-semibold text-fg"
      >
        {formatMonthLabel(value)} <span className="font-normal text-fg-muted">· month {value}</span>
      </output>
    </div>
  );
}
