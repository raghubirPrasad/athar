import { cn } from "../../lib/cn";
import { isCloud, MONOGRAM, type Monogram } from "./clouds";

export interface CloudIconProps {
  cloud: string;
  size?: number;
  className?: string;
  /** Render the provider name next to the monogram. */
  withLabel?: boolean;
}

/** Inline SVG monogram; no external assets. Always labelled for screen readers. */
export function CloudIcon({ cloud, size = 18, className, withLabel = false }: CloudIconProps) {
  const key = cloud.toLowerCase();
  const m: Monogram = isCloud(key)
    ? MONOGRAM[key]
    : { label: cloud, text: "?", fill: "var(--border-strong)", fg: "var(--fg)" };
  const fontSize = m.text.length > 2 ? 7.5 : m.text.length === 2 ? 9 : 11;
  return (
    <span className={cn("inline-flex items-center gap-1 align-middle", className)}>
      <svg role="img" aria-label={m.label} width={size} height={size} viewBox="0 0 20 20">
        <title>{m.label}</title>
        <rect width="20" height="20" rx="4" fill={m.fill} />
        <text
          x="10"
          y="10.5"
          textAnchor="middle"
          dominantBaseline="central"
          fontFamily="ui-sans-serif, system-ui, sans-serif"
          fontWeight="700"
          fontSize={fontSize}
          fill={m.fg}
        >
          {m.text}
        </text>
      </svg>
      {withLabel && <span className="text-xs text-fg-muted">{m.label}</span>}
    </span>
  );
}

/** Compact row of provider monograms for table cells. */
export function CloudIcons({ clouds, size = 16 }: { clouds: readonly string[]; size?: number }) {
  if (clouds.length === 0) return <span className="text-fg-faint">—</span>;
  return (
    <span className="inline-flex items-center gap-1">
      {clouds.map((c) => (
        <CloudIcon key={c} cloud={c} size={size} />
      ))}
    </span>
  );
}
