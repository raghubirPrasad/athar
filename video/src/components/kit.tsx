import React from "react";
import {
  AbsoluteFill,
  Img,
  interpolate,
  spring,
  staticFile,
  useCurrentFrame,
  useVideoConfig,
} from "remotion";
import { C, MONO, SANS } from "../theme";

/* ---------- motion helpers ---------- */

/** Spring 0→1 that starts at frame `delay`. */
export function useReveal(delay = 0, damping = 200) {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  return spring({ frame: frame - delay, fps, config: { damping }, durationInFrames: 26 });
}

/** Rise + fade in. */
export const Rise: React.FC<{
  delay?: number;
  y?: number;
  children: React.ReactNode;
  style?: React.CSSProperties;
}> = ({ delay = 0, y = 26, children, style }) => {
  const p = useReveal(delay);
  return (
    <div style={{ opacity: p, transform: `translateY(${(1 - p) * y}px)`, ...style }}>{children}</div>
  );
}

/* ---------- backdrop ---------- */

export const Bg: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const frame = useCurrentFrame();
  const drift = Math.sin(frame / 90) * 20;
  return (
    <AbsoluteFill
      style={{
        fontFamily: SANS,
        color: C.fg,
        background: `radial-gradient(1400px 700px at ${78 + drift / 10}% -8%, rgba(39,198,223,.10), transparent 60%),
                     radial-gradient(1100px 700px at -6% 112%, rgba(11,124,147,.16), transparent 55%),
                     ${C.bg}`,
      }}
    >
      {/* top electric rule */}
      <div
        style={{
          position: "absolute",
          top: 0,
          left: 0,
          right: 0,
          height: 5,
          background: `linear-gradient(90deg, ${C.cyanDeep}, #1596b0 45%, ${C.cyan})`,
        }}
      />
      {/* faint grid texture */}
      <AbsoluteFill
        style={{
          backgroundImage:
            "linear-gradient(rgba(255,255,255,.022) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.022) 1px,transparent 1px)",
          backgroundSize: "64px 64px",
          maskImage: "radial-gradient(circle at 50% 40%, black, transparent 85%)",
        }}
      />
      <AbsoluteFill style={{ padding: "96px 120px" }}>{children}</AbsoluteFill>
    </AbsoluteFill>
  );
}

/* ---------- text bits ---------- */

export const Kicker: React.FC<{ children: React.ReactNode; delay?: number }> = ({ children, delay = 0 }) => (
  <Rise delay={delay}>
    <div
      style={{
        font: `600 20px/1 ${MONO}`,
        letterSpacing: "0.3em",
        textTransform: "uppercase",
        color: C.cyan,
        marginBottom: 24,
      }}
    >
      {children}
    </div>
  </Rise>
);

export const Title: React.FC<{ children: React.ReactNode; delay?: number; size?: number }> = ({
  children,
  delay = 4,
  size = 68,
}) => (
  <Rise delay={delay}>
    <div style={{ fontSize: size, fontWeight: 700, letterSpacing: "-0.02em", lineHeight: 1.04 }}>
      {children}
    </div>
  </Rise>
);

export const Sub: React.FC<{ children: React.ReactNode; delay?: number; style?: React.CSSProperties }> = ({
  children,
  delay = 10,
  style,
}) => (
  <Rise delay={delay}>
    <div style={{ fontSize: 28, color: C.muted, lineHeight: 1.45, maxWidth: 1180, ...style }}>
      {children}
    </div>
  </Rise>
);

/* ---------- panels & data ---------- */

export const Panel: React.FC<{
  children: React.ReactNode;
  style?: React.CSSProperties;
  accent?: string;
  delay?: number;
}> = ({ children, style, accent, delay = 0 }) => {
  const p = useReveal(delay);
  return (
    <div
      style={{
        background: `linear-gradient(180deg, ${C.panel}, ${C.panel2})`,
        border: `1px solid ${accent ? accent : C.border}`,
        borderRadius: 16,
        padding: 30,
        opacity: p,
        transform: `translateY(${(1 - p) * 20}px)`,
        boxShadow: "0 20px 50px rgba(0,0,0,.35)",
        ...style,
      }}
    >
      <div style={{ height: 3, width: 44, background: accent ?? C.cyan, borderRadius: 3, marginBottom: 18 }} />
      {children}
    </div>
  );
}

export const Stat: React.FC<{
  value: React.ReactNode;
  label: React.ReactNode;
  hint?: React.ReactNode;
  color?: string;
  delay?: number;
}> = ({ value, label, hint, color = C.cyan, delay = 0 }) => (
  <Panel delay={delay}>
    <div
      style={{
        font: `600 16px/1 ${MONO}`,
        letterSpacing: "0.2em",
        textTransform: "uppercase",
        color: C.faint,
        marginBottom: 16,
      }}
    >
      {label}
    </div>
    <div style={{ fontSize: 64, fontWeight: 700, letterSpacing: "-0.02em", color, fontVariantNumeric: "tabular-nums", lineHeight: 1 }}>
      {value}
    </div>
    {hint && <div style={{ color: C.muted, fontSize: 19, marginTop: 14, lineHeight: 1.4 }}>{hint}</div>}
  </Panel>
);

export const Bullet: React.FC<{ children: React.ReactNode; delay?: number }> = ({ children, delay = 0 }) => (
  <Rise delay={delay}>
    <div style={{ display: "flex", gap: 16, alignItems: "flex-start", fontSize: 24, lineHeight: 1.4 }}>
      <div
        style={{
          width: 12,
          height: 12,
          background: C.cyan,
          transform: "rotate(45deg)",
          marginTop: 9,
          flexShrink: 0,
          borderRadius: 2,
        }}
      />
      <div>{children}</div>
    </div>
  </Rise>
);

export const Chip: React.FC<{ children: React.ReactNode; tone?: string; delay?: number }> = ({
  children,
  tone,
  delay = 0,
}) => {
  const p = useReveal(delay);
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 10,
        border: `1px solid ${tone ? tone : C.border2}`,
        color: tone ?? C.muted,
        background: tone ? C.cyanSoft : "transparent",
        borderRadius: 999,
        padding: "10px 20px",
        font: `600 19px/1 ${MONO}`,
        opacity: p,
        transform: `scale(${0.9 + p * 0.1})`,
      }}
    >
      {children}
    </span>
  );
}

/* ---------- brand mark ---------- */

export const Brand: React.FC<{ size?: number; draw?: boolean }> = ({ size = 40, draw = false }) => {
  const frame = useCurrentFrame();
  const d = draw ? interpolate(frame, [0, 30], [0, 1], { extrapolateRight: "clamp" }) : 1;
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none">
      <circle cx="8" cy="12" r="2.4" fill={C.cyan} />
      <path d="M13 6.5a8 8 0 0 1 0 11" stroke={C.cyan} strokeWidth="1.7" strokeLinecap="round" opacity={0.85 * d} />
      <path d="M16.5 4a12 12 0 0 1 0 16" stroke={C.cyan} strokeWidth="1.7" strokeLinecap="round" opacity={0.45 * d} />
    </svg>
  );
}

/* ---------- footer ---------- */

export const Footer: React.FC<{ n: string }> = ({ n }) => (
  <div
    style={{
      position: "absolute",
      left: 120,
      right: 120,
      bottom: 44,
      display: "flex",
      justifyContent: "space-between",
      alignItems: "center",
      font: `500 17px/1 ${MONO}`,
      letterSpacing: "0.16em",
      textTransform: "uppercase",
      color: C.faint,
    }}
  >
    <span style={{ display: "flex", gap: 12, alignItems: "center", color: C.muted }}>
      <Brand size={22} />
      <span style={{ fontWeight: 700, letterSpacing: "0.24em" }}>ATHAR</span>
    </span>
    <span>{n}</span>
  </div>
);

/* ---------- framed screenshot with Ken Burns + optional focus box ---------- */

export const Screen: React.FC<{
  src: string;
  /** Ken Burns start/end scale + origin (0..1). */
  from?: { scale: number; x: number; y: number };
  to?: { scale: number; x: number; y: number };
  delay?: number;
  style?: React.CSSProperties;
  /** Focus rectangle in % of the image [x,y,w,h], fades in at focusAt. */
  focus?: [number, number, number, number];
  focusAt?: number;
}> = ({ src, from = { scale: 1.06, x: 50, y: 20 }, to = { scale: 1.12, x: 50, y: 34 }, delay = 0, style, focus, focusAt = 0 }) => {
  const frame = useCurrentFrame();
  const { durationInFrames } = useVideoConfig();
  const reveal = useReveal(delay);
  const t = interpolate(frame, [delay, durationInFrames], [0, 1], { extrapolateRight: "clamp" });
  const scale = interpolate(t, [0, 1], [from.scale, to.scale]);
  const ox = interpolate(t, [0, 1], [from.x, to.x]);
  const oy = interpolate(t, [0, 1], [from.y, to.y]);
  const fp = focus ? spring({ frame: frame - focusAt, fps: 30, config: { damping: 200 }, durationInFrames: 22 }) : 0;
  return (
    <div
      style={{
        border: `1px solid ${C.border2}`,
        borderRadius: 14,
        overflow: "hidden",
        background: "#0a0f14",
        boxShadow: "0 40px 90px rgba(0,0,0,.55)",
        opacity: reveal,
        transform: `translateY(${(1 - reveal) * 30}px)`,
        ...style,
      }}
    >
      <div style={{ height: 34, background: "#0f1720", borderBottom: `1px solid ${C.border}`, display: "flex", alignItems: "center", gap: 8, padding: "0 16px" }}>
        {[0, 1, 2].map((i) => (
          <span key={i} style={{ width: 11, height: 11, borderRadius: 999, background: "#2a3a48" }} />
        ))}
      </div>
      <div style={{ position: "relative", overflow: "hidden" }}>
        <Img
          src={staticFile(src)}
          style={{ width: "100%", display: "block", transform: `scale(${scale})`, transformOrigin: `${ox}% ${oy}%` }}
        />
        {focus && (
          <div
            style={{
              position: "absolute",
              left: `${focus[0]}%`,
              top: `${focus[1]}%`,
              width: `${focus[2]}%`,
              height: `${focus[3]}%`,
              border: `2.5px solid ${C.cyan}`,
              borderRadius: 8,
              boxShadow: `0 0 0 3000px rgba(6,10,14,${0.55 * fp})`,
              opacity: fp,
            }}
          />
        )}
      </div>
    </div>
  );
}
