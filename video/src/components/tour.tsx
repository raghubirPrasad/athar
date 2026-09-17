import React from "react";
import {
  AbsoluteFill,
  Easing,
  Img,
  interpolate,
  spring,
  staticFile,
  useCurrentFrame,
  useVideoConfig,
} from "remotion";
import { C, MONO, SANS } from "../theme";

/* ============================================================ easing */
export const EXPO = Easing.bezier(0.16, 1, 0.3, 1);
export const SWIFT = Easing.bezier(0.33, 1, 0.68, 1);

export const ease = (frame: number, from: number, to: number, a = 0, b = 1, curve = EXPO) =>
  interpolate(frame, [from, to], [a, b], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing: curve,
  });

/** Smooth 0→1→0 bump, for flashes and sweeps. */
const bump = (p: number) => Math.sin(Math.max(0, Math.min(1, p)) * Math.PI);

/* ============================================================ shot
 * Scenes cross-dissolve. All the movement lives in the 3D stage, so the cut
 * itself stays soft — no blur-flash between beats.
 */
export const Shot: React.FC<{ children: React.ReactNode; f?: number }> = ({ children, f = 13 }) => {
  const frame = useCurrentFrame();
  const { durationInFrames } = useVideoConfig();
  const o = Math.min(ease(frame, 0, f), 1 - ease(frame, durationInFrames - f, durationInFrames));
  return <AbsoluteFill style={{ opacity: o }}>{children}</AbsoluteFill>;
};

/* ============================================================ light FX */

/** Anamorphic lens flare that sweeps across frame. Use sparingly, on beats. */
export const Flare: React.FC<{ at: number; len?: number; y?: number; power?: number }> = ({
  at,
  len = 44,
  y = 40,
  power = 1,
}) => {
  const frame = useCurrentFrame();
  const p = (frame - at) / len;
  if (p <= 0 || p >= 1) return null;
  const o = bump(p) * power;
  const x = interpolate(p, [0, 1], [-12, 112]);
  return (
    <AbsoluteFill style={{ pointerEvents: "none", zIndex: 30, mixBlendMode: "screen" }}>
      <div
        style={{
          position: "absolute",
          left: `${x}%`,
          top: `${y}%`,
          width: 1700,
          height: 5,
          transform: "translate(-50%,-50%)",
          background:
            "linear-gradient(90deg,transparent,rgba(120,230,255,.45) 34%,rgba(255,255,255,.92) 50%,rgba(120,230,255,.45) 66%,transparent)",
          filter: "blur(7px)",
          opacity: o * 0.9,
        }}
      />
      <div
        style={{
          position: "absolute",
          left: `${x}%`,
          top: `${y}%`,
          width: 260,
          height: 260,
          transform: "translate(-50%,-50%)",
          background: "radial-gradient(circle, rgba(190,245,255,.42), transparent 66%)",
          filter: "blur(16px)",
          opacity: o,
        }}
      />
      <div
        style={{
          position: "absolute",
          left: `${x + 9}%`,
          top: `${y}%`,
          width: 90,
          height: 90,
          transform: "translate(-50%,-50%)",
          background: "radial-gradient(circle, rgba(39,198,223,.34), transparent 70%)",
          filter: "blur(10px)",
          opacity: o * 0.8,
        }}
      />
    </AbsoluteFill>
  );
};

/** Specular sweep across the glass of the screen. */
const Sweep: React.FC<{ at: number; len?: number }> = ({ at, len = 44 }) => {
  const frame = useCurrentFrame();
  const p = (frame - at) / len;
  if (p <= 0 || p >= 1) return null;
  const x = interpolate(p, [0, 1], [-45, 145]);
  return (
    <div style={{ position: "absolute", inset: 0, overflow: "hidden", pointerEvents: "none", zIndex: 6 }}>
      <div
        style={{
          position: "absolute",
          top: "-25%",
          bottom: "-25%",
          left: `${x}%`,
          width: "26%",
          background: "linear-gradient(104deg,transparent,rgba(255,255,255,.13),transparent)",
          transform: "skewX(-13deg)",
          opacity: bump(p),
        }}
      />
    </div>
  );
};

/* ============================================================ screen (3D) */
export type Focus = { x: number; y: number; z: number };

export const Screen: React.FC<{
  src: string;
  from: Focus;
  to: Focus;
  move?: [number, number];
  ring?: { at: number; w: number; h: number };
  /** how far it rises from below on entry */
  rise?: number;
  /** entry tilt in degrees */
  tilt?: number;
  /** specular sweep start */
  sweep?: number;
  children?: React.ReactNode;
}> = ({ src, from, to, move, ring, rise = 300, tilt = 15, sweep, children }) => {
  const frame = useCurrentFrame();
  const { durationInFrames } = useVideoConfig();
  const [a, b] = move ?? [0, durationInFrames];
  const t = ease(frame, a, b);
  const z = interpolate(t, [0, 1], [from.z, to.z]);
  const ox = interpolate(t, [0, 1], [from.x, to.x]);
  const oy = interpolate(t, [0, 1], [from.y, to.y]);

  // entrance: rises from below with a tilt that settles — the promo move
  const ent = ease(frame, 0, 38);
  const ty = interpolate(ent, [0, 1], [rise, 0]);
  const sc = interpolate(ent, [0, 1], [0.93, 1]);
  // slow parallax drift so the frame is never dead still
  const rx = interpolate(ent, [0, 1], [tilt, 0]) + Math.sin(frame / 105) * 0.7;
  const ry = Math.sin(frame / 135 + 1.2) * 1.5;

  return (
    <AbsoluteFill style={{ alignItems: "center", justifyContent: "center", perspective: 2300 }}>
      {/* floor glow the screen appears to sit on */}
      <div
        style={{
          position: "absolute",
          bottom: 40,
          width: 1500,
          height: 150,
          background: "radial-gradient(ellipse at center, rgba(39,198,223,.20), transparent 70%)",
          filter: "blur(40px)",
          opacity: ent * 0.9,
        }}
      />
      <div
        style={{
          transform: `translateY(${ty}px) rotateX(${rx}deg) rotateY(${ry}deg) scale(${sc})`,
          transformStyle: "preserve-3d",
          opacity: ent,
        }}
      >
        <div
          style={{
            width: 1720,
            height: 946,
            borderRadius: 24,
            overflow: "hidden",
            border: `1px solid ${C.border2}`,
            background: "#0a0f14",
            boxShadow:
              "0 60px 150px rgba(0,0,0,.66), 0 0 0 1px rgba(255,255,255,.04), inset 0 1px 0 rgba(255,255,255,.10)",
            position: "relative",
          }}
        >
          <div
            style={{
              height: 38,
              background: "#0f1720",
              borderBottom: `1px solid ${C.border}`,
              display: "flex",
              alignItems: "center",
              gap: 9,
              padding: "0 18px",
            }}
          >
            {[0, 1, 2].map((i) => (
              <span key={i} style={{ width: 11, height: 11, borderRadius: 999, background: "#2a3a48" }} />
            ))}
            <span style={{ marginLeft: 16, font: `400 14px/1 ${MONO}`, color: C.faint }}>
              athar.gov · access governance
            </span>
          </div>
          <div style={{ position: "relative", height: 908, overflow: "hidden" }}>
            <Img
              src={staticFile(src)}
              style={{
                width: "100%",
                display: "block",
                transform: `scale(${z})`,
                transformOrigin: `${ox}% ${oy}%`,
              }}
            />
            {ring && <Ring at={ring.at} x={ox} y={oy} w={ring.w} h={ring.h} z={z} />}
          </div>
          <AbsoluteFill
            style={{ pointerEvents: "none", boxShadow: "inset 0 0 170px 44px rgba(6,10,14,.34)" }}
          />
          {sweep !== undefined && <Sweep at={sweep} />}
        </div>
      </div>
      {children}
    </AbsoluteFill>
  );
};

/** The image is taller than its window, so an image-space y maps down by this factor. */
const Y_MAP = 1075 / 908;

const Ring: React.FC<{ at: number; x: number; y: number; w: number; h: number; z: number }> = ({
  at,
  x,
  y,
  w,
  h,
  z,
}) => {
  const frame = useCurrentFrame();
  const p = spring({ frame: frame - at, fps: 30, config: { damping: 200, mass: 0.6 }, durationInFrames: 22 });
  const pulse = 1 + Math.sin(Math.max(0, frame - at) / 11) * 0.012;
  if (p <= 0) return null;
  return (
    <div
      style={{
        position: "absolute",
        left: `${x}%`,
        top: `${y * Y_MAP}%`,
        width: `${w * z}%`,
        height: `${h * Y_MAP * z}%`,
        transform: `translate(-50%,-50%) scale(${interpolate(p, [0, 1], [1.25, 1]) * pulse})`,
        border: `2px solid ${C.cyan}`,
        borderRadius: 12,
        boxShadow: `0 0 0 1px rgba(39,198,223,.22), 0 0 38px rgba(39,198,223,${0.45 * p}), inset 0 0 22px rgba(39,198,223,.10)`,
        opacity: p,
      }}
    />
  );
};

/* ============================================================ kinetic text */

export const Kinetic: React.FC<{
  text: string;
  at?: number;
  stagger?: number;
  size?: number;
  weight?: number;
  color?: string;
  accent?: string[];
  style?: React.CSSProperties;
}> = ({ text, at = 0, stagger = 2.2, size = 44, weight = 300, color = C.fg, accent = [], style }) => {
  const frame = useCurrentFrame();
  return (
    <div style={{ display: "flex", flexWrap: "wrap", gap: `0 ${size * 0.26}px`, fontFamily: SANS, ...style }}>
      {text.split(" ").map((w, i) => {
        const p = ease(frame, at + i * stagger, at + i * stagger + 16);
        const hot = accent.includes(w.replace(/[.,—]/g, ""));
        return (
          <span key={i} style={{ overflow: "hidden", display: "inline-block", paddingBottom: size * 0.1 }}>
            <span
              style={{
                display: "inline-block",
                transform: `translateY(${(1 - p) * size * 0.95}px)`,
                opacity: p,
                fontSize: size,
                fontWeight: hot ? 500 : weight,
                letterSpacing: "-0.02em",
                color: hot ? C.cyan : color,
                lineHeight: 1.12,
              }}
            >
              {w}
            </span>
          </span>
        );
      })}
    </div>
  );
};

export const Counter: React.FC<{ to: number; at?: number; len?: number; decimals?: number }> = ({
  to,
  at = 0,
  len = 26,
  decimals = 0,
}) => {
  const frame = useCurrentFrame();
  const v = ease(frame, at, at + len, 0, to);
  return <>{v.toLocaleString(undefined, { minimumFractionDigits: decimals, maximumFractionDigits: decimals })}</>;
};

/* ============================================================ captions */

export const Caption: React.FC<{
  kicker?: string;
  text: string;
  accent?: string[];
  at?: number;
  out?: number;
  pos?: "bl" | "tl" | "tr" | "br";
  size?: number;
}> = ({ kicker, text, accent = [], at = 8, out, pos = "bl", size = 33 }) => {
  const frame = useCurrentFrame();
  const { durationInFrames } = useVideoConfig();
  const end = out ?? durationInFrames - 10;
  const inP = ease(frame, at, at + 15);
  const outP = ease(frame, end - 10, end);
  const o = Math.min(inP, 1 - outP);
  const edge: React.CSSProperties =
    pos === "bl"
      ? { left: 108, bottom: 78 }
      : pos === "br"
        ? { right: 108, bottom: 78 }
        : pos === "tl"
          ? { left: 108, top: 84 }
          : { right: 108, top: 84 };

  return (
    <div
      style={{
        position: "absolute",
        ...edge,
        opacity: o,
        transform: `translateY(${(1 - inP) * 22 + outP * -14}px)`,
        maxWidth: 980,
        zIndex: 20,
      }}
    >
      <div
        style={{
          background: "rgba(9,14,19,.72)",
          border: `1px solid rgba(47,68,84,.9)`,
          borderLeft: `3px solid ${C.cyan}`,
          borderRadius: 14,
          padding: kicker ? "16px 28px 18px" : "16px 28px",
          backdropFilter: "blur(14px)",
          boxShadow: "0 22px 60px rgba(0,0,0,.5)",
        }}
      >
        {kicker && (
          <div
            style={{
              font: `500 14px/1 ${MONO}`,
              letterSpacing: "0.26em",
              textTransform: "uppercase",
              color: C.cyan,
              marginBottom: 12,
              opacity: ease(frame, at, at + 10),
            }}
          >
            {kicker}
          </div>
        )}
        <Kinetic text={text} at={at + 3} size={size} weight={300} accent={accent} />
      </div>
    </div>
  );
};

export const Callout: React.FC<{
  label: string;
  x: number;
  y: number;
  dir?: "left" | "right";
  at?: number;
  out?: number;
  len?: number;
}> = ({ label, x, y, dir = "right", at = 0, out, len = 130 }) => {
  const frame = useCurrentFrame();
  const { durationInFrames, width, height } = useVideoConfig();
  const end = out ?? durationInFrames - 10;
  const draw = ease(frame, at, at + 16);
  const chip = ease(frame, at + 8, at + 24);
  const o = 1 - ease(frame, end - 8, end);
  const sign = dir === "right" ? 1 : -1;
  const pulse = 1 + Math.sin(Math.max(0, frame - at) / 9) * 0.1;

  return (
    <div style={{ position: "absolute", left: (x / 100) * width, top: (y / 100) * height, opacity: o, zIndex: 22 }}>
      <div
        style={{
          position: "absolute",
          left: dir === "right" ? 0 : -len * draw,
          top: -1,
          width: len * draw,
          height: 2,
          background: `linear-gradient(90deg, ${C.cyan}, rgba(39,198,223,.25))`,
          boxShadow: `0 0 14px rgba(39,198,223,.7)`,
        }}
      />
      <div
        style={{
          position: "absolute",
          left: -5,
          top: -6,
          width: 11,
          height: 11,
          borderRadius: 999,
          background: C.cyan,
          boxShadow: `0 0 18px ${C.cyan}`,
          transform: `scale(${draw * pulse})`,
        }}
      />
      <div
        style={{
          position: "absolute",
          left: sign === 1 ? len + 12 : -len - 12,
          top: -21,
          transform: `translateX(${sign * (1 - chip) * 18}px) ${sign === -1 ? "translateX(-100%)" : ""}`,
          opacity: chip,
          whiteSpace: "nowrap",
          background: "rgba(9,14,19,.88)",
          border: `1px solid rgba(39,198,223,.45)`,
          borderRadius: 10,
          padding: "10px 17px",
          font: `500 21px/1 ${MONO}`,
          color: C.cyan,
          backdropFilter: "blur(8px)",
          boxShadow: "0 10px 30px rgba(0,0,0,.45)",
        }}
      >
        {label}
      </div>
    </div>
  );
};

/* ============================================================ cursor */

export const Cursor: React.FC<{
  path: [number, number][];
  at?: number;
  step?: number;
  clickAt?: number[];
  hideAt?: number;
}> = ({ path, at = 0, step = 24, clickAt = [], hideAt }) => {
  const frame = useCurrentFrame();
  const { width, height } = useVideoConfig();
  const appear = ease(frame, at - 10, at + 4);
  const gone = hideAt ? ease(frame, hideAt, hideAt + 12) : 0;

  let x = path[0][0];
  let y = path[0][1];
  for (let i = 1; i < path.length; i++) {
    const s = at + (i - 1) * step;
    const p = ease(frame, s, s + step, 0, 1, SWIFT);
    x = interpolate(p, [0, 1], [path[i - 1][0], path[i][0]]);
    y = interpolate(p, [0, 1], [path[i - 1][1], path[i][1]]);
    if (frame < s + step) break;
  }

  // squash toward the direction of travel for a touch of life
  const press = clickAt.reduce((acc, c) => Math.max(acc, 1 - Math.abs(frame - c) / 6), 0);

  return (
    <div
      style={{
        position: "absolute",
        left: (x / 100) * width,
        top: (y / 100) * height,
        opacity: appear * (1 - gone),
        zIndex: 40,
      }}
    >
      {clickAt.map((c) => {
        const r = ease(frame, c, c + 22);
        if (r <= 0 || r >= 1) return null;
        return (
          <div
            key={c}
            style={{
              position: "absolute",
              left: -22,
              top: -22,
              width: 44,
              height: 44,
              borderRadius: 999,
              border: `2px solid ${C.cyan}`,
              boxShadow: `0 0 20px rgba(39,198,223,${(1 - r) * 0.8})`,
              transform: `scale(${0.3 + r * 2})`,
              opacity: 1 - r,
            }}
          />
        );
      })}
      <div
        style={{
          position: "absolute",
          left: -16,
          top: -16,
          width: 32,
          height: 32,
          borderRadius: 999,
          background: "radial-gradient(circle, rgba(39,198,223,.34), transparent 70%)",
          filter: "blur(3px)",
        }}
      />
      <svg
        width="32"
        height="32"
        viewBox="0 0 24 24"
        style={{ filter: "drop-shadow(0 3px 8px rgba(0,0,0,.75))", transform: `scale(${1 - press * 0.16})` }}
      >
        <path d="M4 2l6 16 2.5-6.5L19 9 4 2z" fill="#fff" stroke="#0a0f14" strokeWidth="1.2" />
      </svg>
    </div>
  );
};
